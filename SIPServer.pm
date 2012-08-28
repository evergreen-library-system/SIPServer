#
# Copyright (C) 2006-2008  Georgia Public Library Service
# 
# Author: David J. Fiander
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA

package SIPServer;

use strict;
use warnings;
use Exporter;
use Sys::Syslog qw(syslog);
use Net::Server::PreFork;
use Net::Server::Proto;
use IO::Socket::INET;
use Socket qw(:crlf);
use Data::Dumper;		# For debugging
require UNIVERSAL::require;

#use Sip qw(readline);
use Sip::Constants qw(:all);
use Sip::Configuration;
use Sip::Checksum qw(checksum verify_cksum);
use Sip::MsgType;

use constant LOG_SIP => "local6"; # Local alias for the logging facility

our $VERSION = 0.02;
our @ISA = qw(Net::Server::PreFork);
#
# Main
#

my %transports = (
    RAW    => \&raw_transport,
    telnet => \&telnet_transport,
    http   => \&http_transport,
);

# Read configuration

my $config = Sip::Configuration->new($ARGV[0]);

my @parms;

#
# Ports to bind
#
foreach my $svc (keys %{$config->{listeners}}) {
    push @parms, "port=" . $svc;
}

#
# Logging
#
# Log lines look like this:
# Jun 16 21:21:31 server08 steve_sip: Sip::MsgType::_initialize('Login', ...)
# [  TIMESTAMP  ] [ HOST ] [ IDENT ]: Message...
#
# The IDENT is determined by $ENV{SIP_LOG_IDENT}, if present.
# Otherwise it is "_sip" appended to $USER, if present, or "acs-server" as a fallback.
#

my $syslog_ident = $ENV{SIP_LOG_IDENT} || ($ENV{USER} ? $ENV{USER} . "_sip" : 'acs-server');

push @parms,
    "log_file=Sys::Syslog",
    "syslog_ident=$syslog_ident",
    "syslog_facility=" . LOG_SIP;

#
# Server Management: set parameters for the Net::Server::PreFork
# module.  The module silently ignores parameters that it doesn't
# recognize, and complains about invalid values for parameters
# that it does.
#
if (defined($config->{'server-params'})) {
    while (my ($key, $val) = each %{$config->{'server-params'}}) {
        push @parms, $key . '=' . $val;
    }
}

print Dumper(@parms);

#
# This is the main event.
SIPServer->run(@parms);

#
# Child
#

# process_request is the callback used by Net::Server to handle
# an incoming connection request.

sub process_request {
    my $self = shift;
    my $service;
    my $sockname;
    my ($sockaddr, $port, $proto);
    my $transport;

    $self->{account} = undef; # New connection, no need to keep login info
    $self->{config} = $config;

    $sockaddr = $self->{server}->{sockaddr};
    $port     = $self->{server}->{sockport};
    $proto    = $self->{server}->{client}->NS_proto();
    syslog('LOG_INFO', "Inbound connection from $sockaddr on port $port and proto $proto");

    $self->{service} = $config->find_service( $sockaddr, $port, $proto );

    if (! defined($self->{service})) {
        syslog( "LOG_ERR", "process_request: Unrecognized server connection: %s:%s/%s",
            $sockaddr, $port, $proto );
        die "process_request: Bad server connection";
    }

    $transport = $transports{ $self->{service}->{transport} };

    if ( !defined($transport) ) {
        syslog("LOG_WARNING", "Unknown transport '%s', dropping", $service->{transport});
        return;
    } else {
        &$transport($self);
        # Transport has shut down, remove any lingering login info
        $self->{account} = undef;
    }
}

#
# Transports
#

sub raw_transport {
    my $self = shift;
    my ($uid, $pwd);
    my $input;
    my $service = $self->{service};
    my $strikes = 3;
    my $inst;
    my $timeout = $self->{service}->{timeout} || $self->{config}->{timeout} || 0;

    eval {
        local $SIG{ALRM} = sub { die "raw_transport Timed Out!\n"; };
        syslog("LOG_DEBUG", "raw_transport: timeout is $timeout");

    while ($strikes--) {
        alarm $timeout;
        $input = Sip::read_SIP_packet(*STDIN);
        alarm 0;

        if (!$input) {
            # EOF on the socket
            syslog("LOG_INFO", "raw_transport: shutting down: EOF during login");
            return;
        } elsif ($input !~ /\S/) {
            syslog("LOG_INFO", "raw_transport: received whitespace line (length %s) during login, skipping", length($input));
            next;
        }
        $input =~ s/[\r\n]+$//sm;	# Strip off trailing line terminator
        last if Sip::MsgType::handle($input, $self, LOGIN);
    }
    };

    if ($@) {
        syslog("LOG_ERR", "raw_transport: LOGIN ERROR: '$@'");
        die "raw_transport: login error (timeout? $@), exiting";
    } elsif (!$self->{account}) {
        syslog("LOG_ERR", "raw_transport: LOGIN FAILED");
        die "raw_transport: Login failed (no account), exiting";
    }

    syslog("LOG_DEBUG", "raw_transport: uname/inst: '%s/%s'",
        $self->{account}->{id},
        $self->{account}->{institution});

    $self->sip_protocol_loop();

    syslog("LOG_INFO", "raw_transport: shutting down");
}

sub telnet_transport {
    my $self = shift;
    my ($uid, $pwd);
    my $strikes = 3;
    my $account = undef;
    my $input;
    my $config = $self->{config};
    my $timeout = $self->{service}->{timeout} || $config->{timeout} || 0;
    syslog("LOG_DEBUG", "telnet_transport: timeout is %s", $timeout);

    # Until the terminal has logged in, we don't trust it
    # so use a timeout to protect ourselves from hanging.
    eval {
    local $SIG{ALRM} = sub { die "telnet_transport: Timed Out ($timeout seconds)!\n";; };
    local $| = 1;			# Unbuffered output

    while ($strikes--) {
        print "login: ";
        alarm $timeout;
        $uid = <STDIN>;
        alarm 0;

        print "password: ";
        alarm $timeout;
        $pwd = <STDIN>;
        alarm 0;

        $uid =~ s/[\r\n]+$//;
        $pwd =~ s/[\r\n]+$//;

        if (exists($config->{accounts}->{$uid})
        && ($pwd eq $config->{accounts}->{$uid}->password())) {
            $account = $config->{accounts}->{$uid};
            last;
        } else {
            syslog("LOG_WARNING", "Invalid login attempt: '%s'", $uid);
            print("Invalid login$CRLF");
        }
    }
    }; # End of eval

    if ($@) {
        syslog("LOG_ERR", "telnet_transport: Login timed out");
        die "Telnet Login Timed out";
    } elsif (!defined($account)) {
        syslog("LOG_ERR", "telnet_transport: Login Failed");
        die "Login Failure";
    } else {
        print "Login OK.  Initiating SIP$CRLF";
    }

    $self->{account} = $account;
    syslog("LOG_DEBUG", "telnet_transport: uname/inst: '%s/%s'", $account->{id}, $account->{institution});
    $self->sip_protocol_loop();
    syslog("LOG_INFO", "telnet_transport: shutting down");
}


sub http_transport {
}

#
# The terminal has logged in, using either the SIP login process
# over a raw socket, or via the pseudo-unix login provided by the
# telnet transport.  From that point on, both the raw and the telnet
# processes are the same:
sub sip_protocol_loop {
    my $self = shift;
    my $expect;
    my $service = $self->{service};
    my $config  = $self->{config};
    my $input;
    my $timeout = $self->{service}->{timeout} || $config->{timeout} || 0;

    # Now that the terminal has logged in, the first message
    # we recieve must be an SC_STATUS message.  But it might be
    # an SC_REQUEST_RESEND.  So, as long as we keep receiving
    # SC_REQUEST_RESEND, we keep waiting for an SC_STATUS

    # Comprise reports that no other ILS actually enforces this
    # constraint, so we'll relax about it too.  As long as everybody
    # uses the SIP "raw" login process, rather than telnet, this
    # will be fine, becaues the LOGIN protocol exchange will force
    # us into SIP 2.00 anyway.  Machines that want to log in using
    # telnet MUST send an SC Status message first, even though we're
    # not enforcing it.
    # 
    #$expect = SC_STATUS;
    $expect = '';

    alarm $timeout; # First loop timeout
    while ( $input = Sip::read_SIP_packet(*STDIN) ) {
        alarm 0; # Don't timeout while we are processing
        $input =~ s/[\r\n]+$//sm;    # Strip off any trailing line ends

        my $status = Sip::MsgType::handle($input, $self, $expect);
        next if $status eq REQUEST_ACS_RESEND;

        if (!$status) {
            syslog("LOG_ERR", "raw_transport: failed to handle %s", substr($input,0,2));
            die "sip_protocol_loop: failed Sip::MsgType::handle('$input', $self, '$expect')";
        }
        elsif ($expect && ($status ne $expect)) {
            # We received a non-"RESEND" that wasn't what we were expecting.
            syslog("LOG_ERR", "raw_transport: expected %s, received %s, exiting", $expect, $input);
            die "sip_protocol_loop: exiting: expected '$expect', received '$status'";
        }

        # We successfully received and processed what we were expecting
        $expect = '';
        alarm $timeout; # Next loop timeout
    }
}
