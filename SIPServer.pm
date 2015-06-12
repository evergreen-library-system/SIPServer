#
# Copyright (C) 2006-2008  Georgia Public Library Service
# Copyright (C) 2013-2014  Equinox Software, Inc.
# 
# Author: David J. Fiander
# Author: Mike Rylander
# Author: Bill Erickson
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
use Net::Server::Multiplex;
use Net::Server::PreFork;
use Net::Server::Proto;
use IO::Socket::INET;
use IO::Pipe;
use Socket qw(:crlf SOL_SOCKET SO_KEEPALIVE IPPROTO_TCP TCP_KEEPALIVE);
use Data::Dumper;		# For debugging
require UNIVERSAL::require;
use POSIX qw/:sys_wait_h :errno_h/;

use Sip qw($protocol_version);
use Sip::Constants qw(:all);
use Sip::Configuration;
use Sip::Checksum qw(checksum verify_cksum);
use Sip::MsgType;
use Time::HiRes qw/time/;

use Cache::Memcached;

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
# Server Management: set parameters for the Net::Server personality
# chosen, defaulting to PreFork.
#
# The PreFork module silently ignores parameters that it doesn't
# recognize, and complains about invalid values for parameters
# that it does.
#
# The Fork module only cares about max_servers, for our purposes, which
# defaults to 256.
#
# The Multiplex module ignores all runtime params, and triggers an
# alternate implementation of the processing loop.  See the Net::Server
# personality documentation for details. The max-concurrent parameter
# can be used here to limit the number of concurrent in-flight requests
# to avoid a fork-bomb DoS situation.  The default is 256.
#
my $worker_keepalive = 5;
my $max_concurrent = 256;
if (defined($config->{'server-params'})) {
    while (my ($key, $val) = each %{$config->{'server-params'}}) {
        push @parms, $key . '=' . $val;
        @ISA = ('Net::Server::'.$val) if ($key eq 'personality');
        $max_concurrent = $val if ($key eq 'max-concurrent');
        $worker_keepalive = $val if ($key eq 'worker-keepalive');
    }
}

print Dumper(@parms);

# initialize all remaining global variables before 
# going into listen mode.
my %kid_hash;
my $kid_count = 0;
my $cache;
my @pending_connections;
my %active_connections;

#
# This is the main event.
SIPServer->run(@parms);

#
# Child
#

# process_request is the callback used by Net::Server to handle
# an incoming connection request when the peronsality is either
# Fork or PreFork.

sub process_request {
    my $self = shift;
    my $service;
    my $sockname;
    my ($sockaddr, $port, $proto);
    my $transport;

    # This is kind of kinky, but allows us to avoid requiring Socket::Linux.
    # A simple "Socket::Linux"->use won't suffice since we need access to
    # all of it's bareword constants as well.
    eval <<'    EVAL';
    use Socket::Linux qw(TCP_KEEPINTVL TCP_KEEPIDLE TCP_KEEPCNT);
    setsockopt($self->{server}->{client}, SOL_SOCKET,  SO_KEEPALIVE, 1);
    setsockopt($self->{server}->{client}, IPPROTO_TCP, TCP_KEEPIDLE, 120);
    setsockopt($self->{server}->{client}, IPPROTO_TCP, TCP_KEEPINTVL, 10);
    EVAL

    syslog('LOG_DEBUG', 
        "Consider installing Socket::Linux for TCP keepalive: $@") if $@;

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
        # handle client authentication prior to
        # passing further processing to sip_protocol_loop()
        &$transport($self);
    }

    $self->sip_protocol_loop();

    syslog("LOG_INFO", '%s: shutting down', $transport);
}

# for forking personalities, don belt and suspenders
# and ensure that the session account is cleared when
# a client connection ends cleanly (as opposed to the
# Net::Server backend having been terminated).
sub post_process_request {
    my $self = shift;
   
    $self->{account} = undef;

}

# mux_input is the callback used by Net::Server to handle
# an incoming connection request when the peronsality is 
# Multiplex.


sub init_cache {
    return $cache if $cache;

    if (!$config->{cache}) {
        syslog('LOG_ERR', "Cache servers needed");
        return;
    }
    my $servers = $config->{cache}->{server};
    syslog('LOG_DEBUG', "Cache servers: @$servers");

    $cache = Cache::Memcached->new({servers => $servers}) or
        syslog('LOG_ERR', "Unable to initialize memcache: @$servers");

    return $cache;
}

# In the parent, pending connections are tracked as an array of PIDs.
# As each child process completes the login dance, it plops some
# info into memcache for us to pickup and copy into our active
# connections.  No memcache entry means the child login dance
# is still in progress.
sub check_pending_connections {
    return unless @pending_connections;

    init_cache();

    syslog('LOG_DEBUG', 
        "multi: pending connections to inspect: @pending_connections");

    # get_multi will return all completed login blobs
    my @keys = map { "sip_pending_auth_$_" } @pending_connections;
    my $values = $cache->get_multi(@keys);

    for my $key (keys %$values) {
        my $VAR1; # for Dump() -> eval;
        eval $values->{$key}; # Data::Dumper->Dump string

        my $id = $VAR1->{id}; # conn_id
        $active_connections{$id}{net_server_parts} = $VAR1->{net_server_parts};

        if ($VAR1->{success}) {
            if ($active_connections{$id}{net_server_parts}{state}) {
                local $Data::Dumper::Indent = 0;
                syslog('LOG_DEBUG', "multi: conn_id=$id has state: ".
                    Dumper($active_connections{$id}{net_server_parts}{state}));
            }

        } else {
            syslog('LOG_INFO', "Child $id failed SIP login; removing connection");
            delete $active_connections{$id};
        }

        # clean up ---

        syslog('LOG_DEBUG', 
            "multi: pending connection for conn_id=$id resolved");
        $cache->delete($key);
        @pending_connections = grep {$_ ne $id} @pending_connections;
    }

    syslog('LOG_DEBUG', 
        "multi: connections still pending after check: @pending_connections")
        if @pending_connections;

    if (0) {
        # useful for debugging connection-specific state information
        local $Data::Dumper::Indent = 0;
        for my $conn_id (keys %active_connections) {
            syslog('LOG_DEBUG', "Connection $conn_id has state "
                .Dumper($active_connections{$conn_id}{net_server_parts}{state}));
        }
    }
}

sub sig_chld {
    if ( !scalar(keys(%kid_hash))) { # not using mux mode
        1 while waitpid(-1, WNOHANG) > 0;
    } else {
        for (keys(%kid_hash)) {
            if ( my $reaped = waitpid($_, WNOHANG) > 0 ) {
                syslog('LOG_DEBUG', "Reaping child $_");
                # Mourning... done.
                $kid_count--;
                # note: in some cases (when the primary connection is severed),
                # the active connection is cleaned up in mux_close.  
                if ($active_connections{$kid_hash{$_}}) {
                    if ($active_connections{$kid_hash{$_}}{worker_pipe}) {
                        syslog('LOG_DEBUG', "Closing worker pipe after timeout for: $kid_hash{$_}");
                        delete $active_connections{$kid_hash{$_}}{worker_pipe};
                    }
                }
                delete $kid_hash{$_};
            }
        }
    }
}

sub mux_connection {
    my ($mself, $fh) = @_;

    my ($peeraddr, $peerport) = (
        $mself->{net_server}->{server}->{peeraddr},
        $mself->{net_server}->{server}->{peerport}
    );

    # create a new connection ID for this MUX handler.
    $mself->{conn_id} = "$peeraddr:$peerport\@" . time();
    syslog('LOG_DEBUG', "New connection created: ".$mself->{conn_id});
}

sub mux_input {
    my $mself = shift;
    my $mux = shift;
    my $mux_fh = shift;
    my $str_ref = shift;

    my $conn_id = $mself->{conn_id}; # see mux_connection

    # and process any pending logins
    check_pending_connections();

    my $c = scalar(keys %active_connections);
    syslog("LOG_DEBUG", "multi: inbound message on connection $conn_id; $c total");

    if ($kid_count >= $max_concurrent) {
        # XXX should we say something to the client? maybe wait and try again?
        syslog('LOG_ERR', "Unwilling to fork new child process, at least $max_concurrent already ongoing");
        return;
    }

    my $self;
    if (!$active_connections{$conn_id}) { # Brand new connection, log them in
        $self = $mself->{net_server};

        my ($sockaddr, $port, $proto);
    
        $self->{config} = $config;
    
        $sockaddr = $self->{server}->{sockaddr};
        $port     = $self->{server}->{sockport};
        $proto    = $self->{server}->{client}->NS_proto();
    
        syslog('LOG_INFO', "New client $conn_id connecting to $sockaddr on port $port and proto $proto");
    
        $self->{service} = $config->find_service( $sockaddr, $port, $proto );
    
        if (! defined($self->{service})) {
            syslog( "LOG_ERR", "process_request: Unrecognized server connection: %s:%s/%s",
                $sockaddr, $port, $proto );
            syslog('LOG_ERR', "process_request: Bad server connection");
            return;
        }
    
        my $transport = $transports{ $self->{service}->{transport} };
    
        if ( !defined($transport) ) {
            syslog("LOG_WARNING", "Unknown transport, dropping");
            return;
        }

        # We stick this here, assuming success. Cleanup comes later via memcache and reaper.
        $active_connections{$conn_id} = {
            id => $conn_id,
            transport => $transport,
            net_server => $self,
            worker_pipe => IO::Pipe->new
        };
 
        # This is kind of kinky, but allows us to avoid requiring Socket::Linux.
        # A simple "Socket::Linux"->use won't suffice since we need access to
        # all of it's bareword constants as well.
        eval <<'        EVAL';
        use Socket::Linux qw(TCP_KEEPINTVL TCP_KEEPIDLE TCP_KEEPCNT);
        setsockopt($self->{server}->{client}, SOL_SOCKET,  SO_KEEPALIVE, 1);
        setsockopt($self->{server}->{client}, IPPROTO_TCP, TCP_KEEPIDLE, 120);
        setsockopt($self->{server}->{client}, IPPROTO_TCP, TCP_KEEPINTVL, 10);
        EVAL

        my $pid = fork();
        if (!defined($pid) or $pid < 0) {
            syslog('LOG_ERR', "Unable to fork new child process $!");
            return;
        }

        if ($pid == 0) { # in kid
            $active_connections{$conn_id}{worker_pipe}->reader;

            $cache = undef; # don't use the same cache handle as our parent.
            my $cache_data = {id => $conn_id};

            # Once the login dance is complete in SipMsg, login_complete() is
            # called so that we may cache the results before the login response
            # message is delivered to the client.  
            $self->{login_complete} = sub {
                my $status = shift;

                if ($status) { # login OK

                    $self->{state} = $self->{ils}->state() if (UNIVERSAL::can($self->{ils},'state'));

                    $cache_data->{success} = 1;
                    $cache_data->{net_server_parts} = {
                        map { ($_ => $$self{$_}) } qw/state institution account/
                    };

                    # Stash the ILS module somewhere handy for later
                    $cache_data->{net_server_parts}{ils} = ref($self->{ils});

                } else {
                    $cache_data->{success} = 0;
                }

                init_cache()->set(
                    "sip_pending_auth_$conn_id", 
                    Data::Dumper->Dump([$cache_data]),
                    # Our cache entry is only inspected when the parent process
                    # wakes up from an inbound request.  If this is the last child
                    # to connect before a long period of inactivity, our cache
                    # entry may sit unnattended for some time, hence the
                    # 12 hour cache timeout.  XXX: make it configurable?
                    43200 # 12 hours
                );

                $self->{login_complete_called} = 1;
            };

            syslog('LOG_DEBUG', "Child $$ / $conn_id kicking off login process");

            eval { &$transport($self, $active_connections{$conn_id}{worker_pipe}) };

            if ($@) {
                syslog('LOG_ERR', "ILS login error: $@");
                $self->{login_complete}->(0) unless $self->{login_complete_called};
            }

            $self->sip_protocol_loop(
                $active_connections{$conn_id}{worker_pipe},
                $self->{account}->{'worker-keepalive'}
                    // $self->{institution}->{'worker-keepalive'}
                    // $worker_keepalive
            );

            exit(0);

        } else {
            my $fh = $active_connections{$conn_id}{worker_pipe};
            $fh->writer;
            $fh->autoflush;
            print $fh $$str_ref;
            push(@pending_connections, $conn_id);
            $kid_hash{$pid} = $conn_id;
            $kid_count++;
        }

    } else {

        $self = $active_connections{$conn_id}->{net_server};
        my $ns_parts = $active_connections{$conn_id}->{net_server_parts};

        if ($active_connections{$conn_id}{worker_pipe}) {
            syslog('LOG_DEBUG', "multi: parent writing msg to existing child process");
            my $fh = $active_connections{$conn_id}{worker_pipe};
            print $fh $$str_ref;

        } else { # waited too long, kid and pipe are gone
            $active_connections{$conn_id}{worker_pipe} = IO::Pipe->new;
            syslog('LOG_DEBUG', "multi: parent creating new pipe for existing connection");
    
            my $pid = fork();
            if (!defined($pid) or $pid < 0) {
                syslog('LOG_ERR', "Unable to fork new child process $!");
                return;
            }
        
            if ($pid == 0) { # in kid
                $active_connections{$conn_id}{worker_pipe}->reader;
        
                syslog("LOG_DEBUG", "multi: $conn_id to be processed by child $$");
        
                # build the connection we deleted after logging in
                $ns_parts->{ils}->use; # module name in the parent
                $self->{$_} = $ns_parts->{$_} for keys %$ns_parts;
                $self->{ils} = $ns_parts->{ils}->new(
                    $ns_parts->{institution}, $ns_parts->{account}, $ns_parts->{state});
        
                # MUX mode only works with protocol version 2, because it assumes
                # a SIP login has occured.  However, since the login occured 
                # within a different now-dead process, the previously modified
                # protocol_version is lost.  Re-apply it globally here.
                $protocol_version = 2;
        
                if (!$self->{ils}) {
                    syslog('LOG_ERR', "Unable to build ILS module in mux child");
                    exit(0);
                }
        
                $self->sip_protocol_loop(
                    $active_connections{$conn_id}{worker_pipe},
                    $self->{account}->{'worker-keepalive'}
                        // $self->{institution}->{'worker-keepalive'}
                        // $worker_keepalive
                );

       
                exit(0);
        
            } else { # in parent
                $active_connections{$conn_id}{worker_pipe}->writer;
                my $fh = $active_connections{$conn_id}{worker_pipe};
                $fh->autoflush;
                print $fh $$str_ref;
                $kid_count++;
                $kid_hash{$pid} = $conn_id;
                syslog("LOG_DEBUG", "multi: $conn_id forked child $pid; $kid_count total");
            } 
        }
    }

    # clear read data from the mux string ref
    $$str_ref = '';
}

# client disconnected, remove the active connection
sub mux_close {
    my ($self, $mux, $fh) = @_;
    my $conn_id = $self->{conn_id};

    delete $active_connections{$conn_id};
    syslog("LOG_DEBUG", "multi: mux_close cleaning up child: $conn_id; ". 
        scalar(keys %active_connections)." remain");
}


#
# Transports
#

sub raw_transport {
    my $self = shift;
    my $fh = shift || *STDIN;

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
        $input = Sip::read_SIP_packet($fh);
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
        if ($input =~ /^99/) { # SC Status
            unless ($service->allow_sc_status_then_login()) {
                die 'raw_transport: sending SC status before login not enabled, exiting';
            }
            Sip::MsgType::handle($input, $self, SC_STATUS);
            $strikes++; # it's allowed, don't charge for it
            next;
        }
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
}

sub telnet_transport {
    my $self = shift;
    my $fh = shift || *STDIN;

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
        $uid = <$fh>;
        alarm 0;

        print "password: ";
        alarm $timeout;
        $pwd = <$fh>;
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
    my $fh = shift || *STDIN;
    my $keepalive = shift;
    my $expect;
    my $service = $self->{service};
    my $config  = $self->{config};
    my $input;
    my $timeout = $keepalive || $self->{service}->{timeout} || $config->{timeout} || 0;

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
    while ( $input = Sip::read_SIP_packet($fh) ) {
        alarm 0; # Don't timeout while we are processing
        $input =~ s/[\r\n]+$//sm;    # Strip off any trailing line ends

        my $start = time;
        my $status = Sip::MsgType::handle($input, $self, $expect);
        if ($status eq REQUEST_ACS_RESEND) {
            alarm $timeout;
            next;
        }

        my $duration = sprintf("%0.3f", time - $start);
        syslog('LOG_DEBUG', "SIP processing duration $duration : $input");

        if (!$status) {
            syslog("LOG_ERR", "raw_transport: failed to handle %s", substr($input,0,2));
            die "sip_protocol_loop: failed Sip::MsgType::handle('$input', $self, '$expect')";
        }
        elsif ($expect && ($status ne $expect)) {
            # We received a non-"RESEND" that wasn't what we were expecting.
            syslog("LOG_ERR", "raw_transport: expected %s, received %s, exiting", $expect, $input);
            die "sip_protocol_loop: exiting: expected '$expect', received '$status'";
        }

        last if (defined $keepalive && !$keepalive);

        # We successfully received and processed what we were expecting
        $expect = '';
        alarm $timeout; # Next loop timeout

    }
}
