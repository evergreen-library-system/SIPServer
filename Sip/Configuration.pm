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
# 
# parse-config: Parse an XML-format
# ACS configuration file and build the configuration
# structure.
#

package Sip::Configuration;

our $VERSION = 0.02;

use strict;
use warnings;
use XML::Simple qw(:strict);

use Sip::Configuration::Institution;
use Sip::Configuration::Account;
use Sip::Configuration::Service;

my $parser = new XML::Simple(
    KeyAttr => {
        login       => '+id',
        institution => '+id',
        service     => '+port',
    },
    GroupTags => {
        listeners    => 'service',
        accounts     => 'login',
        institutions => 'institution',
    },
    ForceArray => [ 'service', 'login', 'institution', 'server' ],
    ValueAttr  => {
        'error-detect' => 'enabled',
        'timeout'      => 'value',
        'min_servers'  => 'value',
        'max_servers'  => 'value'
    }
);

sub new {
    my ($class, $config_file) = @_;
    my $cfg = $parser->XMLin($config_file);
    my %listeners;

    foreach my $acct (values %{$cfg->{accounts}}) {
        new Sip::Configuration::Account $acct;
    }

    # The key to the listeners hash is the 'port' component of the
    # configuration, which is of the form '[host]:[port]/proto', and
    # the 'proto' component could be upper-, lower-, or mixed-cased.
    # Regularize it here to lower-case, and then do the same below in
    # find_server() when building the keys to search the hash.

    foreach my $service (values %{$cfg->{listeners}}) {
        new Sip::Configuration::Service $service;
        $listeners{lc $service->{port}} = $service;
    }
    $cfg->{listeners} = \%listeners;

    foreach my $inst (values %{$cfg->{institutions}}) {
        new Sip::Configuration::Institution $inst;
    }

    return bless $cfg, $class;
}

sub error_detect {
    my $self = shift;
    return $self->{'error-detect'};
}

sub timeout {
    my $self = shift;
    return $self->{'timeout'}
}

sub accounts {
    my $self = shift;
    return values %{$self->{accounts}};
}

sub find_service {
    my ( $self, $sockaddr, $port, $proto ) = @_;
    my $portstr;
    $self->{listeners} or die "ERROR: " . __PACKAGE__ . " object has no {listeners} for find_service() to find!";

    my @misses;
    foreach my $addr ( '', '*:', "$sockaddr:" ) {
        $portstr = sprintf( "%s%s/%s", $addr, $port, lc $proto );
        if (exists($self->{listeners}->{$portstr})) {
            Sys::Syslog::syslog("LOG_DEBUG", "find_service: Matched $portstr" );
            return $self->{listeners}->{$portstr};
        }
        push @misses, $portstr;
    }
    Sys::Syslog::syslog("LOG_WARNING", "find_service: No match in: " . join(' ',@misses));
    return;
}

1;
__END__

=head1 NAME

Sip::Configuration - abstraction/accessor for SIP configs

=head1 SYNOPSIS

use Sip::Configuration;
my $config = Sip::Configuration->new($ARGV[0]);

foreach my $acct ($config->accounts) {
    print "Found account: '", $acct->id, "', part of '";
    print $acct->institution, "'\n";
}

=cut

