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

package Sip::Configuration::Service;

use strict;
use warnings;

sub new {
    my ($class, $obj) = @_;
    my $type = ref($class) || $class;

    if (ref($obj) eq "HASH") {
        return bless $obj, $type;   # Just bless the object
    }

    return bless {}, $type;
}

sub timeout {
    my $self = shift;
    return $self->{timeout} || $self->SUPER::timeout();
}

sub allow_sc_status_then_login {
    my $self = shift;
    return $self->{'allow_sc_status_then_login'} =~ /true|yes|enabled/i ? 1 : 0;
}

1;
