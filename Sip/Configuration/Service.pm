#
# Copyright (C) 2006-2008  Georgia Public Library Service
# 
# Author: David J. Fiander
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
