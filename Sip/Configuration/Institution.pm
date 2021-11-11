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

package Sip::Configuration::Institution;

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

sub name {
    my $self = shift;
    return $self->{name};
}

sub relais_extensions_to_msg24 {
    my $self = shift;
    return (
        exists $self->{'relais_extensions_to_msg24'} &&
        $self->{'relais_extensions_to_msg24'}->{'enabled'} =~ /true|yes|enabled/i
    ) ? 1 : 0;
}

sub phone_ext_to_msg10 {
    my $self = shift;
    return (
        exists $self->{'phone_ext_to_msg10'} &&
        $self->{'phone_ext_to_msg10'}->{'enabled'} =~ /true|yes|enabled/i
    ) ? 1 : 0;
}

1;
