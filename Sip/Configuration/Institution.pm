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

1;
