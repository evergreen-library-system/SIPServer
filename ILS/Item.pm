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
# ILS::Item.pm
# 
# A Class for hiding the ILS's concept of the item from the OpenSIP
# system
#

package ILS::Item;

use strict;
use warnings;

use Encode;

use Sys::Syslog qw(syslog);

use ILS::Transaction;

our %item_db = (
		'1565921879' => {
				 title => "Perl 5 desktop reference",
				 id => '1565921879',
				 sip_media_type => '001',
				 magnetic_media => 0,
				 hold_queue => [],
				},
		'0440242746' => {
				 title => "The deep blue alibi",
				 id => '0440242746',
				 sip_media_type => '001',
				 magnetic_media => 0,
				 hold_queue => [],
		},
		'660' => {
				 title => decode_utf8('Harry Potter y el cáliz de fuego'),
				 id => '660',
				 sip_media_type => '001',
				 magnetic_media => 0,
				 hold_queue => [],
			 },
		);

sub new {
    my ($class, $item_id) = @_;
    my $type = ref($class) || $class;
    my $self;


    if (!exists($item_db{$item_id})) {
	syslog("LOG_DEBUG", "new ILS::Item('%s'): not found", $item_id);
	return undef;
    }

    $self = $item_db{$item_id};
    bless $self, $type;

    syslog("LOG_DEBUG", "new ILS::Item('%s'): found with title '%s'",
	   $item_id, encode_utf8($self->{title}));

    return $self;
}

sub magnetic {
    my $self = shift;
    return $self->{magnetic_media};
}
sub sip_media_type {
    my $self = shift;
    return $self->{sip_media_type};
}
sub sip_item_properties {
    my $self = shift;
    return $self->{sip_item_properties};
}

sub status_update {
    my ($self, $props) = @_;
    my $status = new ILS::Transaction;

    $self->{sip_item_properties} = $props;
    $status->{ok} = 1;

    return $status;
}

    
sub id {
    my $self = shift;
    return $self->{id};
}
sub title_id {
    my $self = shift;
    return $self->{title};
}
sub permanent_location {
    my $self = shift;
    return $self->{permanent_location} || '';
}
sub current_location {
    my $self = shift;
    return $self->{current_location} || '';
}

sub sip_circulation_status {
    my $self = shift;

    if ($self->{patron}) {
	return '04';
    } elsif (scalar @{$self->{hold_queue}}) {
	return '08';
    } else {
	return '03';
    }
}

sub sip_security_marker {
    return '02';
}

sub sip_fee_type {
    return '01';
}

sub fee {
    my $self = shift;
    return $self->{fee} || 0;
}

sub fee_currency {
    my $self = shift;
    return $self->{currency} || 'CAD';
}

sub owner {
    my $self = shift;
    return 'UWOLS';
}

sub hold_queue {
    my $self = shift;
    return $self->{hold_queue};
}

sub hold_queue_position {
    my ($self, $patron_id) = @_;
    my $i;

    for ($i = 0; $i < scalar @{$self->{hold_queue}}; $i += 1) {
	if ($self->{hold_queue}[$i]->{patron_id} eq $patron_id) {
	    return $i + 1;
	}
    }
    return 0;
}

sub due_date {
    my $self = shift;

    if ($self->{due_date}) {
        return Sip::timestamp($self->{due_date});
    } else {
        return 0;
    }
}

sub recall_date {
    my $self = shift;
    return $self->{recall_date} || 0;
}
sub hold_pickup_date {
    my $self = shift;
    return $self->{hold_pickup_date} || 0;
}
sub screen_msg {
    my $self = shift;
    return $self->{screen_msg} || '';
}
sub print_line {
     my $self = shift;
     return $self->{print_line} || '';
}

# An item is available for a patron if
# 1) It's not checked out and (there's no hold queue OR patron
#    is at the front of the queue)
# OR
# 2) It's checked out to the patron and there's no hold queue
sub available {
     my ($self, $for_patron) = @_;

     return ((!defined($self->{patron_id}) && (!scalar @{$self->{hold_queue}}
					       || ($self->{hold_queue}[0] eq $for_patron)))
	     || ($self->{patron_id} && ($self->{patron_id} eq $for_patron)
		 && !scalar @{$self->{hold_queue}}));
}

1;
