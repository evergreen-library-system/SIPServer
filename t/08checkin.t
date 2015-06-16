#!/usr/bin/perl
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
# checkin: test Checkin Response

use strict;
use warnings;
use Clone qw(clone);

use Sip::Constants qw(:all);

use SIPtest qw($datepat $textpat $instid $user_barcode
	       $item_barcode $item_title);

my $checkin_test_template = {
    id => 'Checkin: Item is checked out',
    msg => "09N20060102    08423620060113    084235APUnder the bed|AO$instid|AB$item_barcode|ACterminal password|",
    pat => qr/^101YNN$datepat/o,
    fields => [
	       $SIPtest::field_specs{(FID_INST_ID)},
	       $SIPtest::field_specs{(FID_SCREEN_MSG)},
	       $SIPtest::field_specs{(FID_PRINT_LINE)},
	       { field    => FID_PATRON_ID,
		 pat      => qr/^$user_barcode$/o,
		 required => 1, },
	       { field    => FID_ITEM_ID,
		 pat      => qr/^$item_barcode$/o,
		 required => 1, },
	       { field    => FID_PERM_LOCN,
		 pat      => $textpat,
		 required => 1, },
	       { field    => FID_TITLE_ID,
		 pat      => qr/^$item_title\s*$/o,
		 required => 1, }, # not required by the spec.
	       ],};

my $checkout_template = {
    id => 'Checkin: prep: check out item',
    msg => "11YN20060329    203000                  AO$instid|AA$user_barcode|AB$item_barcode|AC|",
    pat => qr/^121NNY$datepat/o,
    fields => [],
};

my @tests = (
	     $SIPtest::login_test,
	     $SIPtest::sc_status_test,
	     $checkout_template,
	     $checkin_test_template,
	     );

my $test;

# Checkin item that's not checked out.  Basically, this
# is identical to the first case, except the header says that
# the ILS didn't check the item in, and there's no patron id.
$test = clone($checkin_test_template);
$test->{id} = 'Checkin: Item not checked out';
$test->{pat} = qr/^100YNN$datepat/o;
$test->{fields} = [grep $_->{field} ne FID_PATRON_ID, @{$test->{fields}}];

push @tests, $test;

# 
# Still need tests for magnetic media
# 

SIPtest::run_sip_tests(@tests);

1;
