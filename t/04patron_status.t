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
# patron_status: test Patron Status Response

use strict;
use warnings;
use Clone qw(clone);

use Sip::Constants qw(:all);

use SIPtest qw($datepat $textpat $instid $user_barcode $password);

my $patron_status_test_template = {
    id => 'Patron Status: valid patron, no patron password',
    msg => "2300120060101    084237AO$instid|AA$user_barcode|AC$password|",
    pat => qr/^24 [ Y]{13}001$datepat/,
    fields => [
	       $SIPtest::field_specs{(FID_INST_ID)},
	       $SIPtest::field_specs{(FID_SCREEN_MSG)},
	       $SIPtest::field_specs{(FID_PRINT_LINE)},
	       { field    => FID_PATRON_ID,
		 pat      => qr/^$user_barcode$/,
		 required => 1, },
	       { field    => FID_PERSONAL_NAME,
		 pat      => qr/^David J\. Fiander$/,
		 required => 1, },
	       { field    => FID_VALID_PATRON,
		 pat      => qr/^Y$/,
		 # Not required by the spec, but by the test
		 required => 1, },
	       $SIPtest::field_specs{(FID_CURRENCY)},
	       { field    => FID_FEE_AMT,
		 pat      => $textpat,
		 required => 0, },
	       ], };

my @tests = (
	     $SIPtest::login_test,
	     $SIPtest::sc_status_test,
	     clone($patron_status_test_template),
	     );

# Invalid patron
my $test = clone($patron_status_test_template);

$test->{id} = 'Patron Status: invalid id';
$test->{msg} =~ s/AA$user_barcode\|/AAbad_userid|/ or warn "Substitution failed on test clone";

# The test assumes that the language sent by the terminal is
# just echoed back for invalid patrons.
$test->{pat} = qr/^24Y[ Y]{13}001$datepat/; 

delete $test->{fields};
$test->{fields} = [
		   $SIPtest::field_specs{(FID_INST_ID)},
		   $SIPtest::field_specs{(FID_SCREEN_MSG)},
		   $SIPtest::field_specs{(FID_PRINT_LINE)},
		   { field    => FID_PATRON_ID,
		     pat      => qr/^bad_userid$/,
		     required => 1, },
		   { field    => FID_PERSONAL_NAME,
		     pat      => qr/^$/,
		     required => 1, },
		   { field    => FID_VALID_PATRON,
		     pat      => qr/^N$/,
		     required => 1, },
		   ];

push @tests, $test;

# Valid patron, invalid patron password
$test = clone($patron_status_test_template);
$test->{id} = 'Patron Status: Valid patron, invalid patron password';
$test->{msg} .= (FID_PATRON_PWD) . 'badpwd|';
$test->{pat} = qr/^24[ Y]{14}001$datepat/;
delete $test->{fields};
$test->{fields} = [
		 $SIPtest::field_specs{(FID_INST_ID)},
		 $SIPtest::field_specs{(FID_SCREEN_MSG)},
		 $SIPtest::field_specs{(FID_PRINT_LINE)},
		 { field    => FID_PATRON_ID,
		   pat      => qr/^$user_barcode$/,
		   required => 1, },
		 { field    => FID_PERSONAL_NAME,
		   pat      => qr/^David J\. Fiander$/,
		   required => 1, },
		 { field    => FID_VALID_PATRON,
		   pat      => qr/^Y$/,
		   required => 1, },
		 { field    => FID_VALID_PATRON_PWD,
		   pat      => qr/^N$/,
		   required => 1, },
		 ];
push @tests, $test;

# TODO: Need multiple patrons to test each individual 
# status field

SIPtest::run_sip_tests(@tests);

1;
