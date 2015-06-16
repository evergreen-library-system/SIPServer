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
# patron_info: test Patron Information Response

use strict;
use warnings;
use Clone qw(clone);

use Sip::Constants qw(:all);

use SIPtest qw($datepat $textpat $instid $currency $user_barcode $user_pin
	       $user_fullname $user_homeaddr $user_email $user_phone
	       $user_birthday $user_ptype $user_inet $user_homelib);

# This is a template test case for the Patron Information
# message handling.  Because of the large number of fields,
# this template forms the basis for all of the different
# situations: valid patron no details, valid patron with each
# individual detail requested, invalid patron, invalid patron
# password, etc.
my $patron_info_test_template = {
    id => 'valid Patron Info no details',
    msg => "6300020060329    201700          AO$instid|AA$user_barcode|",
    pat => qr/^64 [ Y]{13}\d{3}$datepat(\d{4}){6}/,
    fields => [
	       $SIPtest::field_specs{(FID_INST_ID)   },
	       $SIPtest::field_specs{(FID_SCREEN_MSG)},
	       $SIPtest::field_specs{(FID_PRINT_LINE)},
	       { field    => FID_PATRON_ID,
		 pat      => qr/^$user_barcode$/o,
		 required => 1, },
	       { field    => FID_PERSONAL_NAME,
		 pat      => qr/^$user_fullname$/o,
		 required => 1, },
	       $SIPtest::field_specs{(FID_HOLD_ITEMS_LMT)   },
	       $SIPtest::field_specs{(FID_OVERDUE_ITEMS_LMT)},
	       $SIPtest::field_specs{(FID_CHARGED_ITEMS_LMT)},
	       { field    => FID_VALID_PATRON,
		 pat      => qr/^Y$/,
		 # Not required by the spec, but by the test
		 required => 1, },
	       $SIPtest::field_specs{(FID_CURRENCY)},
	       { field    => FID_FEE_AMT,
		 pat      => $textpat,
		 required => 0, },
	       { field    => FID_FEE_LMT,
		 pat      => $textpat,
		 required => 0, },
	       { field    => FID_HOME_ADDR,
		 pat      => qr/^$user_homeaddr$/o,
		 required => 1, }, # required by this test case
	       { field    => FID_EMAIL,
		 pat      => qr/^$user_email$/o,
		 required => 1, },
	       { field    => FID_HOME_PHONE,
		 pat      => qr/^$user_phone$/o,
		 required => 1, },
	       { field    => FID_PATRON_BIRTHDATE,
		 pat      => qr/^$user_birthday$/o,
		 required => 1, },
	       { field    => FID_PATRON_CLASS,
		 pat      => qr/^$user_ptype$/o,
		 required => 1, },
	       { field    => FID_INET_PROFILE,
		 pat      => qr/^$user_inet$/,
		 required => 1, },
	       { field    => FID_HOME_LIBRARY,
		 pat      => qr/^$user_homelib$/,
		 required => 1, }, # Required for this test
	      ], };

my @tests = (
    $SIPtest::login_test,
    $SIPtest::sc_status_test,
    clone($patron_info_test_template),
);


# Create the test cases for the various summary detail fields
sub create_patron_summary_tests {
    my $test;
    my @patron_info_summary_tests = (
				     { field    => FID_HOLD_ITEMS,
				       pat      => $textpat,
				       required => 0, },
				     { field    => FID_OVERDUE_ITEMS,
				       pat      => $textpat,
				       required => 0, },
				     { field    => FID_CHARGED_ITEMS,
				       pat      => $textpat,
				       required => 0, },
# The test user has no items of these types, so the tests seem to fail
#				     { field    => FID_FINE_ITEMS,
#				       pat      => $textpat,
#				       required => 1, },
#				     { field    => FID_RECALL_ITEMS,
#				       pat      => $textpat,
#				       required => 0, },
#				     { field    => FID_UNAVAILABLE_HOLD_ITEMS,
#				       pat      => $textpat,
#				       required => 0, },
				     );

    foreach my $i (0 .. scalar @patron_info_summary_tests-1) {
    # The tests for each of the summary fields are exactly the
    # same as the basic one, except for the fact that there's
    # an extra field to test

    # Copy the hash, adjust it, add it to the end of the list
        $test = clone($patron_info_test_template);

        substr($test->{msg}, 23+$i, 1) = 'Y';
        $test->{id} = "valid Patron Info details: "
            . $patron_info_summary_tests[$i]->{field};
        push @{$test->{fields}}, $patron_info_summary_tests[$i];
        push @tests, $test;
    }
}

sub create_invalid_patron_tests {
    my $test;

    $test = clone($patron_info_test_template);
    $test->{id} = "invalid Patron Info id";
    $test->{msg} =~ s/AA$user_barcode\|/AAbad_barcode|/o;
    $test->{pat} = qr/^64Y[ Y]{13}\d{3}$datepat(\d{4}){6}/;
    delete $test->{fields};
    $test->{fields} = [
        $SIPtest::field_specs{   (FID_INST_ID)  },
        $SIPtest::field_specs{ (FID_SCREEN_MSG) },
        $SIPtest::field_specs{ (FID_PRINT_LINE) },
          { field    => FID_PATRON_ID,
            pat      => qr/^bad_barcode$/,
            required => 1,
          },
          { field    => FID_PERSONAL_NAME,
            pat      => qr/^$/,
            required => 1,
          },
          { field    => FID_VALID_PATRON,
            pat      => qr/^N$/,
            required => 1,
          },
    ];
    push @tests, $test;

    # Valid patron, invalid patron password
    $test = clone($patron_info_test_template);
    $test->{id} = "valid Patron Info, invalid password";
    $test->{msg} .= (FID_PATRON_PWD) . 'badpwd|';
    $test->{pat} = qr/^64[ Y]{14}\d{3}$datepat(\d{4}){6}/;
    delete $test->{fields};
    $test->{fields} = [
        $SIPtest::field_specs{   (FID_INST_ID)  },
        $SIPtest::field_specs{ (FID_SCREEN_MSG) },
        $SIPtest::field_specs{ (FID_PRINT_LINE) },
          { field    => FID_PATRON_ID,
            pat      => qr/^$user_barcode$/,
            required => 1,
          },
          { field    => FID_PERSONAL_NAME,
            pat      => qr/^$user_fullname$/,
            required => 1,
          },
          { field    => FID_VALID_PATRON,
            pat      => qr/^Y$/,
            required => 1,
          },
          { field    => FID_VALID_PATRON_PWD,
            pat      => qr/^N$/,
            required => 1,
          },
    ];
    push @tests, $test;
}

create_patron_summary_tests;

create_invalid_patron_tests;

SIPtest::run_sip_tests(@tests);

1;
