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
# patron_status: check status of valid patron and invalid patron

use strict;
use warnings;

use Sip::Constants qw(:all);
use SIPtest qw($datepat $instid $currency $user_barcode $user_pin
	       $user_fullname $user_homeaddr $user_email $user_phone
	       $user_birthday);

my @tests = (
	     $SIPtest::login_test,
	     $SIPtest::sc_status_test,
	     { id => 'valid Patron Status',
	       msg => "2300120060101    084237AO$SIPtest::instid|AA$user_barcode|AD$user_pin|AC|",
	       pat => qr/^24 [ Y]{13}\d{3}$datepat/,
	       fields => [
			  $SIPtest::field_specs{(FID_INST_ID)},
			  $SIPtest::field_specs{(FID_SCREEN_MSG)},
			  $SIPtest::field_specs{(FID_PRINT_LINE)},
			  { field    => FID_PERSONAL_NAME,
			    pat      => qr/^$user_fullname$/o,
			    required => 1, },
			  { field    => FID_PATRON_ID,
			    pat      => qr/^$user_barcode/o,
			    required => 1, },
			  { field    => FID_VALID_PATRON,
			    pat      => qr/^Y$/,
			    required => 0, },
			  { field    => FID_VALID_PATRON_PWD,
			    pat      => qr/^Y$/,
			    required => 0, },
			  { field    => FID_CURRENCY,
			    pat      => qr/^$currency$/io,
			    required => 0, },
			  { field    => FID_FEE_AMT,
			    pat      => qr/^[0-9.]+$/,
			    required => 0, },
			  ], },
	     { id => 'invalid password Patron Status',
	       msg => "2300120060101    084237AO$instid|AA$user_barcode|AC|ADbadw|",
	       pat => qr/^24[ Y]{14}\d{3}$datepat/,
	       fields => [
			  { field    => FID_PERSONAL_NAME,
			    pat      => qr/^$user_fullname$/o,
			    required => 1, },
			  { field    => FID_PATRON_ID,
			    pat      => qr/^$user_barcode$/o,
			    required => 1, },
			  { field    => FID_INST_ID,
			    pat      => qr/^$instid$/o,
			    required => 1, },
			  { field    => FID_VALID_PATRON_PWD,
			    pat      => qr/^N$/,
			    required => 1, },
			  { field    => FID_VALID_PATRON,
			    pat      => qr/^Y$/,
			    required => 1, },
			  ], },
	     { id => 'invalid Patron Status',
	       msg => "2300120060101    084237AO$instid|AAwshakespeare|AC|",
	       pat => qr/^24Y[ Y]{13}\d{3}$datepat/,
	       fields => [
			  { field    => FID_PERSONAL_NAME,
			    pat      => qr/^$/,
			    required => 1, },
			  { field    => FID_PATRON_ID,
			    pat      => qr/^wshakespeare$/,
			    required => 1, },
			  { field    => FID_INST_ID,
			    pat      => qr/^$instid$/o,
			    required => 1, },
			  ], },
	     );

SIPtest::run_sip_tests(@tests);

1;
