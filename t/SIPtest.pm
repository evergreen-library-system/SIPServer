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

package SIPtest;

use strict;
use warnings;

use Exporter;
use Data::Dumper;

our @ISA = qw(Exporter);
our $VERSION = 0.02;

our @EXPORT_OK = qw(run_sip_tests no_tagged_fields
		    $datepat $textpat
		    $login_test $sc_status_test
		    %field_specs

		    $instid $currency $server $username $password
		    $user_barcode $user_pin $user_fullname $user_homeaddr
		    $user_email $user_phone $user_birthday $user_ptype
		    $user_inet $user_homelib
		    $item_barcode $item_title $item_owner
		    $item2_barcode $item2_title $item2_owner
		    $item_diacritic_barcode $item_diacritic_title
		    $item_diacritic_owner);

# The number of tests is set in run_sip_tests() below, based
# on the size of the array of tests.
use Test::More;

use IO::Socket::INET;
use Encode;

use Sip qw(:all);
use Sip::Checksum qw(verify_cksum);
use Sip::Constants qw(:all);

# 
# Configuration parameters to run the test suite
#
our $instid   = 'BR1';
our $currency = 'USD';
our $server   = 'localhost:6001'; # Address of the SIP server

# SIP username and password to connect to the server.  See the
# SIP config.xml for the correct values.
# our $username = 'scclient';
# our $password = 'clientpwd';
our $username = 'sip_01';
our $password = 'sip_01';

# ILS Information

# Valid user barcode and corresponding user password/pin and full name
our $user_barcode  = '999999';  # 'djfiander';
our $user_pin      = '6789';
our $user_fullname = 'David J\. Fiander';
our $user_homeaddr = '2 Meadowvale Dr\. St Thomas, ON Canada 90210';
our $user_email    = 'djfiander\@hotmail\.com';
our $user_phone    = '\(519\) 555 1234';
our $user_birthday = '19640925';
our $user_ptype    = 'Patrons';
our $user_inet     = 'Unfiltered';
our $user_homelib  = 'BR1';

# Valid item barcode and corresponding title
# isbn: 9781565921870, 1565921879
# OCoLC: 34373965
our $item_barcode = '1565921879';
our $item_title   = 'Perl 5 desktop reference';
our $item_owner   = 'BR1';

# Another valid item
# isbn: 9780553088533
# OCoLC: 25026617
our $item2_barcode = '0440242746';
our $item2_title   = 'Snow crash';
our $item2_owner   = 'BR1';

# An item with a diacritical in the title
# isbn: 9788478886456, 9788478886456;
# OCoLC: 48667449
our $item_diacritic_barcode = '660';
our $item_diacritic_title = decode_utf8('Harry Potter y el cáliz de fuego');
our $item_diacritic_owner = 'BR1';

# End configuration

# Pattern for a SIP datestamp, to be used by individual tests to
# match timestamp fields (duh).
our $datepat = '\d{8} {4}\d{6}';

# Pattern for a random text field (may be empty)
our $textpat = qr/^[^|]*$/;

our %field_specs = (
    (FID_SCREEN_MSG) => {
        field    => FID_SCREEN_MSG,
        pat      => $textpat,
        required => 0,
    },
    (FID_PRINT_LINE) => {
        field    => FID_PRINT_LINE,
        pat      => $textpat,
        required => 0,
    },
    (FID_INST_ID) => {
        field    => FID_INST_ID,
        pat      => qr/^$instid$/o,
        required => 1,
    },
    (FID_HOLD_ITEMS_LMT) => {
        field    => FID_HOLD_ITEMS_LMT,
        pat      => qr/^\d{4}$/,
        required => 0,
    },
    (FID_OVERDUE_ITEMS_LMT) => {
        field    => FID_OVERDUE_ITEMS_LMT,
        pat      => qr/^\d{4}$/,
        required => 0,
    },
    (FID_CHARGED_ITEMS_LMT) => {
        field    => FID_CHARGED_ITEMS_LMT,
        pat      => qr/^\d{4}$/,
        required => 0,
    },
    (FID_VALID_PATRON) => {
        field    => FID_VALID_PATRON,
        pat      => qr/^[NY]$/,
        required => 0,
    },
    (FID_VALID_PATRON_PWD) => {
        field    => FID_VALID_PATRON_PWD,
        pat      => qr/^[NY]$/,
        required => 0,
    },
    (FID_CURRENCY) => {
        field    => FID_CURRENCY,
        pat      => qr/^$currency$/io,
        required => 0,
    },
);

# Login and SC Status are always the first two messages that
# the terminal sends to the server, so just create the test
# cases here and reference them in the individual test files.

our $login_test = { id => 'login',
		    msg => "9300CN$username|CO$password|CP$instid|",
		    pat => qr/^941/,
		    fields => [], };

our $sc_status_test = { id => 'SC status',
			msg => '9910302.00',
			pat => qr/^98[YN]{6}\d{3}\d{3}$datepat(2\.00|1\.00)/,
			fields => [
				   $field_specs{(FID_SCREEN_MSG)},
				   $field_specs{(FID_PRINT_LINE)},
				   $field_specs{(FID_INST_ID)},
				   { field    => 'AM',
				     pat      => $textpat,
				     required => 0, },
				   { field    => 'BX',
				     pat      => qr/^[YN]{16}$/,
				     required => 1, },
				   { field    => 'AN',
				     pat      => $textpat,
				     required => 0, },
				   ],
			};

our $debug = 1;
our $error_detect = 0;

sub one_msg {
    my ($sock, $test, $seqno) = @_;
    my $resp;
    my %fields;

    # If reading or writing fails, then the server's dead,
    # so there's no point in continuing.
    $debug and note("Sending message");
    if (!write_msg({seqno => $seqno}, $test->{msg}, $sock)) {
        BAIL_OUT("Write failure in $test->{id}");
    } elsif (!($resp = <$sock>)) {
        BAIL_OUT("Read failure in $test->{id}");
    }
    $debug and note("Processing response");

    chomp($resp);
    $resp =~ tr/\cM//d;
    $resp =~ s/\015?\012$//;
    $resp =~ s/^\s*//sg;
    chomp($resp);

    if ($error_detect and !verify_cksum($resp)) {
        fail("$test->{id} checksum($resp)");
        return;
    }
    if ($resp !~ $test->{pat}) {
        fail("match leader $test->{id}");
        diag("Response '$resp' doesn't match pattern '$test->{pat}'");
        return;
    }

    # Split the tagged fields of the response into (name, value)
    # pairs and stuff them into the hash.
    $resp =~ $test->{pat};
    %fields = substr($resp, $+[0]) =~ /(..)([^|]*)\|/go;

#    print STDERR Dumper($test);
#    print STDERR Dumper(\%fields);
    if (!defined($test->{fields})) {
        diag("TODO: $test->{id} field tests not written yet");
    } else {
        # If there are no tagged fields, then 'fields' should be an
        # empty list which will automatically skip this loop
        foreach my $ftest (@{$test->{fields}}) {
            my $field = $ftest->{field};

            if ($ftest->{required} && !exists($fields{$field})) {
                fail("$test->{id}: required field '$field' not found in '$resp'");
                return;
            }

            if (exists($fields{$field}) && (decode_utf8($fields{$field}) !~ $ftest->{pat})) {
                fail("$test->{id} field test $field");
                diag("Field '$field' pattern '$ftest->{pat}' fails to match value '$fields{$field}' in message '$resp'");
                return;
            }
        }
    }
    pass("$test->{id}");
    return;
}

sub run_sip_tests {
    $Sip::error_detection = $error_detect;
    $/ = "\r";
    # $/ = "\015\012";    # must use correct record separator

    my $sock = IO::Socket::INET->new(
        PeerAddr => $server,
        Type     => SOCK_STREAM
    );

    BAIL_OUT('failed to create connection to server') unless $sock;

    plan tests => scalar(@_);
    my $seqno = 1;
    foreach my $test (@_) {
        # print STDERR "Test $seqno:" . Dumper($test);
        one_msg($sock, $test, $seqno++);
        $seqno %= 10;		# sequence number is one digit
    }
}

1;
