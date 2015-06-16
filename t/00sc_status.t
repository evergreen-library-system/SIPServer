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
# sc_status: test basic connection, login, and response
# to the SC Status message, which has to be sent before
# anything else

use strict;
use warnings;

use SIPtest qw($datepat $username $password $login_test $sc_status_test);

my $invalid_uname = { id => 'Invalid username',
		      msg => "9300CNinvalid$username|CO$password|CPThe floor|",
		      pat => qr/^940/,
		      fields => [], };

my $invalid_pwd = { id => 'Invalid password',
		      msg => "9300CN$username|COinvalid$password|CPThe floor|",
		      pat => qr/^940/,
		      fields => [], };

my @tests = ( $invalid_uname, $invalid_pwd, $login_test, $sc_status_test );

SIPtest::run_sip_tests(@tests);

1;
