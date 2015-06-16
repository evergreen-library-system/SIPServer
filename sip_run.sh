#!/bin/bash
#
# Copyright (C) 2010 Equinox Software, Inc.
# Author: Joe Atzberger
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
# A sample script for starting SIP.  
# You probably want to specify new log destinations.
#
# Takes 3 optional arguments:
# ~ SIPconfig.xml file to use
# ~ file for STDOUT, default ~/sip.out
# ~ file for STDERR, default ~/sip.err
#
# The STDOUT and STDERR files are only for the SIPServer process itself.
# Actual SIP communication and transaction logs are handled by Syslog.
#
# Examples:
#   sip_run.sh /path/to/SIPconfig.xml
#   sip_run.sh ~/my_sip/SIPconfig.xml sip_out.log sip_err.log


for x in HOME PERL5LIB; do
	echo $x=${!x}
	if [ -z ${!x} ] ; then 
		echo ERROR: $x not defined;
		exit 1;
	fi;
done;
unset x;
# cd $PERL5LIB/C4/SIP;
echo;
echo Running from `pwd`;

sipserver='./SIPServer.pm';
sipconfig=${1:-`pwd`/SIPconfig.xml};
outfile=${2:-$HOME/sip.out};
errfile=${3:-$HOME/sip.err};

if [ ! -r $sipconfig ] ; then
    echo "ERROR: Required SIP Configuration file not found at '$sipconfig'" >&2;
    exit 1;
fi
if [ ! -r $sipserver ] ; then
    echo "ERROR: Target SIPServer not found at '$sipserver'" >&2;
    exit 1;
fi
echo "Calling (backgrounded):";
echo "perl -I./ $sipserver $sipconfig >>$outfile 2>>$errfile";
perl -I./ $sipserver $sipconfig >>$outfile 2>>$errfile &
