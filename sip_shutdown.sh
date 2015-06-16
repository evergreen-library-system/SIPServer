#!/bin/bash

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

[ -r $HOME/.bash_profile ] && $HOME/.bash_profile

# this is brittle: the primary server must have the lowest PPID
# this is brittle: ps behavior is very platform-specific, only tested on Debian Etch

target="SIPServer";
PROCPID=$(ps x -o pid,ppid,args --sort ppid | grep "$target" | grep -v grep | head -1 | awk '{print $1}');

if [ ! $PROCPID ] ; then
    echo "No processes found for $target";
    exit;
fi

echo "SIP Processes for this user ($USER):";
ps x -o pid,ppid,args --sort ppid | grep "$target" | grep -v grep ;
echo "Killing process #$PROCPID";
kill $PROCPID;
