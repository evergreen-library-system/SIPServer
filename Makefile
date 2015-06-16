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
# There's not a lot to "make", but this simplifies the usual
# sorts of tasks
#

PODFLAGS = --htmlroot=. --podroot=.

.SUFFIXES: .pod .html

.pod.html:
	pod2html $(PODFLAGS) --outfile=$@ --infile=$<

all:
	@echo Nothing to make.  The command '"make run"' will run the server.

# just run the server from the command line
run: 
	perl SIPServer.pm SIPconfig.xml

test:
	cd t; $(MAKE) test

tags:
	find . -name '*.pm' -print | etags -

html: ILS.html ILS/Item.html ILS/Patron.html
