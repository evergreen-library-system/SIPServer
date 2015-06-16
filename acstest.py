#!/usr/bin/python
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

import operator
import socket
from time import strftime;

def SipSocket(host='localhost', port=5300):
    so = socket.socket()
    so.connect((host, port))
    return so

def login(so, uname='scclient', passwd='clientpwd', locn='The basement',
          seqno=0):
    port = so.getpeername()[1]
    if port == 5300:
        resp = send(so, '9300CN%s|CO%s|CP%s|' % (uname, passwd, locn), seqno)
        print "Received", repr(resp)
        print "Verified: ", verify(resp)
    else:
        raise "Logging in is only support for the raw transport on port 5300"

def send(so, msg, seqno=0):
    if seqno:
        msg += 'AY' + str(seqno)[0] + 'AZ'
        msg += ('%04X' % calculate_cksum(msg))
    msg += '\r'
    print 'Sending', repr(msg)
    so.send(msg)
    resp = so.recv(1000)
    return resp, verify(resp)

def calculate_cksum(msg):
    return (-reduce(operator.add, map(ord, msg)) & 0xFFFF)

def sipdate():
    return(strftime("%Y%m%d    %H%M%S"))

def verify(msg):
    if msg[-1] == '\r': msg = msg[:-2]
    if msg[-6:-4] == 'AZ':
        cksum = calculate_cksum(msg[:-4])
        return (msg[-4:] == ('%04X' % cksum))
    # If there's no checksum, then the message is ok
    return True
