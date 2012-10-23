#
# Copyright (C) 2006-2008  Georgia Public Library Service
# 
# Author: David J. Fiander
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307 USA

package Sip::Checksum;

use Exporter;
use strict;
use warnings;
use integer;    # important

our $VERSION   = 0.02;
our @EXPORT_OK = qw(checksum verify_cksum);
our @ISA   = qw(Exporter);
our $debug = 0;

sub debug_print {
    my $label = shift;
    my $var   = shift;
    printf STDERR "# %16s: %016s %4.4s %6s\n",
        $label,
           substr(sprintf("%b",   $var), -16),
        uc substr(sprintf("%4.4x",$var),  -4),
        $var;
}

sub debug_split_print {
    my $line = shift;
    my $total = 0;
    my (@row, @rows);
    foreach(split('', $line)) {
        $total += ord($_);
        push @row, $_;
        if (scalar(@row) == 10) {
            push @rows, [@row];
            @row = ();
        }
    }
    scalar(@row) and push @rows, \@row;
    foreach (@rows) {
        my $subtotal = 0;
        print STDERR map {"   $_ "} @$_;
        printf STDERR "\n%-50s", join '', map {sprintf " %3d ", $_} map {$subtotal += ord($_); ord($_)} @$_;
        printf STDERR "= %4d\n\n", $subtotal;
    }
    printf STDERR "%56d\n", $total;
    # Pack, then upack to make sure we have 16-bit value.
    return unpack("S", pack("S", $total));
}


sub checksum {
    my $pkt   = shift;
    my $u     = unpack('%16C*', $pkt);
    my $check = ($u * -1) & 0xFFFF;
    if ($debug) {
        my $total = debug_split_print($pkt);
        $total == $u or warn "Internal error: mismatch between $total and $u";
        printf STDERR "# checksum('$pkt')\n# %34s  HEX  DECIMAL\n", 'BINARY';
        debug_print("ascii sum",      $u  );
        debug_print("binary invert", ~$u  );
        debug_print("add one",       ~$u+1);
        printf STDERR "# %39s\n", $check;
    }

    return sprintf("%4.4X", $check);
}

sub verify_cksum {
    my $pkt = shift;
    my $cksum;
    my $shortsum;

    return 0 if (not defined($pkt) or substr($pkt, -6, 2) ne "AZ"); # No checksum at end

    # Convert the checksum back to hex and calculate the sum of the
    # pack without the checksum.
    $cksum = hex(substr($pkt, -4));
    $shortsum = unpack("%16C*", substr($pkt, 0, -4));

    # The checksum is valid if the hex sum, plus the checksum of the 
    # base packet short when truncated to 16 bits.
    return (($cksum + $shortsum) & 0xFFFF) == 0;
}

1;

__END__

#
# Some simple test data
#
sub test {
    my $testpkt = shift;
    my $cksum = checksum($testpkt);
    my $fullpkt = sprintf("%s%4X", $testpkt, $cksum);

    print $fullpkt, "\n";
}

while (<>) {
    chomp;
    test($_);
}
