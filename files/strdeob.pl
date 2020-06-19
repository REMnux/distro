#!/usr/bin/perl

# Locate and decode stack strings.
# Script created by the folks at TotalHash.

use strict;

unless (@ARGV) { print "Usage: strdeob.pl <file>\n"; exit; }

my $file = $ARGV[0];

unless (-f $file ) { print "Error file $file not found\n"; exit; }

open(ASM,"objdump -D $file |grep movb |") || die "Failed: $!\n";

my $strings;

while ( <ASM> ) {
    my $line = $_;
    if ($line =~ /([a-f0-9\:]+)\s+([a-f0-9\s]+)movb\s+\$0x([0-9a-f]{2})/) {
        my $inst = $3;
        #grab the last two chars and ascii them up
        my $string = sprintf ("%c", hex substr($inst, -2));
        $string =~ s/[\x7F-\xFF\x00-\x09\x0B-\x1F]/\./g;
        $strings .= $string;
    } else {
        unless (substr($strings, -1) eq "\n") {
            $strings .= "\n";
        }
    }
}

print "$strings\n";
