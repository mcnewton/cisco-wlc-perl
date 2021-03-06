#! /usr/bin/perl -w

package CiscoWireless::Util;

use strict;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(sanitise_mac format_mac convert_snmp_mac_to_hex get_mac_from_oid);
$VERSION = '0.01';



################################################################################
# MAC address functions


#-------------------------------------------------------------------------------
# Sanitise all sorts of formats of MAC address to lowercase aabbccddeeff format

sub sanitise_mac
{
  my ($inmac) = @_;

  return undef unless defined $inmac;

  if ($inmac =~ /^(?:0x)?([0-9a-f]{12})$/i) {
    # maybe mac is string possibly beginning 0x? if so, return without 0x
    return lc $1;
  }

  if ($inmac =~ /^([0-9a-f]{2})([:-]) ([0-9a-f]{2})\2
                  ([0-9a-f]{2})\2 ([0-9a-f]{2})\2
                  ([0-9a-f]{2})\2 ([0-9a-f]{2}) $/xi) {
    # IEEE or network formats aa-bb-cc-dd-ee-ff or aa:bb:cc:dd:ee:ff
    return lc "$1$3$4$5$6$7";
  }

  if ($inmac =~ /^([0-9a-f]{4}) \. ([0-9a-f]{4}) \. ([0-9a-f]{4}) $/xi) {
    # Cisco format aabb.ccdd.eeff
    return lc "$1$2$3";
  }

  if ($inmac =~ /^.{6}$/s) {
    # if MAC consists of exactly six chars, return hex representation
    return lc join("", unpack("H2H2H2H2H2H2", $inmac));
  }

  # dunno what it is...
  return undef;
}


#-------------------------------------------------------------------------------
# Format mac with user-supplied separator
#
# $mac should be supplied as 12 char hex
# $sep should be ':', '-' or '.'

sub format_mac
{
  my ($mac, $sep) = @_;

  return $mac unless defined $sep;

  if ($sep eq ":" || $sep eq "-") {
    return lc join($sep, unpack("(a2)6", $mac));
  }

  if ($sep eq ".") {
    return lc join($sep, unpack("(a4)3", $mac));
  }

  croak "unknown mac separator '$sep'";
}


#-------------------------------------------------------------------------------
# Convert MAC returned from SNMP to hex
#
# Tidies up whatever sort of junk for a MAC address comes from an SNMP get

sub convert_snmp_mac_to_hex
{
  my $inmac = shift;

  if ($inmac =~ /^(?:0x)?([0-9a-f]{12})$/) {
    # maybe mac is string possibly beginning 0x? if so, return without 0x
    return lc $1;
  }

  if ($inmac =~ /^.{6}$/s) {
    # if MAC consists of exactly six chars, return hex representation
    return lc join("", unpack("H2H2H2H2H2H2", $inmac));
  }

  # dunno what it is...
  carp "unknown mac address format '$inmac'";
  return undef;
}


#-------------------------------------------------------------------------------
# Get MAC address from OID (last six octets)

sub get_mac_from_oid
{
  my ($oid, $base) = @_;
  my $octets;

  if (defined $base) {
    unless ($oid =~ s/^$base.(\d+(?:\.\d+){5})$//) {
      carp "cannot extract mac from oid ($oid) with base ($base)";
      return undef;
    }
    $octets = $1;
  } else {
    unless ($oid =~ /(\d+(?:\.\d+){5})$/) {
      carp "cannot extract mac from oid ($oid)";
      return undef;
    }
    $octets = $1;
  }

  return lc join("", unpack("(H2)6", pack("C6", split(/\./, $octets))));
}


1;

