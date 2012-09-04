#! /usr/bin/perl -w

package CiscoWireless::AP;

use Data::Dumper;

use strict;
use Net::SNMP;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw();
$VERSION = '0.01';


sub new
{
  my ($class, $wlc, $mac, $wlc_ip) = @_;

  croak "invalid mac address format ($mac)" unless $mac =~ /^[a-f0-9]{12}$/i;

  my $self = {
    wlc         => $wlc,
    mac         => $mac,
    oidindex    => join(".", map {hex $_} unpack("(A2)6", $mac)),
    wlc_ip      => $wlc_ip,
    name        => undef,
  };

  bless $self, $class;
  $self->init();

  return $self;
}

sub init
{
  my ($self) = @_;

}

sub update
{
  my ($self, $key, $value) = @_;

  $self->{$key} = $value;
}

#sub name
#{
#  my ($self, $new) = @_;
#
#  return $self->{name} unless defined $new;
#
#  my $oid = ".1.3.6.1.4.1.14179.2.2.1.1.3." . $self->{oidindex};
#  my $r = $self->{wlc}->_snmp_write_ap($self, [$oid, OCTET_STRING, $new]);
#
#  if (defined $r) {
#    if ($$r[0] eq $oid) {
#      $self->{name} = $$r[1];
#      return 1;
#    } else {
#      carp "unknown result from snmp set request=$oid response=$$r[0] ($$r[1])";
#    }
#  }
#
#  return 0;
#}

sub mac
{
  my ($self, $sep) = @_;

  if (defined $sep) {
    if ($sep eq ":" || $sep eq "-") {
      return lc join($sep, unpack("(a2)6", $self->{mac}));
    }
    if ($sep eq ".") {
      return lc join($sep, unpack("(a4)3", $self->{mac}));
    }
    croak "unknown separator '$sep'";
  }

  return $self->{mac};
}

sub wlcip
{
  my ($self) = @_;

  return $self->{wlc_ip};
}

sub _oidindex
{
  my ($self) = @_;

  return $self->{oidindex};
}

sub _generic_method
{
  my ($self, $name, $oidprefix, $new, $rw, $type) = @_;
  my $oid = $oidprefix . $self->{oidindex};
  my $r;

  unless (defined($new)) {
    return $self->{$name} if defined $self->{$name};

    $r = $self->{wlc}->_snmp_get_ap($self, [$oid]);
    return undef unless defined $r;
    $self->{$name} = $$r{$oid} || undef;
    return $self->{$name};
  }

  if (defined $rw and !$rw) {
    carp "attempt to set read only value";
    return undef;
  }

  $r = $self->{wlc}->_snmp_write_ap($self, [$oid, $type, $new]);

  if (defined $r) {
    if (defined $$r{$oid}) {
      $self->{$name} = $$r{$oid};
      return $self->{$name};
    } else {
      carp "unknown result from snmp set request=$oid response=$$r[0] ($$r[1])";
    }
  }

  return undef;
}

#sub location
#{
#  my ($self, $new) = @_;
#
#  return $self->_generic_method("location", ".1.3.6.1.4.1.14179.2.2.1.1.4.", $new, 1);
#}

my %_methods = (
    "name"            => [ ".1.3.6.1.4.1.14179.2.2.1.1.3.", 1, OCTET_STRING],
    "location"        => [ ".1.3.6.1.4.1.14179.2.2.1.1.4.", 1, OCTET_STRING],
    "operationstatus" => [ ".1.3.6.1.4.1.14179.2.2.1.1.6.", 0, INTEGER],
    "softwareversion" => [ ".1.3.6.1.4.1.14179.2.2.1.1.8.", 0, OCTET_STRING],
    "bootversion"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.9.", 0, OCTET_STRING],
    "primarywlc"      => [ ".1.3.6.1.4.1.14179.2.2.1.1.10.", 1, OCTET_STRING],
    "resetap"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.11.", 1, INTEGER],
    "model"           => [ ".1.3.6.1.4.1.14179.2.2.1.1.16.", 0, OCTET_STRING],
    "serialnumber"    => [ ".1.3.6.1.4.1.14179.2.2.1.1.17.", 0, OCTET_STRING],
    "clearconfig"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.19.", 1, INTEGER],
    "ipaddress"       => [ ".1.3.6.1.4.1.14179.2.2.1.1.19.", 1, IPADDRESS],
    "secondarywlc"    => [ ".1.3.6.1.4.1.14179.2.2.1.1.23.", 1, OCTET_STRING],
    "tertiarywlc"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.24.", 1, OCTET_STRING],
    "isstaticip"      => [ ".1.3.6.1.4.1.14179.2.2.1.1.25.", 1, INTEGER],
    "netmask"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.26.", 1, IPADDRESS],
    "gateway"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.27.", 1, IPADDRESS],
    "staticipaddress" => [ ".1.3.6.1.4.1.14179.2.2.1.1.28.", 1, IPADDRESS],
    "apgroup"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.30.", 1, OCTET_STRING],
    "ethernetmac"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.33.", 0, OCTET_STRING],
    "adminstatus"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.37.", 1, INTEGER],
  );

# INTEGER, INTEGER32, OCTET_STRING, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, COUNTER32, GAUGE,
# GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64


{
  foreach my $func (keys %_methods) {
    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \"" .
          $_methods{$func}[0] . "\", \$_[1], " . $_methods{$func}[1] . ", " .
          $_methods{$func}[2] . ");}"
  }
}




#sub location
#{
#  my ($self, $new) = @_;
#  my $oid = ".1.3.6.1.4.1.14179.2.2.1.1.4." . $self->{oidindex};
#  my $r;
#
#  unless (defined($new)) {
#    return $self->{location} if defined $self->{location};
#
#    $r = $self->{wlc}->_snmp_get_ap($self, [$oid]);
#    return undef unless defined $r;
#    $self->{location} = $$r{$oid} || undef;
#    return $self->{location};
#  }
#
#  $r = $self->{wlc}->_snmp_write_ap($self, [$oid, OCTET_STRING, $new]);
#
#  if (defined $r) {
#    if (defined $$r{$oid}) {
#      $self->{location} = $$r{$oid};
#      return $self->{location};
#    } else {
#      carp "unknown result from snmp set request=$oid response=$$r[0] ($$r[1])";
#    }
#  }
#
#  return undef;
#}

1;

