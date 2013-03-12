#! /usr/bin/perl -w

package CiscoWireless::AP;

use Data::Dumper;
use CiscoWireless::Util qw/sanitise_mac format_mac/;

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
  my ($class, $mac, $wlc) = @_;

  my $smac = sanitise_mac($mac);
  croak "invalid mac address format ($mac)" unless defined $smac;

  my $self = {
    mac         => $smac,
    wlc         => $wlc,
    oidindex    => join(".", map {hex $_} unpack("(A2)6", $smac)),
    name        => undef,
    ethernetmac => undef,
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

  return format_mac($self->{mac}, $sep);
}

sub ethernetmac
{
  my ($self, $sep) = @_;

  if (!defined($self->{ethernetmac})) {
    my $oid = ".1.3.6.1.4.1.14179.2.2.1.1.33." . $self->{oidindex};
    my $r = $self->{wlc}->_snmp_get_ap($self, [$oid]);
    $self->{ethernetmac} = sanitise_mac($$r{$oid}); # may be undef
    $self->{ethernetmac} =~ s/^0x// if defined($self->{ethernetmac});
  }

  return format_mac($self->{ethernetmac}, $sep);
}

sub wlc
{
  my ($self) = @_;

  return $self->{wlc};
}

sub _oidindex
{
  my ($self) = @_;

  return $self->{oidindex};
}

sub _generic_method
{
  #my ($self, $name, $oidprefix, $new, $rw, $type) = @_;
  my ($self, $name, $new, $opts) = @_;

  my ($oidprefix, $use_slots, $rw, $type) = @$opts;
  my $oid = $oidprefix . $self->{oidindex};
  my $r;

  unless (defined($new)) {
    return $self->{$name} if defined $self->{$name};

    if (!$use_slots) {
      $r = $self->{wlc}->_snmp_get_ap($self, [$oid]);
      return undef unless defined $r;
      $self->{$name} = $$r{$oid} || undef;
      return $self->{$name};
    } else {
      my $slots = $self->numslots() || 1;
      my %ra = ();
      my $got_result = 0;

      for (my $slot = 0; $slot < $slots; $slot++) {
#        print $oid . ".$slot\n";
        $r = $self->{wlc}->_snmp_get_ap($self, [$oid . ".$slot"]);
        $ra{$slot} = undef;
        if (defined $r) {
          $ra{$slot} = $$r{$oid . ".$slot"};
          $got_result = 1;
        }
        return undef unless $got_result;
      }

      $self->{$name} = \%ra || undef;
      return $self->{$name};
    }
  }

  if ($use_slots) {
    carp "currently unable to write to slot-based oid";
    return undef;

    # this can be fixed by accepting hashref as returned above, and
    # writing with a loop like above
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


# oidprefix, use_slots, rw, type

my %_methods = (
    "numslots"        => [ ".1.3.6.1.4.1.14179.2.2.1.1.2.",  0, 1, OCTET_STRING ],
    "name"            => [ ".1.3.6.1.4.1.14179.2.2.1.1.3.",  0, 1, OCTET_STRING ],
    "location"        => [ ".1.3.6.1.4.1.14179.2.2.1.1.4.",  0, 1, OCTET_STRING ],
    "operationstatus" => [ ".1.3.6.1.4.1.14179.2.2.1.1.6.",  0, 0, INTEGER ],
    "softwareversion" => [ ".1.3.6.1.4.1.14179.2.2.1.1.8.",  0, 0, OCTET_STRING ],
    "bootversion"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.9.",  0, 0, OCTET_STRING ],
    "primarywlc"      => [ ".1.3.6.1.4.1.14179.2.2.1.1.10.", 0, 1, OCTET_STRING ],
    "resetap"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.11.", 0, 1, INTEGER ],
    "model"           => [ ".1.3.6.1.4.1.14179.2.2.1.1.16.", 0, 0, OCTET_STRING ],
    "serialnumber"    => [ ".1.3.6.1.4.1.14179.2.2.1.1.17.", 0, 0, OCTET_STRING ],
    "clearconfig"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.19.", 0, 1, INTEGER ],
    "ipaddress"       => [ ".1.3.6.1.4.1.14179.2.2.1.1.19.", 0, 1, IPADDRESS ],
    "secondarywlc"    => [ ".1.3.6.1.4.1.14179.2.2.1.1.23.", 0, 1, OCTET_STRING ],
    "tertiarywlc"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.24.", 0, 1, OCTET_STRING ],
    "isstaticip"      => [ ".1.3.6.1.4.1.14179.2.2.1.1.25.", 0, 1, INTEGER ],
    "netmask"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.26.", 0, 1, IPADDRESS ],
    "gateway"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.27.", 0, 1, IPADDRESS ],
    "staticipaddress" => [ ".1.3.6.1.4.1.14179.2.2.1.1.28.", 0, 1, IPADDRESS ],
    "apgroup"         => [ ".1.3.6.1.4.1.14179.2.2.1.1.30.", 0, 1, OCTET_STRING ],
    "adminstatus"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.37.", 0, 1, INTEGER ],

# AIRESPACE-WIRELESS-MIB::bsnAPIfTable

    "bsnAPIfType"                   => [ ".1.3.6.1.4.1.14179.2.2.2.1.2.",  1, 0, INTEGER ],
    "bsnAPIfPhyChannelAssignment"   => [ ".1.3.6.1.4.1.14179.2.2.2.1.3.",  1, 1, INTEGER ],
    "bsnAPIfPhyChannelNumber"       => [ ".1.3.6.1.4.1.14179.2.2.2.1.4.",  1, 1, INTEGER ],
    "bsnAPIfPhyTxPowerControl"      => [ ".1.3.6.1.4.1.14179.2.2.2.1.5.",  1, 1, INTEGER ],
    "bsnAPIfPhyTxPowerLevel"        => [ ".1.3.6.1.4.1.14179.2.2.2.1.6.",  1, 1, INTEGER ],
    "bsnAPIfOperStatus"             => [ ".1.3.6.1.4.1.14179.2.2.2.1.12.", 1, 1, INTEGER ],
    "bsnApIfNoOfUsers"              => [ ".1.3.6.1.4.1.14179.2.2.2.1.15.", 1, 0, INTEGER ],
    "bsnAPIfAdminStatus"            => [ ".1.3.6.1.4.1.14179.2.2.2.1.34.", 1, 1, INTEGER ],

# AIRESPACE-WIRELESS-MIB::bsnAPIfLoadParametersTable
    "bsnAPIfLoadRxUtilization"      => [ ".1.3.6.1.4.1.14179.2.2.13.1.1.", 1, 0, INTEGER ],
    "bsnAPIfLoadTxUtilization"      => [ ".1.3.6.1.4.1.14179.2.2.13.1.2.", 1, 0, INTEGER ],
    "bsnAPIfLoadChannelUtilization" => [ ".1.3.6.1.4.1.14179.2.2.13.1.3.", 1, 0, INTEGER ],
    "bsnAPIfLoadNumOfClients"       => [ ".1.3.6.1.4.1.14179.2.2.13.1.4.", 1, 0, INTEGER ],
    "bsnAPIfPoorSNRClients"         => [ ".1.3.6.1.4.1.14179.2.2.13.1.5.", 1, 0, INTEGER ],
  
  );

# INTEGER, INTEGER32, OCTET_STRING, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, COUNTER32, GAUGE,
# GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64


{
  foreach my $func (keys %_methods) {
    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \$_[1], " .
          "\$_methods{$func});}";
  }
}

#{
#  foreach my $func (keys %_methods) {
#    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \"" .
#          $_methods{$func}[0] . "\", \$_[1], " . $_methods{$func}[1] . ", " .
#          $_methods{$func}[2] . ");}"
#  }
#}


sub get_rrd_create
{
  my ($self, $func) = @_;

  carp "no method $func" unless defined $_methods{$func};

  my $use_slots = ${$_methods{$func}}[1];

  my $rrd = "rrdtool create filename.rrd";
  print "$use_slots\n";
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

