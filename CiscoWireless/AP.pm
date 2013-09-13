#! /usr/bin/perl -w

package CiscoWireless::AP;

use Data::Dumper;
use CiscoWireless::Util;
use CiscoWireless::WLC;
use CiscoWireless::Cache;

use strict;
use Net::SNMP;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter CiscoWireless::Cache::Util);
@EXPORT = qw();
$VERSION = '0.01';


sub new
{
  my ($class, $mac, $wlc) = @_;

  my $smac = sanitise_mac($mac);
  croak "invalid mac address format ($mac)" unless defined $smac;

  my $self = {
    mac              => $smac,
    wlc              => $wlc,
    oidindex         => join(".", map {hex $_} unpack("(A2)6", $smac)),
    name             => undef,
    ethernetmac      => undef,

    _cache           => undef,
    _cachelife       => \%CiscoWireless::AP::_cachelife,
  };

  bless $self, $class;

  return $self;
}


sub init_cache
{
  my ($self, $cache) = @_;

  $self->{_cache} = $cache;
  $self->{_cachekey} = $cache->get_key_name("ap", $self->{mac});

  $self->_init_cache();
}


sub update
{
  my ($self, $key, $value) = @_;

  $self->{$key} = $value;
  my $h = $self->cache_insert($key, $value);

  return $value;
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
    $r = sanitise_mac($$r{$oid}); # may be undef
    return undef unless defined $r;
    $r =~ s/^0x//;
    $self->update("ethernetmac", $r);

#    $self->{ethernetmac} = sanitise_mac($$r{$oid}); # may be undef
#    $self->{ethernetmac} =~ s/^0x// if defined($self->{ethernetmac});
  }

  return format_mac($self->{ethernetmac}, $sep);
}

sub cdpneighbour
{
  my ($self) = @_;

  my $obase = ".1.3.6.1.4.1.9.9.623.1.3.1.1.";

  my $oids = { $obase . "6."  . $self->{oidindex} . ".1" => "hostname",
               $obase . "8."  . $self->{oidindex} . ".1" => "ip",
               $obase . "9."  . $self->{oidindex} . ".1" => "port",
               $obase . "10." . $self->{oidindex} . ".1" => "version",
             };

  my %out;

  my @snmpoid;

  foreach my $oid (keys %$oids) {
    if (defined $self->{"cdpn_" . $$oids{$oid}}) {
      $out{$$oids{$oid}} = $self->{"cdpn_" . $$oids{$oid}};
    } else {
      push @snmpoid, $oid;
    }
  }

  if (scalar @snmpoid) {
    my $r = $self->{wlc}->_snmp_get_ap($self, \@snmpoid);

    foreach my $oid (keys %$r) {
      if (defined($$oids{$oid})) {
        $out{$$oids{$oid}} = $$r{$oid};
        if ($$oids{$oid} eq 'ip') {
          my $ip = $$r{$oid};
          $ip =~ s/^0x//;
          $out{ip} = join ".", unpack "C4", pack "H8", $ip;
        }
        $self->update("cdpn_" . $$oids{$oid}, $out{$$oids{$oid}});
      }
    }
  }

  $self->{cdp} = \%out;

  return \%out;
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
      return $self->update($name, $$r{$oid} || undef);
#      $self->{$name} = $$r{$oid} || undef;
#      return $self->{$name};
    } else {
      my $slots = $self->numslots() || 1;
      my %ra = ();
      my $got_result = 0;

# todo: can't currently cache slot-based oids

      for (my $slot = 0; $slot < $slots; $slot++) {
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

    # todo: this can be fixed by accepting hashref as returned
    # above, and writing with a loop like above
  }

  if (defined $rw and !$rw) {
    carp "attempt to set read only value";
    return undef;
  }

  $r = $self->{wlc}->_snmp_write_ap($self, [$oid, $type, $new]);

  if (defined $r) {
    if (defined $$r{$oid}) {
       return $self->update($name, $$r{$oid});
#      $self->{$name} = $$r{$oid};
#      return $self->{$name};
    } else {
      carp "unknown result from snmp set request=$oid response=$$r[0] ($$r[1])";
    }
  }

  return undef;
}


# 1 week = 604800
# 2 days = 172800
# 1 day = 86400
# 

our %_cachelife = (
    "numslots"        => 604800,
    "name"            => 7200,
    "location"        => 7200,
    "operationstatus" => 600,
    "softwareversion" => 172800,
    "bootversion"     => 172800,
    "primarywlc"      => 7200,
    "model"           => 604800,
    "serialnumber"    => 604800,
    "ipaddress"       => 86400,
    "secondarywlc"    => 7200,
    "tertiarywlc"     => 7200,
    "isstaticip"      => 86400,
    "netmask"         => 86400,
    "gateway"         => 86400,
    "staticipaddress" => 86400,
    "apgroup"         => 86400,
    "adminstatus"     => 7200,

#    "ap_list"         => 300,
  );

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
    "clearconfig"     => [ ".1.3.6.1.4.1.14179.2.2.1.1.18.", 0, 1, INTEGER ],
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

# CISCO-LWAPP-AP::CLApEntry
    "uptime"                        => [ ".1.3.6.1.4.1.9.9.513.1.1.1.1.6.",  0, 0, INTEGER ],
    "jointime"                      => [ ".1.3.6.1.4.1.9.9.513.1.1.1.1.7.",  0, 0, INTEGER ],

  );

# INTEGER, INTEGER32, OCTET_STRING, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, COUNTER32, GAUGE,
# GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64


{
  foreach my $func (keys %_methods) {
    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \$_[1], " .
          "\$_methods{$func});}";
  }
}



################################################################################
# RRD functions (in development)

sub get_rrd_create
{
  my ($self, $func) = @_;

  carp "no method $func" unless defined $_methods{$func};

  my $use_slots = ${$_methods{$func}}[1];

  my $rrd = "rrdtool create filename.rrd";
  print "$use_slots\n";
}



################################################################################
# AP functions for WLC

package CiscoWireless::WLC;


#-------------------------------------------------------------------------------
# get list of all APs

sub get_aps
{
  my ($self) = @_;

  $self->_query_aps() unless defined $self->{ap_list};

  return values %{$self->{ap_list}};
}


#-------------------------------------------------------------------------------
# add or update values for an AP

sub _add_update_ap
{
  my ($self, $ap_mac, $data) = @_;

  unless (defined $self->{ap_list}{$ap_mac}) {
    $self->{ap_list}{$ap_mac} = CiscoWireless::AP->new($ap_mac, $self);
    $self->{ap_list}{$ap_mac}->init_cache($self->{_cache}) if defined $self->{_cache};
  }

  foreach my $i (keys %$data) {
    $self->{ap_list}{$ap_mac}->update($i, $$data{$i});
  }

#  return $self->{ap_list}{$ap_mac};
}


#-------------------------------------------------------------------------------
# force query the WLC for all connected APs

sub _query_aps
{
  my ($self) = @_;
  my $snmp_session;

  my $baseoid = ".1.3.6.1.4.1.14179.2.2.1.1.3";

  $self->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $ap_mac = get_mac_from_oid($oid);
      $self->_add_update_ap($ap_mac, {name => $value});
    });
}



1;

