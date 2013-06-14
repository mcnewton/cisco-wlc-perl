#! /usr/bin/perl -w

package CiscoWireless::Client;

use Data::Dumper;
use CiscoWireless::WLC;

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

  croak "invalid mac address format ($mac)" unless $mac =~ /^[a-f0-9]{12}$/i;

  my $self = {
    mac         => $mac,
    wlc         => $wlc,
    oidindex    => join(".", map {hex $_} unpack("(A2)6", $mac)),
    username    => undef,
    ip          => undef,
    nearby      => undef,
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
  my ($self, $name, $new, $opts) = @_;

  my ($oidprefix, $rw, $type) = @$opts;
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


my %_methods = (
    "ipaddress"       => [ ".1.3.6.1.4.1.14179.2.1.4.1.2.",  1, IPADDRESS ],
    "username"        => [ ".1.3.6.1.4.1.14179.2.1.4.1.3.",  1, OCTET_STRING ],
    "apmac"           => [ ".1.3.6.1.4.1.14179.2.1.4.1.4.",  1, OBJECT_IDENTIFIER ],
    "apslot"          => [ ".1.3.6.1.4.1.14179.2.1.4.1.5.",  1, INTEGER ],
    "wlanid"          => [ ".1.3.6.1.4.1.14179.2.1.4.1.6.",  1, INTEGER ],
    "ssid"            => [ ".1.3.6.1.4.1.14179.2.1.4.1.7.",  1, OCTET_STRING ],
    "status"          => [ ".1.3.6.1.4.1.14179.2.1.4.1.9.",  1, INTEGER ],
    "reasoncode"      => [ ".1.3.6.1.4.1.14179.2.1.4.1.10.", 1, INTEGER ],
    "mobilitystatus"  => [ ".1.3.6.1.4.1.14179.2.1.4.1.11.", 1, INTEGER ],
    "anchoraddress"   => [ ".1.3.6.1.4.1.14179.2.1.4.1.12.", 1, IPADDRESS ],
    "sessiontimeout"  => [ ".1.3.6.1.4.1.14179.2.1.4.1.18.", 1, INTEGER32 ],
    "delete"          => [ ".1.3.6.1.4.1.14179.2.1.4.1.22.", 0, INTEGER ],
    "protocol"        => [ ".1.3.6.1.4.1.14179.2.1.4.1.25.", 1, INTEGER ],
    "vlan"            => [ ".1.3.6.1.4.1.14179.2.1.4.1.29.", 1, INTEGER ],
    "policytype"      => [ ".1.3.6.1.4.1.14179.2.1.4.1.30.", 1, INTEGER ],
    "encryptioncipher"=> [ ".1.3.6.1.4.1.14179.2.1.4.1.31.", 1, INTEGER ],
    "eaptype"         => [ ".1.3.6.1.4.1.14179.2.1.4.1.32.", 1, INTEGER ],
    "ccxversion"      => [ ".1.3.6.1.4.1.14179.2.1.4.1.33.", 1, INTEGER ],
  );

# INTEGER, INTEGER32, OCTET_STRING, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, COUNTER32, GAUGE,
# GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64


{
  foreach my $func (keys %_methods) {
    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \$_[1], " .
          "\$_methods{$func});}";
  }
}


#sub get_rrd_create
#{
#  my ($self, $func) = @_;
#
#  carp "no method $func" unless defined $_methods{$func};
#
#  my $use_slots = ${$_methods{$func}}[1];
#
#  my $rrd = "rrdtool create filename.rrd";
#  print "$use_slots\n";
#}


sub get_nearby_aps
{
  my ($self) = @_;

  return $self->{nearby} if defined $self->{nearby};

  my %nearby = ();

  my $baseoid = ".1.3.6.1.4.1.14179.2.1.11.1.4." . $self->{oidindex};
  $self->{wlc}->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $ap_mac = $self->_get_nearby_ap_mac_from_oid($oid);
      $nearby{$ap_mac}{name} = $value;
    });

  $baseoid = ".1.3.6.1.4.1.14179.2.1.11.1.5." . $self->{oidindex};
  $self->{wlc}->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $ap_mac = $self->_get_nearby_ap_mac_from_oid($oid);
      $nearby{$ap_mac}{rssi} = $value;
    });

  $baseoid = ".1.3.6.1.4.1.14179.2.1.11.1.25." . $self->{oidindex};
  $self->{wlc}->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $ap_mac = $self->_get_nearby_ap_mac_from_oid($oid);
      $nearby{$ap_mac}{lastseen} = $value;
    });

  $self->{nearby} = \%nearby;

  return $self->{nearby};
}


sub _get_nearby_ap_mac_from_oid
{
  my ($self, $oid) = @_;

  unless ($oid =~ /\.(\d+(?:\.\d+){5}).[01].[01]$/) {
    carp "cannot extract mac from oid ($oid)";
    return undef;
  }

  return lc join("", unpack("(H2)6", pack("C6", split(/\./, $1))));
}



################################################################################
# Client functions for WLC

package CiscoWireless::WLC;


#-------------------------------------------------------------------------------
# add or update values for a Client

sub get_clients
{
  my ($self) = @_;

  $self->_query_clients() unless defined $self->{client_list};

  return values %{$self->{client_list}};
}


#-------------------------------------------------------------------------------
# add or update values for a Client

sub _add_update_client
{
  my ($self, $client_mac, $data) = @_;

  unless (defined $self->{client_list}{$client_mac}) {
    $self->{client_list}{$client_mac} = CiscoWireless::Client->new($client_mac, $self);
  }

  foreach my $i (keys %$data) {
    $self->{client_list}{$client_mac}->update($i, $$data{$i});
  }
}


#-------------------------------------------------------------------------------
# force query the WLC for all connected Clients

sub _query_clients
{
  my ($self) = @_;
  my $snmp_session;

  my $baseoid = ".1.3.6.1.4.1.14179.2.1.4.1.4";

  $self->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $client_mac = get_mac_from_oid($oid);
      $self->_add_update_client($client_mac,
        {apmac => convert_snmp_mac_to_hex($value)});
    });
}


1;

