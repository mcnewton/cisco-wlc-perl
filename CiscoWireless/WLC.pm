#! /usr/bin/perl -w

package CiscoWireless::WLC;

use Data::Dumper;
use CiscoWireless::Util;

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
  my ($class, $ip, $data) = @_;

  carp "Unknown WLC IP" unless defined $ip;

  my $self = {
    ip               => $ip,
    _ciscowireless   => undef,
    name             => undef,
    snmp_community   => "public",
    snmp_version     => 1,
    ap_list          => undef,
    client_list      => undef,
    auto_requery_aps => 1, # try and find new controller if I don't have requested AP
  };

  $$self{snmp_community} = delete $$data{community} if $$data{community};
  $$self{snmp_version} = delete $$data{version} if $$data{version};

  carp "Unknown arguments" if scalar %$data;

  bless $self, $class;

  return $self;
}


sub update
{
  my ($self, $key, $value) = @_;

  $self->{$key} = $value;
}


sub ip
{
  my ($self, $new_ip) = @_;

  my $current_ip = $self->{ip};

  $self->{ip} = $new_ip if defined $new_ip;

  return $current_ip;
}


sub _generic_method
{
  my ($self, $name, $oid, $new, $rw, $type) = @_;
  my $r;

  unless (defined($new)) {
    return $self->{$name} if defined $self->{$name};

    my $snmp_session = $self->_get_snmp_session();
    $r = $snmp_session->get_request(-varbindlist => [$oid]);

    return undef unless defined $r;
    $self->{$name} = $$r{$oid} || undef;
    return $self->{$name};
  }

  if (defined $rw and !$rw) {
    carp "attempt to set read only value";
    return undef;
  }

  carp "write not implemented";

#  $r = $self->{wlc}->_snmp_write_ap($self, [$oid, $type, $new]);
#
#  if (defined $r) {
#    if (defined $$r{$oid}) {
#      $self->{$name} = $$r{$oid};
#      return $self->{$name};
#    } else {
#      carp "unknown result from snmp set request=$oid response=$$r[0] ($$r[1])";
#    }
#  }

  return undef;
}


my %_methods = (
    "name"             => [ ".1.3.6.1.2.1.1.5.0",   0, OCTET_STRING],
    "model"            => [ ".1.3.6.1.4.1.14179.1.1.1.3.0",   0, OCTET_STRING],
    "serial"           => [ ".1.3.6.1.4.1.14179.1.1.1.4.0",   0, OCTET_STRING],
    "burnedinmac"      => [ ".1.3.6.1.4.1.14179.1.1.1.9.0",   0, OCTET_STRING],
    "manufacturer"     => [ ".1.3.6.1.4.1.14179.1.1.1.12.0",  0, OCTET_STRING],
    "productname"      => [ ".1.3.6.1.4.1.14179.1.1.1.13.0",  0, OCTET_STRING],
    "version"          => [ ".1.3.6.1.4.1.14179.1.1.1.14.0",  0, OCTET_STRING],
    "maxaps"           => [ ".1.3.6.1.4.1.14179.1.1.1.18.0",  0, OCTET_STRING],
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


################################################################################
# AP functions

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


#-------------------------------------------------------------------------------
# Generic SNMP write to an AP

sub _snmp_write_ap
{
  my ($self, $ap, $vbl) = @_;

  my $wlc_ip = $ap->{wlc}->{ip};
  my $snmp_session = $self->_get_snmp_session($wlc_ip);

  my $r = $snmp_session->set_request(-varbindlist => $vbl);
  return $r if defined $r;

  # AP may have moved to a different controller
  $self->_query_aps();
  my $wlc_ip2 = $ap->{wlc}->{ip};
  return undef if $wlc_ip eq $wlc_ip2;

  $snmp_session = $self->_get_snmp_session($wlc_ip2);
  return $snmp_session->set_request(-varbindlist => $vbl);
}


#-------------------------------------------------------------------------------
# Generic SNMP get for an AP

sub _snmp_get_ap
{
  my ($self, $ap, $vbl) = @_;

  my $snmp_session = $self->_get_snmp_session();

  my $r = $snmp_session->get_request(-varbindlist => $vbl);
  return $r if defined $r;

  return undef;
##  # AP may have moved to a different controller
##  $self->_query_aps();
##  my $wlc_ip2 = $ap->{wlc_ip};
##  return undef if $wlc_ip eq $wlc_ip2;
##
##  $snmp_session = $self->_get_snmp_session($wlc_ip2);
##  return $snmp_session->get_request(-varbindlist => $vbl);
}

################################################################################
# Client functions

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

#  return $self->{client_list}{$ap_mac};
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



################################################################################
# Rogue functions

#-------------------------------------------------------------------------------
# get list of all rogues

sub get_rogues
{
  my ($self) = @_;

  $self->_query_rogues() unless defined $self->{rogue_list};

  return values %{$self->{rogue_list}};
}


#-------------------------------------------------------------------------------
# add or update values for a rogue

sub _add_update_rogue
{
  my ($self, $rogue_mac) = @_;

  unless (defined $self->{rogue_list}{$rogue_mac}) {
    $self->{rogue_list}{$rogue_mac} = CiscoWireless::Rogue->new($rogue_mac, $self);
  }

#  foreach my $i (keys %$data) {
#    $self->{rogue_list}{$rogue_mac}->update($i, $$data{$i});
#  }

#  return $self->{rogue_list}{$rogue_mac};
}


#-------------------------------------------------------------------------------
# force query the WLC for all detected rogues

sub _query_rogues
{
  my ($self) = @_;
  my $snmp_session;

  my $baseoid = ".1.3.6.1.4.1.14179.2.1.7";

  $self->_get_generic_snmp_table($baseoid,
    sub {
      my ($oid, $value) = @_;
      my $rogue_mac = get_mac_from_oid($oid);
      $self->_add_update_rogue($rogue_mac);
    });
}



################################################################################
# SNMP functions



#-------------------------------------------------------------------------------
# Get SNMP session for this WLC

sub _get_snmp_session
{
  my ($self) = shift;

  return $self->{snmp_session} if defined $self->{snmp_session};

  my ($session, $error) = Net::SNMP->session(
                            -version => $self->{snmp_version},
                            -hostname => $self->{ip},
                            -community => $self->{snmp_community});

  if (!defined $session) {
    carp "error getting snmp session to " . $self->{ip} . " ($error)";
    return undef;
  }

  $self->{snmp_session} = $session;

  return $session;
}


#-------------------------------------------------------------------------------
# Generic read SNMP table

sub _get_generic_snmp_table
{
  my ($self, $tablebase, $callback) = @_;
  my $count = 0;
  my $oid;

  my $session = $self->_get_snmp_session();

  my @args = (-varbindlist => [$tablebase]);

  while (defined($session->get_next_request(@args))) {
    $oid = ($session->var_bind_names())[0];

    last unless Net::SNMP::oid_base_match($tablebase, $oid);

    my $value = $session->var_bind_list()->{$oid};
    &$callback($oid, $value);
    $count++;

    @args = (-varbindlist => [$oid]);
  }

  return $count;
}


#-------------------------------------------------------------------------------
# Generic SNMP write

sub _snmp_write
{
  my ($self, $vbl) = @_;

  my $snmp_session = $self->_get_snmp_session();
  return $snmp_session->set_request(-varbindlist => $vbl);
}


#-------------------------------------------------------------------------------
# Generic SNMP get

sub _snmp_get
{
  my ($self, $vbl) = @_;

  my $snmp_session = $self->_get_snmp_session();
  return $snmp_session->get_request(-varbindlist => $vbl);
}


1;

