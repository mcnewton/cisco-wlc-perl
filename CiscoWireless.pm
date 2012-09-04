#! /usr/bin/perl -w

package CiscoWireless;

use Data::Dumper;
use Net::SNMP;

use CiscoWireless::AP;
use CiscoWireless::WLC;

use strict;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw();
$VERSION = '0.01';


sub new
{
  my ($class, %data) = @_;

  my $self = {
    ap_list     => undef,
    wlc_list    => {},
    cache_file  => undef,
    cache_data  => undef,
  };

  bless $self, $class;
  $self->init();

  return $self;
}

sub init
{
  my ($self) = @_;

}

################################################################################
# WLC functions

#-------------------------------------------------------------------------------
# add_wlc

sub add_wlc
{
  my ($self, $ip, $data) = @_;

  unless (defined $ip) {
    carp "No IP address specificed";
    return undef;
  }

  if (defined $$self{wlc_list}{$ip}) {
    carp "WLC $ip already added";
    return undef;
  }

  my $wlc = {
    ip => $ip,
    snmp_community => "public",
    snmp_version => 1,
    hostname => undef,
  };

  $$wlc{snmp_community} = delete $$data{community} if $$data{community};
  $$wlc{snmp_version} = delete $$data{version} if $$data{version};

  $self->{wlc_list}{$ip} = $wlc;

  carp "add_wlc: unknown arguments" if scalar %$data;
  
  1;
}

#-------------------------------------------------------------------------------
# _get_snmp_session

sub _get_snmp_session
{
  my ($self, $wlc_ip) = @_;

  return undef unless defined $self->{wlc_list}{$wlc_ip};

  my $wlc = $self->{wlc_list}{$wlc_ip};

  return $$wlc{snmp_session} if defined $$wlc{snmp_session};

  my ($session, $error) = Net::SNMP->session(
                            -version => $$wlc{snmp_version},
                            -hostname => $wlc_ip,
                            -community => $$wlc{snmp_community});

  if (!defined $session) {
    carp "error getting snmp session to $wlc_ip ($error)";
    return undef;
  }

  $$wlc{snmp_session} = $session;

  return $session;
}


################################################################################
# AP functions

#-------------------------------------------------------------------------------
# get_aps

sub get_aps
{
  my ($self) = @_;

  $self->_query_wlcs_aps() unless defined $self->{ap_list};

  return values %{$self->{ap_list}};
}


sub get_ap_by_name
{
  my ($self, $name) = @_;

  $name = lc $name;

  $self->_query_wlcs_aps() unless defined $self->{ap_list};

  foreach my $ap (values %{$self->{ap_list}}) {
    if (lc $ap->{name} eq $name) {
      return $ap;
    }
  }

  return undef;
}


sub get_ap_by_mac
{
  my ($self, $mac) = @_;

  $mac = lc $mac;

  $self->_query_wlcs_aps() unless defined $self->{ap_list};

  foreach my $ap (values %{$self->{ap_list}}) {
    if (lc $ap->{mac} eq $mac) {
      return $ap;
    }
  }

  return undef;
}


#-------------------------------------------------------------------------------
# query_aps

sub _query_wlcs_aps
{
  my ($self) = @_;
  my $snmp_session;

  my $baseoid = ".1.3.6.1.4.1.14179.2.2.1.1.3";
  foreach my $wlc_ip (keys %{$self->{wlc_list}}) {
    $snmp_session = $self->_get_snmp_session($wlc_ip);
    $self->_get_generic_snmp_table($snmp_session, $baseoid,
      sub {
        my ($oid, $value) = @_;
        my $mac = _get_mac_from_oid($oid);
        $self->_add_update_ap($mac, $wlc_ip, {name => $value});
      });
  }
}


#-------------------------------------------------------------------------------
# add or update values for an AP

sub _add_update_ap
{
  my ($self, $ap_mac, $wlc_ip, $data) = @_;

  unless (defined $self->{ap_list}{$ap_mac}) {
    $self->{ap_list}{$ap_mac} = WLC::AP->new($self, $ap_mac, $wlc_ip);
  }

  foreach my $i (keys %$data) {
    $self->{ap_list}{$ap_mac}->update($i, $$data{$i});
  }

#  return $self->{ap_list}{$ap_mac};
}


################################################################################
# SNMP functions

#-------------------------------------------------------------------------------
# Generic read SNMP table

sub _get_generic_snmp_table
{
  my ($self, $session, $tablebase, $callback) = @_;
  my $count = 0;
  my $oid;

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
# Generic SNMP write to an AP

sub _snmp_write_ap
{
  my ($self, $ap, $vbl) = @_;

  my $wlc_ip = $ap->{wlc_ip};
  my $snmp_session = $self->_get_snmp_session($wlc_ip);

  my $r = $snmp_session->set_request(-varbindlist => $vbl);
  return $r if defined $r;

  # AP may have moved to a different controller
  $self->_query_wlcs_aps();
  my $wlc_ip2 = $ap->{wlc_ip};
  return undef if $wlc_ip eq $wlc_ip2;

  $snmp_session = $self->_get_snmp_session($wlc_ip2);
  return $snmp_session->set_request(-varbindlist => $vbl);
}

#-------------------------------------------------------------------------------
# Generic SNMP write

sub _snmp_get_ap
{
  my ($self, $ap, $vbl) = @_;

  my $wlc_ip = $ap->{wlc_ip};
  my $snmp_session = $self->_get_snmp_session($wlc_ip);

  my $r = $snmp_session->get_request(-varbindlist => $vbl);
  return $r if defined $r;

  # AP may have moved to a different controller
  $self->_query_wlcs_aps();
  my $wlc_ip2 = $ap->{wlc_ip};
  return undef if $wlc_ip eq $wlc_ip2;

  $snmp_session = $self->_get_snmp_session($wlc_ip2);
  return $snmp_session->get_request(-varbindlist => $vbl);
}


#-------------------------------------------------------------------------------
# Get MAC address from OID (last six octets)

sub _get_mac_from_oid
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

