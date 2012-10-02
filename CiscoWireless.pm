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
  my ($self, $wlc) = @_;

  unless (defined $wlc) {
    carp "no WLC given";
    return undef;
  }

  my $wlc_ip = $wlc->ip();

  if (defined $$self{wlc_list}{$wlc_ip}) {
    carp "WLC $wlc_ip already added";
    return undef;
  }

  $self->{wlc_list}{$wlc_ip} = $wlc;
  $wlc->update("_ciscowireless", $self);

  1;
}

##-------------------------------------------------------------------------------
## _get_snmp_session
#
#sub _get_snmp_session
#{
#  my ($self, $wlc_ip) = @_;
#
#  return undef unless defined $self->{wlc_list}{$wlc_ip};
#
#  my $wlc = $self->{wlc_list}{$wlc_ip};
#
#  return $$wlc{snmp_session} if defined $$wlc{snmp_session};
#
#  my ($session, $error) = Net::SNMP->session(
#                            -version => $$wlc{snmp_version},
#                            -hostname => $wlc_ip,
#                            -community => $$wlc{snmp_community});
#
#  if (!defined $session) {
#    carp "error getting snmp session to $wlc_ip ($error)";
#    return undef;
#  }
#
#  $$wlc{snmp_session} = $session;
#
#  return $session;
#}


################################################################################
# AP functions

#-------------------------------------------------------------------------------
# get_aps

sub get_aps
{
  my ($self) = @_;
  my @allaps = ();

  foreach my $wlc (values %{$self->{wlc_list}}) {
    push @allaps, $wlc->get_aps();
  }

  return \@allaps;
}


sub get_ap_by_name
{
  my ($self, $name) = @_;

  $name = lc $name;

  foreach my $wlc (values %{$self->{wlc_list}}) {
    foreach my $ap ($wlc->get_aps()) {
      if (defined $ap->{name} and (lc $ap->{name} eq $name)) {
        return $ap;
      }
    }
  }

  return undef;
}


sub get_ap_by_mac
{
  my ($self, $mac) = @_;

  $mac = lc $mac;

  foreach my $wlc (values %{$self->{wlc_list}}) {
    foreach my $ap ($wlc->get_aps()) {
      if (lc $ap->{mac} eq $mac) {
        return $ap;
      }
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

  foreach my $wlc (keys %{$self->{wlc_list}}) {
    $self->{wlc_list}{$wlc}->_query_aps();
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

#sub _get_generic_snmp_table
#{
#  my ($self, $session, $tablebase, $callback) = @_;
#  my $count = 0;
#  my $oid;
#
#  my @args = (-varbindlist => [$tablebase]);
#
#  while (defined($session->get_next_request(@args))) {
#    $oid = ($session->var_bind_names())[0];
#
#    last unless Net::SNMP::oid_base_match($tablebase, $oid);
#
#    my $value = $session->var_bind_list()->{$oid};
#    &$callback($oid, $value);
#    $count++;
#
#    @args = (-varbindlist => [$oid]);
#  }
#
#  return $count;
#}


#-------------------------------------------------------------------------------
# Generic SNMP write to an AP

#sub _snmp_write_ap
#{
#  my ($self, $ap, $vbl) = @_;
#
#  my $wlc_ip = $ap->{wlc_ip};
#  my $snmp_session = $self->_get_snmp_session($wlc_ip);
#
#  my $r = $snmp_session->set_request(-varbindlist => $vbl);
#  return $r if defined $r;
#
#  # AP may have moved to a different controller
#  $self->_query_wlcs_aps();
#  my $wlc_ip2 = $ap->{wlc_ip};
#  return undef if $wlc_ip eq $wlc_ip2;
#
#  $snmp_session = $self->_get_snmp_session($wlc_ip2);
#  return $snmp_session->set_request(-varbindlist => $vbl);
#}

#-------------------------------------------------------------------------------
# Generic SNMP write

#sub _snmp_get_ap
#{
#  my ($self, $ap, $vbl) = @_;
#
#  my $wlc_ip = $ap->{wlc_ip};
#  my $snmp_session = $self->_get_snmp_session($wlc_ip);
#
#  my $r = $snmp_session->get_request(-varbindlist => $vbl);
#  return $r if defined $r;
#
#  # AP may have moved to a different controller
#  $self->_query_wlcs_aps();
#  my $wlc_ip2 = $ap->{wlc_ip};
#  return undef if $wlc_ip eq $wlc_ip2;
#
#  $snmp_session = $self->_get_snmp_session($wlc_ip2);
#  return $snmp_session->get_request(-varbindlist => $vbl);
#}


##-------------------------------------------------------------------------------
## Get MAC address from OID (last six octets)
#
#sub _get_mac_from_oid
#{
#  my ($oid, $base) = @_;
#  my $octets;
#
#  if (defined $base) {
#    unless ($oid =~ s/^$base.(\d+(?:\.\d+){5})$//) {
#      carp "cannot extract mac from oid ($oid) with base ($base)";
#      return undef;
#    }
#    $octets = $1;
#  } else {
#    unless ($oid =~ /(\d+(?:\.\d+){5})$/) {
#      carp "cannot extract mac from oid ($oid)";
#      return undef;
#    }
#    $octets = $1;
#  }
#
#  return lc join("", unpack("(H2)6", pack("C6", split(/\./, $octets))));
#}


1;

