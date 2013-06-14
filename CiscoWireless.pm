#! /usr/bin/perl -w

package CiscoWireless;

use Data::Dumper;
use Net::SNMP;

use CiscoWireless::AP;
use CiscoWireless::WLC;
use CiscoWireless::Client;
use CiscoWireless::Rogue;

use CiscoWireless::Util;

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
    client_list => {},
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
# Client functions

#-------------------------------------------------------------------------------
# get_clients

sub get_clients
{
  my ($self) = @_;
  my @allclients = ();

  foreach my $wlc (values %{$self->{wlc_list}}) {
    push @allclients, $wlc->get_clients();
  }

  return \@allclients;
}


sub get_client_by_mac
{
  my ($self, $mac) = @_;

  $mac = lc $mac;

  foreach my $wlc (values %{$self->{wlc_list}}) {
    foreach my $client ($wlc->get_clients()) {
      if (lc $client->{mac} eq $mac) {
        return $client;
      }
    }
  }

  return undef;
}


#-------------------------------------------------------------------------------
# query_clients

sub _query_wlcs_clients
{
  my ($self) = @_;

  foreach my $wlc (keys %{$self->{wlc_list}}) {
    $self->{wlc_list}{$wlc}->_query_clients();
  }
}


################################################################################
# Rogue functions

#-------------------------------------------------------------------------------
# get_rogues

sub get_rogues
{
  my ($self) = @_;
  my @allrogues = ();

  foreach my $wlc (values %{$self->{wlc_list}}) {
    push @allrogues, $wlc->get_rogues();
  }

  return \@allrogues;
}


1;

