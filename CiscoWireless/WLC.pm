#! /usr/bin/perl -w

package CiscoWireless::WLC;

use Data::Dumper;
use CiscoWireless::Util;

# use CiscoWireless::Cache;


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
    _cache           => undef,
    _cachelife       => \%CiscoWireless::WLC::_cachelife,
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

sub init_cache
{
  my ($self, $cache) = @_;

  $self->{_cache} = $cache;

  $self->{_cachekey} = $cache->get_key_name("wlc", $self->{ip});

  my $subkeys = $cache->get_all_subkeys($self->{_cachekey});

print "a--\n";
print Dumper $subkeys;
print "b--\n";

  foreach my $sk (@$subkeys) {
    if (exists $self->{$sk}) {
      my $cv = $cache->get_subkey($self->{_cachekey}, $sk);
      $self->{$sk} = $cv if defined $cv;
    }
  }
}


sub update
{
  my ($self, $key, $value) = @_;

  $self->{$key} = $value;

  $self->cache_insert($key, $value);
}


sub cache_insert
{
  my ($self, $subkey, $value) = @_;

  return unless defined $self->{_cache};
  return unless defined $self->{_cachelife};
  return unless defined $self->{_cachelife}->{$subkey};

  print "key $subkey life " . $self->{_cachelife}->{$subkey} . "\n";

  $self->{_cache}->set_subkey($self->{_cachekey}, $subkey, $value, $self->{_cachelife}->{$subkey});
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


# 1 week = 604800
# 2 days = 172800
# 1 day = 86400
# 

our %_cachelife = (
    "name"             => 604800,
    "model"            => 604800,
    "serial"           => 604800,
    "burnedinmac"      => 604800,
    "manufacturer"     => 604800,
    "productname"      => 604800,
    "version"          => 604800,
    "maxaps"           => 86400,
  );


my %_methods = (
    "name"             => [ ".1.3.6.1.2.1.1.5.0",             0, OCTET_STRING],
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

#    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \"" .
#          $_methods{$func}[0] . "\", \$_[1], " . $_methods{$func}[1] . ", " .
#          $_methods{$func}[2] . ");}"

    eval "sub $func {
            return \$_[0]->_generic_method(
                               \"$func\", 
                               \"" .  $_methods{$func}[0] . "\",
                               \$_[1],
                               " . $_methods{$func}[1] . ",
                               " . $_methods{$func}[2] . "
                           );
          }";
  }
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



1;

