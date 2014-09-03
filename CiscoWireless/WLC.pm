#! /usr/bin/perl -w

package CiscoWireless::WLC;

use Data::Dumper;
use CiscoWireless::Util;

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

    _cache           => undef,
    _cachelife       => \%CiscoWireless::WLC::_cachelife,
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

  $self->_init_cache();
}


sub update
{
  my ($self, $key, $value) = @_;

  $self->{$key} = $value;
  $self->cache_insert($key, $value);
  return $value;
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

    $self->cache_insert($name, $self->{$name});
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

# Set returned a failure. This could have been for a number of reasons, and it
# seems impossible to tell if it's the one we care about: that the AP is not
# joined to the controller. (This may happen because the AP could have moved
# since we queried the controllers.) So we try and read the value from the
# controller. If the read fails then the AP has likely moved, so rescan the APs
# and try the write elsewhere.

  my $oid = $$vbl[0];

  $r = $self->_snmp_get_ap($ap, [$oid]);

  if (defined $r) {

# The read succeeded, so the oid does seem to be there. Check the read-back
# value to see if it is the same as the written value, and return true if it
# is.
#
# This code may be wrong because some write-trigger or write-only values
# may fail here, so need to be careful... which we're not.

  my $wval = $$vbl[2];

#print Dumper $r;

#print "uh oh 1 '$wval'\n";
#print "-" . $$r{$oid} . "-\n";

    return $r if $$r{$oid} eq $wval;

#print "uh oh 2 '$wval'\n";
# Returned value does not match, so return undef to let the caller know that
# the write failed.

    return undef;
  }

# Couldn't read the OID, so likely the AP has moved. Rescan to try and find it
# and then redo the write.

  # AP may have moved to a different controller. This is expensive, but not a lot
  # we can do about it if we really think the AP has moved or gone away.
  $self->_query_aps();

# Return if the AP hadn't moved after all. Hopefully given the get above, this
# will almost never be the case.

  my $wlc_ip2 = $ap->{wlc}->{ip};
  return undef if $wlc_ip eq $wlc_ip2;

# Get the session for the new controller, then just do the set. There's not a
# lot else we can do if this fails.

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

