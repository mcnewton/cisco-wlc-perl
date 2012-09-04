#! /usr/bin/perl -w

package CiscoWireless::WLC;

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
  my ($class, $ip, $data) = @_;

  carp "Unknown WLC IP" unless defined $ip;

  my $self = {
    ip               => $ip,
    name             => undef,
    snmp_community   => "public",
    snmp_version     => 1,
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


1;

