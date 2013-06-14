#! /usr/bin/perl -w

package CiscoWireless::Rogue;

use strict;
use Net::SNMP;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw();
$VERSION = '0.01';

# .1.3.6.1.4.1.14179.2.1.7.1.1 MAC
# .1.3.6.1.4.1.14179.2.1.7.1.2 num_detecting_aps

sub new
{
  my ($class, $mac, $wlc) = @_;

  croak "invalid mac address format ($mac)" unless $mac =~ /^[a-f0-9]{12}$/i;

  my $self = {
    mac         => $mac,
    wlc         => $wlc,
    oidindex    => join(".", map {hex $_} unpack("(A2)6", $mac)),
    ssid        => undef,
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

    $r = $self->{wlc}->_snmp_get([$oid]);
    return undef unless defined $r;
    $self->{$name} = $$r{$oid} || undef;
    return $self->{$name};
  }

  if (defined $rw and !$rw) {
    carp "attempt to set read only value";
    return undef;
  }

  $r = $self->{wlc}->_snmp_write([$oid, $type, $new]);

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
    "totaldetectingaps"     => [ ".1.3.6.1.4.1.14179.2.1.7.1.2.",  0, INTEGER ],
    "firstreported"         => [ ".1.3.6.1.4.1.14179.2.1.7.1.3.",  0, OCTET_STRING ],
    "lastreported"          => [ ".1.3.6.1.4.1.14179.2.1.7.1.4.",  0, OCTET_STRING ],
    "containmentlevel"      => [ ".1.3.6.1.4.1.14179.2.1.7.1.5.",  1, INTEGER ],
    "type"                  => [ ".1.3.6.1.4.1.14179.2.1.7.1.6.",  0, INTEGER ],
    "onwirednetwork"        => [ ".1.3.6.1.4.1.14179.2.1.7.1.7.",  0, INTEGER ],
    "totalclients"          => [ ".1.3.6.1.4.1.14179.2.1.7.1.8.",  0, INTEGER ],
    "maxdetectedrssi"       => [ ".1.3.6.1.4.1.14179.2.1.7.1.10.", 0, INTEGER ],
    "ssid"                  => [ ".1.3.6.1.4.1.14179.2.1.7.1.11.", 0, OCTET_STRING ],
    "detectingapradiotype"  => [ ".1.3.6.1.4.1.14179.2.1.7.1.12.", 0, INTEGER ],
    "detectingapmacaddress" => [ ".1.3.6.1.4.1.14179.2.1.7.1.13.", 0, OCTET_STRING ],
    "maxrssiradiotype"      => [ ".1.3.6.1.4.1.14179.2.1.7.1.14.", 0, INTEGER ],
    "state"                 => [ ".1.3.6.1.4.1.14179.2.1.7.1.24.", 0, INTEGER ],
    "classtype"             => [ ".1.3.6.1.4.1.14179.2.1.7.1.25.", 0, INTEGER ],
    "channel"               => [ ".1.3.6.1.4.1.14179.2.1.7.1.26.", 0, INTEGER ],
    "detectingapname"       => [ ".1.3.6.1.4.1.14179.2.1.7.1.27.", 0, OCTET_STRING ],
  );

# INTEGER, INTEGER32, OCTET_STRING, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, COUNTER32, GAUGE,
# GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64


{
  foreach my $func (keys %_methods) {
    eval "sub $func { return \$_[0]->_generic_method(\"$func\", \$_[1], " .
          "\$_methods{$func});}";
  }
}


1;

