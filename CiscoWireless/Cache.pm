#! /usr/bin/perl -w

package CiscoWireless::Cache;

use Data::Dumper;

use strict;
use vars qw($VERSION @ISA @EXPORT);
use Carp;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw();
$VERSION = '0.01';


sub new
{
  my ($class, $data) = @_;

  my $self = {
    memcache => {},
  };

  $$self{location} = delete $$data{location} if $$data{location};
  croak "dir location not set" unless defined($$self{location});

  if (! -d $$self{location}) {
    croak "directory '$$self{location}' does not exist";
  }

  bless $self, $class;

  return $self;
}


################################################################################
# Cache functions

#-------------------------------------------------------------------------------
# Get

sub get_all_subkeys
{
  my ($self, $key) = @_;
  my @subkeys = ();
  my $fh;
  my $invalid = 0;

  my $keypath = $self->get_keypath($key);

  return undef if (! -d $keypath);

  opendir $fh, $keypath || return undef;
  @subkeys = grep { ! /^\./ && -f "$keypath/$_" } readdir $fh;
  closedir $fh;

  return \@subkeys;
}


sub get_subkey
{
  my ($self, $key, $subkey) = @_;
  my $fh;

  my $keypath = $self->get_keypath($key);
  return undef if (! -d $keypath);
  return undef if (! -r $keypath . "/" . $subkey);

  open $fh, "<", $keypath . "/" . $subkey || carp "unable to open $keypath/$subkey";
  binmode($fh);

# const...

  my $buffer;

  # check expiry time
  my $size = read($fh, $buffer, 20);
  return undef if ($size != 20);
  $buffer =~ s/ +$//;
  if ($buffer < time()) {
    unlink("$keypath/$subkey"); # remove cache file??
    return undef;
  }

  # get length
  $size = read($fh, $buffer, 20);
  return undef if ($size != 20);
  $buffer =~ s/ +$//;
  my $length = $buffer;

  # get data, check length
  $size = read($fh, $buffer, 4096);
  return undef if ($size != $length);

  return $buffer;
}


sub set_subkey
{
  my ($self, $key, $subkey, $value, $expiry) = @_;
  my $fh;

  my $keypath = $self->get_keypath($key);

  # trying to flush?
  if (!defined($value)) {
    if (-e "$keypath/$subkey") {
      unlink("$keypath/$subkey");
      return;
    }
  }

  if (! -d $keypath) {
    mkdir $keypath || return undef;
  }

  my $expirytime = time() + $expiry;

  open $fh, ">", $keypath . "/" . $subkey || carp "unable to write $keypath/$subkey";
  binmode $fh;

  # write expiry time
  my $buffer = $expirytime . " " x (20 - length($expirytime));
  print $fh $buffer;

  # write length
  $buffer = length($value) . " " x (20 - length(length($value)));
  print $fh $buffer;

  # write value
  print $fh $value;

  close $fh;
}


sub get_keypath
{
  my ($self, $key) = @_;

  croak "location not set" unless defined $self->{location};

  return $self->{location} . "/" . $key;
}


sub get_key_name
{
  my ($self, $type, $scalar) = @_;

  return $type . join("",unpack("(H2)*", $scalar));
}



################################################################################
# Cache utility methods for other classes

package CiscoWireless::Cache::Util;


#-------------------------------------------------------------------------------
# _init_cache - pull in cache values

sub _init_cache
{
  my ($self) = @_;

  my $subkeys = $self->{_cache}->get_all_subkeys($self->{_cachekey});

  foreach my $subkey (@$subkeys) {
    if (exists $self->{_cachelife}->{$subkey}) {
      my $cacheval = $self->{_cache}->get_subkey($self->{_cachekey}, $subkey);
      $self->{$subkey} = $cacheval if defined $cacheval;
    }
  }
}


#-------------------------------------------------------------------------------
# cache_insert - write to cache

sub cache_insert
{
  my ($self, $subkey, $value) = @_;

  return unless defined $self->{_cache};
  return unless defined $self->{_cachelife};
  return unless defined $self->{_cachelife}->{$subkey};

#  print "key $subkey life " . $self->{_cachelife}->{$subkey} . "\n";

  $self->{_cache}->set_subkey($self->{_cachekey}, $subkey, $value, $self->{_cachelife}->{$subkey});
}


1;

