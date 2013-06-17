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
  my ($class, $type, $data) = @_;

  croak "Bad CiscoWireless::Cache type '$type'" unless $type eq "dir";

  my $self = {
    type => $type,
  };

  if ($type eq "dir") {
    $$self{location} = delete $$data{location} if $$data{location};
    croak "dir location not set" unless defined($$self{location});

    if (! -d $$self{location}) {
      croak "directory '$$self{location}' does not exist";
    }
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
  return undef if (! -r $keypath . "/subkeys");

  open $fh, "<", $keypath . "/subkeys" || return undef;

  while (my $line = <$fh>) {
    chomp $line;
    if (-r $keypath . "/$line") {
      push @subkeys, $line;
    } else {
      $invalid = 1;
    }
  }

  close $fh;

  if ($invalid) {
    carp "invalid subkeys file for $key - fixing";
    $self->write_subkeys($key, \@subkeys);
  }

  return \@subkeys;
}


sub write_subkeys
{
  my ($self, $key, $subkeys) = @_;
  my $fh;

  my $keypath = $self->get_keypath($key);
  return undef if (! -d $keypath);

  open $fh, ">", $keypath . "/subkeys" || carp "unable to open $keypath/subkeys";
  foreach my $sk (@$subkeys) {
    print $fh "$sk\n";
  }
  close $fh;
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
  my $size = read($fh, $buffer, 4096);

  return undef if ($size == 0);

  return $buffer;
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


1;

