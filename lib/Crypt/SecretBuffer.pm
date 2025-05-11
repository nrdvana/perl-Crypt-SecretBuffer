package Crypt::SecretBuffer;
# VERSION
# ABSTRACT: Prevent accidentally copying a string of sensitive data

=head1 SYNOPSIS

  $buf= Crypt::SecretBuffer->new;
  print "Enter your password: ";
  $buf->read_tty(\*STDIN)    # read TTY with echo disabled
    or die "Aborted";
  say $buf;                  # prints "[REDACTED]"
  
  my $fh= $buf->get_pipe;    # create pipe which secret can be read from
  
  my @cmd= qw( openssl enc -e -aes-256-cbc -md sha512 -pbkdf2 -iter 239823 -pass fd:3 );
  IPC::Run::run(\@cmd,
    '0<', \$data,
    '1>', \$ciphertext,
    '3<', $fh                # Feed the password to an external command
  );                         # without it ever being copied into a Perl scalar
  
  $fh->clear;                # no copies of password remain in memory.

=head1 DESCRIPTION

This module helps you protect a secret value from getting copied around unintentionally or
lingering in memory of a long-running program.  It is very much like SecureString from .NET,
but with a better name.   (preventing accidental copies does not make something "secure", and
"string" sometimes implies text or immutability)

The goal of SecretBuffer is to avoid copying secrets into the pool of Perl scalars, which get
reallocated all the time as you perform operations on it or pass it by value into a function.
The SecretBuffer is a blessed reference, and the buffer itself is stored in XS in a way that
the Perl interpreter has no knowledge of.  Any time the buffer needs reallocated, a new buffer
is allocated, the secret is copied, and the old buffer is wiped clean.  It also protects
against timing attacks by copying all the allocated buffer space instead of just the length
that is occupied by the secret.

The API gives you a few methods to read and write data from the secret without exposing it to
the Perl interpreter:

=over 12

=item read_tty

Reads a line of input from a TTY with echo turned off

=item read_file

Reads directly from a file or handle with sysread()

=item write_file

Writes directly to a file or handle with syswrite()

=item get_pipe

Fills the write-end of a pipe with the secret, possibly forking a worker to feed the pipe
if the secret doesn't fit in the OS's pipe buffer.

=back

For interoperability with other Perl code, you can also toggle whether stringification of the
buffer reveals the secret or not.  For instance:

  say $buf;                            # stringifies as [REDACTED]
  {
    local $buf->{stringify_mask}= undef;
    some_xs_function($buf);            # stringifies as the secret
  }
  say $buf;                            # stringifies as [REDACTED]

This does run a bit of a risk of the secret leaking into freed memory, so try to use the methods
above if possible.

=cut

use strict;
use warnings;
use Carp;
use Scalar::Util ();
use overload '""' => \&stringify;

require XSLoader;
sub dl_load_flags {0x01}
XSLoader::load('Crypt::SecretBuffer', $Crypt::SecretBuffer::VERSION);

{
   package Crypt::SecretBuffer::Exports;
   use Exporter 'import';
   @Crypt::SecretBuffer::Exports::EXPORT_OK= qw( secret_buffer secret );
   sub secret_buffer {
      Crypt::SecretBuffer->new(@_)
   }
   *secret= *secret_buffer;
}

sub import {
   splice(@_, 0, 1, 'Crypt::SecretBuffer::Exports');
   goto \&Crypt::SecretBuffer::Exports::import;
}

sub new {
   my $self= bless {}, shift;
   if (@_ == 1) {
      $self->assign($_[0]);
   } else {
      %$self= @_;
   }
   $self;
}

1;
