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
   @Crypt::SecretBuffer::Exports::EXPORT_OK= qw( secret_buffer secret NONBLOCK FULLCOUNT );
   sub secret_buffer {
      Crypt::SecretBuffer->new(@_)
   }
   *secret= *secret_buffer;
   *NONBLOCK= *Crypt::SecretBuffer::NONBLOCK;
   *FULLCOUNT= *Crypt::SecretBuffer::FULLCOUNT;
}

sub import {
   splice(@_, 0, 1, 'Crypt::SecretBuffer::Exports');
   goto \&Crypt::SecretBuffer::Exports::import;
}

sub new {
   my $self= bless {}, shift;
   $self->assign(shift) if @_ == 1;
   while (@_) {
      my ($attr, $val)= splice(@_, 0, 2);
      $self->$attr($val);
   }
   $self;
}

=attribute capacity

  say $buf->capacity;
  $buf->capacity($n_bytes)->...
  $buf->capacity($n_bytes, AT_LEAST)->...

This reads or writes the allocated length of the buffer, presumably because you know how much
space you need for an upcoming reead operation, but it can also free up space you know you no
longer need.  In the third example, a second parameter 'AT_LEAST' is passed to indicate that
the buffer does not need reallocated if it is already large enough.

Capacity beyond 'length' is not initialized.

=attribute length

  say $buf->length;
  $buf->length(0);
  $buf->length(32);   # fills with 32 secure random bytes

This gets or sets the length of the string in the buffer.  If you set it to a smaller value,
the string is truncated.  If you set it to a larger value, the L</capacity> is raised as needed
and the bytes are initialized with L</append_random>.

=method append_random

  $byte_count= $buf->append_random($n_bytes);
  $byte_count= $buf->append_random($n_bytes, NONBLOCK);
  $byte_count= $buf->append_random($n_bytes, FULLCOUNT);

Append N cryptographic-quality random bytes.  This uses either the c library 'getrandom' call
with C<GRND_RANDOM>, or if that isn't available, it reads from /dev/random.  The NONBLOCK flag
can be used to avoid blocking waiting on entropy, and the 'FULLCOUNT' flag can be used to loop
if the call returns fewer than the requested bytes.

=method append_tty_line

  $byte_count= $buf->append_tty_line(STDIN);
  $byte_count= $buf->append_tty_line(STDIN, $max_chars);

This turns off TTY echo, reads characters until newline or EOF storing them in the buffer
(excluding the trailing \r or \n) and returns the number of characters added.  This appends to
the buffer.

B<Win32 Note:> On Windows, this always reads from the Console, and the first parameter is
ignored.

=method append_sysread

  $byte_count= $buf->append_sysread($fh, $count);
  $byte_count= $buf->append_sysread($fh, $count, NONBLOCK);
  $byte_count= $buf->append_sysread($fh, $count, FULLCOUNT);

This performs a low-level read from the file handle and appends the bytes to the buffer.
It must be a real file handle with an underlying file descriptor number (C<fileno>).
Note that on most unixes, 'NONBLOCK' does not apply to disk files, only to pipes, sockets, etc.
'FULLCOUNT' is used to loop on a short blocking read until the desired C<$count>.

=method syswrite

  $byte_count= $buf->syswrite($fh); # one syswrite attempt of whole buffer
  $byte_count= $buf->syswrite($fh, $offset, $count); # subset of buffer
  $byte_count= $buf->syswrite($fh, $offset, $count, NONBLOCK); # one non-blocking write
  $byte_count= $buf->syswrite($fh, $offset, $count, NONBLOCK); # blocking write in a loop
  $byte_count= $buf->syswrite($fh, $offset, $count, NONBLOCK|FULLCOUNT); # background thread

This performs a low-level write from the buffer into a file handle.  It must be a real file
handle with an underlying file descriptor (C<fileno>).

The default behavior is to perform one blocking syswrite of the full buffer, and let you know
how many bytes the OS wrote during that call.  If you specify the flag C<FULLCOUNT>, it will
continue performing blocking writes until the full count is written, or an error occurs.  If
you specify the flag C<NONBLOCK>, it makes one nonblocking attempt to write the buffer. If you
specify both flags, it makes one nonblocking attempt and then if the complete data was not
written it creates a background thread/process to continue blocking writes into that file handle
until an error occurs or the full count is written.

=method as_pipe

  $fh= $buf->as_pipe

This creates a pipe, then calls C<< $self->syswrite(..., NONBLOCK|FULLCOUNT) >> into the
write-end of the pipe (possibly spawning a background thread to keep pumping the data, but
very unlikely to need to if your data is less than 4K) and then returns the read-end of the
pipe.  You can then pass this pipe to other processes.

=cut

sub as_pipe {
   my $self= shift;
   pipe(my ($r, $w)) or die "pipe: $!";   
   $self->syswrite($w, 0, $self->length, NONBLOCK()|FULLCOUNT());
   close($w); # XS dups the file handle if it is writing async from a thread
   return $r;
}

1;
