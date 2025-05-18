package Crypt::SecretBuffer;
# VERSION
# ABSTRACT: Prevent accidentally leaking a string of sensitive data

=head1 SYNOPSIS

  $buf= Crypt::SecretBuffer->new;
  print "Enter your password: ";
  $buf->append_tty_line(\*STDIN)  # read TTY with echo disabled
    or die "Aborted";
  say $buf;                       # prints "[REDACTED]"
  
  my @cmd= qw( openssl enc -e -aes-256-cbc -md sha512 -pbkdf2 -iter 239823 -pass fd:3 );
  IPC::Run::run(\@cmd,
    '0<', \$data,
    '1>', \$ciphertext,
    '3<', $buf->as_pipe   # Feed the password to an external command
  );                      # without it ever being copied into a Perl scalar
  
  undef $buf;             # no copies of password remain in memory.

=head1 DESCRIPTION

This module helps you protect a secret value from getting copied around unintentionally or
lingering in memory of a long-running program.  It is very much like SecureString from .NET,
but with a better name.   (preventing accidental copies does not make something "secure", and
"string" sometimes implies text or immutability)  While a scripting language in general is a
poor choice for managing sensitive data in a long-lived app instance, this at least gives you
some measure of control over how long secrets remain in memory, and how easy it is to
accidentally expose them to other code, such as log messages.  When you free a SecretBuffer,
you can be fairly sure that the secret does not remain anywhere in your process address space.
(with the exception of when it's being fed into a pipe in the background; see L</as_pipe>)

This module exists because in standard OpenSSL examples they always wipe the buffers before
exiting a function, but with Perl's exception behavior (C<croak>) there was no way to ensure
that the buffers got wiped before exiting a function.  By putting all the secrets into
Crypt::SecretBuffer objects, it at least ensures that the buffers are always wiped according to
standard practices for C code.  Passing around SecretBuffer objects perl-side is just an added
benefit.

The SecretBuffer is a blessed reference, and the buffer itself is stored in XS in a way that
the Perl interpreter has no knowledge of.  Any time the buffer needs reallocated, a new buffer
is allocated, the secret is copied, and the old buffer is wiped clean before freeing it.
It also guards against timing attacks by copying all the allocated buffer space instead of
just the length that is occupied by the secret.

The API also provides you with a few ways to read or write the secret, since any read/write code
implemented directly in Perl would potentially expose your secret to having copies made in
temporary buffers.  But, for interoperability with other Perl code, you can also toggle whether
stringification of the buffer reveals the secret or not.  For instance:

  say $buf;                            # stringifies as [REDACTED]
  {
    local $buf->{stringify_mask}= undef;
    some_xs_function($buf);            # stringifies as the secret
  }
  say $buf;                            # stringifies as [REDACTED]

There is no guarantee that the XS function in that example wouldn't make a copy of your secret,
but this at least provides the secret buffer directly to the XS code that calls C<SvPV> without
making a copy.  If an XS module is aware of Crypt::SecretBuffer, it can use a more official C
API that doesn't rely on perl stringification behavior.

=cut

use strict;
use warnings;
use Carp;
use Scalar::Util ();
use parent qw( DynaLoader );
use overload '""' => \&stringify;

sub dl_load_flags {0x01} # Share extern symbols with other modules
bootstrap Crypt::SecretBuffer;

{
   package Crypt::SecretBuffer::Exports;
   use Exporter 'import';
   @Crypt::SecretBuffer::Exports::EXPORT_OK= qw( secret_buffer secret NONBLOCK FULLCOUNT );
   sub secret_buffer {
      Crypt::SecretBuffer->new(@_)
   }
   *secret= *secret_buffer;
   *NONBLOCK=  *Crypt::SecretBuffer::NONBLOCK;
   *FULLCOUNT= *Crypt::SecretBuffer::FULLCOUNT;
   *AT_LEAST=  *Crypt::SecretBuffer::AT_LEAST;
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

=method clear

Erases the buffer.  Equivalent to C<< $buf->length(0) >>

=method substr

  $buf->substr(1);            # New SecretBuffer minus the first character
  $buf->substr(0,5);          # First 5 characters of buffer
  $buf->substr(0,5,$buf2);    # replace first 5 characters with content of $buf2

This is exactly like Perl's C<substr> function, but it returns C<Crypt::SecretBuffer> objects
and they are not an lvalue that alters the original.

=method append_random

  $byte_count= $buf->append_random($n_bytes);
  $byte_count= $buf->append_random($n_bytes, NONBLOCK);
  $byte_count= $buf->append_random($n_bytes, FULLCOUNT);

Append N cryptographic-quality random bytes.  This uses either the c library 'getrandom' call
with C<GRND_RANDOM>, or if that isn't available, it reads from /dev/random.  The NONBLOCK flag
can be used to avoid blocking waiting on entropy, and the 'FULLCOUNT' flag can be used to loop
if the call returns fewer than the requested bytes.

B<Win32 Note:> On Windows, the flags are irrelevant because it always returns the requested
number of bytes and never blocks.

=method append_textline

  $byte_count= $buf->append_textline(STDIN);
  $byte_count= $buf->append_textline(STDIN, $max_chars);
  $byte_count= $buf->append_textline(STDIN, $max_chars, NONBLOCK);

This turns off TTY echo (if the handle is a Unix TTY or Windows Console), reads and appends
characters until newline or EOF (and does not store the \r or \n characters) and returns the
number of characters added.  When possible, this reads directly from the OS to avoid buffering
the secret in libc or Perl, but reads from the buffer if you already have input data in one of
those buffers, or if the file handle is a virtual Perl handle not backed by the OS.

This function supports the NONBLOCK flag, to return immediately if there isn't a complete line
of text available on the file handle.

=method append_sysread

  $byte_count= $buf->append_sysread($fh, $count);
  $byte_count= $buf->append_sysread($fh, $count, NONBLOCK);
  $byte_count= $buf->append_sysread($fh, $count, FULLCOUNT);

This performs a low-level read from the file handle and appends the bytes to the buffer.
It must be a real file handle with an underlying file descriptor number (C<fileno>).
Note that on most unixes, C<NONBLOCK> does not apply to disk files, only to pipes, sockets, etc.
If you specify the C<FULLCOUNT> flag and the sysread returns less than C<$count>, it will loop
until the full count is reached or until EOF.  FULLCOUNT cannot be combined with NONBLOCK.

When possible, this reads directly from the OS to avoid buffering the secret in libc or Perl,
but reads from the buffer if you already have input data in one of those buffers, or if the
file handle is a virtual Perl handle not backed by the OS.

=method syswrite

  $byte_count= $buf->syswrite($fh); # one syswrite attempt of whole buffer
  $byte_count= $buf->syswrite($fh, $ofs, $n); # subset of buffer
  $byte_count= $buf->syswrite($fh, $ofs, $n, NONBLOCK); # one non-blocking write
  $byte_count= $buf->syswrite($fh, $ofs, $n, FULLCOUNT); # blocking write in a loop
  $byte_count= $buf->syswrite($fh, $ofs, $n, NONBLOCK|FULLCOUNT); # maybe background thread

This performs a low-level write from the buffer into a file handle.  It must be a real file
handle with an underlying file descriptor (C<fileno>).

The default behavior is to perform one blocking syswrite of the full buffer, and let you know
how many bytes the OS wrote during that call.  It croaks on errors.
If you specify the flag C<FULLCOUNT>, it will continue performing blocking writes until the full
count is written, or an error occurs.
If you specify the flag C<NONBLOCK>, it makes one nonblocking attempt to write the buffer.
If you specify both flags, it makes one nonblocking attempt and then if the complete data was
not written it creates a background thread/process to continue blocking writes into that file
handle until an error occurs or the full count is written.  This thread gets a copy of the
secret and the secret remains in memory until the thread exits, but you may free C<$buf>
whenever you want.

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
