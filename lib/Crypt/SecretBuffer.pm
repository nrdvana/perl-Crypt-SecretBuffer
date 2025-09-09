package Crypt::SecretBuffer;
# VERSION
# ABSTRACT: Prevent accidentally leaking a string of sensitive data

=head1 SYNOPSIS

  use Crypt::SecretBuffer 'secret';
  $buf= secret;
  print "Enter your password: ";
  $buf->append_console_line(STDIN)   # read TTY with echo disabled
    or die "Aborted";
  say $buf;                          # prints "[REDACTED]"
  
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
making a copy.  If an XS module is aware of Crypt::SecretBuffer, it can use a more official
L</C API> that doesn't rely on perl stringification behavior.

=cut

use strict;
use warnings;
use Carp;
use Scalar::Util ();
use parent qw( DynaLoader );
use overload '""' => \&stringify;

sub dl_load_flags {0x01} # Share extern symbols with other modules
bootstrap Crypt::SecretBuffer;

=head1 EXPORTS

=over 15

=item AT_LEAST

Parameter for setting the L</capacity>.

=item NONBLOCK

Parameter for L</append_random>.

=item secret_buffer

Shorthand function for calling L</new>.

=item secret

Shorthand function for calling L</new>.

=back

=cut

{
   package Crypt::SecretBuffer::Exports;

   use Exporter 'import';
   @Crypt::SecretBuffer::Exports::EXPORT_OK= qw( secret_buffer secret NONBLOCK AT_LEAST );
   sub secret_buffer {
      Crypt::SecretBuffer->new(@_)
   }
   *secret= *secret_buffer;
   *NONBLOCK=  *Crypt::SecretBuffer::NONBLOCK;
   *AT_LEAST=  *Crypt::SecretBuffer::AT_LEAST;
}

sub import {
   splice(@_, 0, 1, 'Crypt::SecretBuffer::Exports');
   goto \&Crypt::SecretBuffer::Exports::import;
}

sub Inline {
   require Crypt::SecretBuffer::Install::Files;
   goto \&Crypt::SecretBuffer::Install::Files::Inline;
}

=constructor new

  $buf= Crypt::SecretBuffer->new($assign_value);
  $buf= Crypt::SecretBuffer->new(%attrs);

If you pass one value to the constructor, it L</assign>s that to the buffer.  If you pass a list
of key/value pairs, it assigns those attributes, such as C<< ->new(capacity => 20) >>.
Technically it just calls each key as a method with the value as a single argument, so you could
also do things like C<< ->new(append_random => 16) >>.

=constructor secret_buffer / secret

The functions C<secret_buffer> and C<secret> can be exported from this module as a shorthand
for C<< Crypt::SecretBuffer->new(...) >>.

=cut

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
  $buf->capacity($n_bytes, 'AT_LEAST')->...

This reads or writes the allocated length of the buffer, presumably because you know how much
space you need for an upcoming read operation, but it can also free up space you know you no
longer need.  In the third example, a second parameter 'AT_LEAST' is passed to indicate that
the buffer does not need reallocated if it is already large enough.

=attribute length

  say $buf->length;
  $buf->length(0);    # wipes buffer
  $buf->length(32);   # fills with zeroes

This gets or sets the length of the string in the buffer.  If you set it to a smaller value,
the string is truncated.  If you set it to a larger value, the L</capacity> is raised as needed
and the bytes are initialized with zeroes.

=method clear

Erases the buffer.  Equivalent to C<< $buf->length(0) >>.  Returns C<$self> for chaining.

=method assign

  $buf->assign($other_buf); # good
  $buf->assign($string);    # works, but $string isn't secret...

Assign a value to the buffer.  Returns C<$self>, for chaining.

=attribute stringify_mask

  $buf->stringify_mask;           # "[REDACTED]"
  $buf->stringify_mask("*****");  # now stringifies as "*****"
  $buf->stringify_mask(undef);    # exposes secret

Get or set the stringification mask.  Setting it to C<undef> causes L</stringify> to expose the
secret.  In order to restore the default C<"[REDACTED]"> you have to delete the attribute:
C<< delete $buf->{stringify_mask} >>.  This attribute is mainly intended to allow cusomizing the
mask during the constructor.  The preferred way to expose the secret is with C<local> on the
hash key directly.

=cut

sub stringify_mask {
   my $self= shift;
   if (@_) {
      $self->{stringify_mask}= shift;
      return $self;
   }
   $self->{stringify_mask}
}

=method stringify

  $buf->stringify;               # returns "[REDACTED]"
  $buf->{stringify_mask}= "***";
  $buf->stringify;               # returns "***"
  $buf->{stringify_mask}= undef;
  $buf->stringify;               # returns secret value
  
  do { local $buf->{stringify_mask}= undef; "$buf" } # expose secret once

SecretBuffer tries not to expose the secret, so the default behavior of this function is to
return the string C<< "[REDACTED]" >> or whatever custom string you store in C<stringify_mask>.
If you set C<stringify_mask> to C<undef>, it exposes the secret.  You can use C<local> to limit
the scope of this exposure.

=method index

  $ofs= $buf->index($str);
  $ofs= $buf->index($str, $from_offset);

Like Perl's C<index> function, returns -1 if not found, or else the offset of the start of the
string you asked it to look for.  You can specify an optional starting offset to search from.
Negative starting offsets search from that many characters before the end of the buffer.

=method substr

  $buf->substr(1);            # New SecretBuffer minus the first character
  $buf->substr(0,5);          # First 5 characters of buffer
  $buf->substr(0,5,$buf2);    # replace first 5 characters with content of $buf2

This is exactly like Perl's C<substr> function, but it returns C<Crypt::SecretBuffer> objects,
and they are not an lvalue that alters the original.

=method append_random

  $byte_count= $buf->append_random($n_bytes);
  $byte_count= $buf->append_random($n_bytes, NONBLOCK);
  $byte_count= $buf->append_random($n_bytes, 'NONBLOCK');

Append N cryptographic-quality random bytes.  On POSIX systems, this uses either the C library
C<getrandom> call with C<GRND_RANDOM>, or if that isn't available, it reads from C</dev/random>.
The C<NONBLOCK> flag can be used to avoid blocking on insufficient entropy.  On Windows, this
uses C<CryptGenRandom> and the flag has no effect because it always returns the requested number
of bytes and never blocks.

=method append_console_line

  $bool= $buf->append_console_line(STDIN);

This turns off TTY echo (if the handle is a Unix TTY or Windows Console) and reads and appends
characters until newline or EOF (and does not store the \r or \n characters).
It returns true if the read "completed" with a line terminator, or false on EOF, or
C<undef> on any OS error.  Characters may be added to the buffer even when it returns false.
There may also be no characters added when it returns true, if the user just hits <enter>.

When possible, this reads directly from the OS to avoid buffering the secret in libc or Perl,
but reads from the buffer if you already have input data in one of those buffers, or if the
file handle is a virtual Perl handle not backed by the OS.

=method append_sysread

  $byte_count= $buf->append_sysread($fh, $count);

This performs a low-level read from the file handle and appends the bytes to the buffer.
It must be a real file handle with an underlying file descriptor number (C<fileno>).
Like C<sysread>, on error it returns C<undef> and on success it returns the count added.
This ignores Perl I/O layers.

=method append_read

  $byte_count= $buf->append_read($fh, $count);

This is a relaxed version of C<append_sysread> that when possible, reads directly from the OS
to avoid buffering the secret in libc or Perl, but reads from the Perl buffer if you already
have input data in one of those buffers, or if the file handle is a virtual Perl handle not
backed by the OS.

=method syswrite

  $byte_count= $buf->syswrite($fh); # one syswrite attempt of whole buffer
  $byte_count= $buf->syswrite($fh, $count); # prefix of buffer
  $byte_count= $buf->syswrite($fh, $count, $offset); # substr of buffer

This performs a low-level write from the buffer into a file handle.  It must be a real file
handle with an underlying file descriptor (C<fileno>).  If the handle has pending bytes in its
IO buffer, those are flushed first.  Like C<syswrite>, this returns C<undef> on an OS error,
and otherwise returns the number of bytes written.  It only makes one write attempt, which may
be shorter than the requested C<$count>. This ignores Perl I/O layers.

=method write_async

  $async_result= $buf->write_async($fh);                  # whole buffer
  $async_result= $buf->write_async($fh, $count);          # prefix of buffer
  $async_result= $buf->write_async($fh, $count, $offset); # substr of buffer
  ($wrote, $errno)= $async_result->wait;
  ($wrote, $errno)= $async_result->wait($seconds);

Write data into a file handle, using a background thread if needed.  Most likely, you will be
writing into a pipe, and your secret will be smaller than the OS pipe buffer, so this will
complete immediately without spawning a thread.  It also immediately returns if there was a
fatal error attempting to write the handle.  But if you have a large secret, or are writing into
a type of handle that can't buffer it, this function will duplicate your file handle and copy
the secret and pass them to a background thread to do the writing.

You can check the status or wait for its completion using the
L<$async_result|Crypt::SecretBuffer::AsyncResult> object.

=method as_pipe

  $fh= $buf->as_pipe

This creates a pipe, then calls C<< $self->write_async($pipe) >> into the write-end of the pipe.
You can then pass this pipe to other processes without needing to "pump" the pipe like you would
with L<IPC::Run>.

The C<$async_result> from L</write_async> is ignored, allowing the background thread to complete
(or error on a closed pipe) on its own time.

=cut

sub as_pipe {
   my $self= shift;
   pipe(my ($r, $w)) or die "pipe: $!";   
   $self->write_async($w);
   close($w); # XS dups the file handle if it is writing async from a thread
   return $r;
}

=head1 C API

This module is intended for C code as much as it is for Perl code.  To write an XS module that
uses SecretBuffer, your XS module should use L<ExtUtils::Depends> to add the headers and linkage
needed for the C API:

  my $dep= ExtUtils::Depends->new('Your::Module', 'Crypt::SecretBuffer');
  ...
  WriteMakefile(
    'NAME' => 'Mymodule',
    $dep->get_makefile_vars()
  );

You can also just use it with L<Inline::C> if you want to skip the hassle of an XS module:

  package TestSecretBufferWithInline;
  use strict;
  use warnings;
  use Inline with => 'Crypt::SecretBuffer';
  use Inline C => <<END_C;
  
  #include <SecretBuffer.h>
  
  int test(secret_buffer *buf) {
    return buf->len;
  }
  
  END_C
  
  print test(Crypt::SecretBuffer->new(length => 10))."\n";
  1;

The complete API documentation is found in
L<SecretBuffer.h|https://metacpan.org/dist/Crypt-SecretBuffer/source/SecretBuffer.h>

=head1 Reporting Security Vulnerabilities

Security issues should not be reported on the bugtracker website.  Please see
L<SECURITY.md|https://metacpan.org/dist/Crypt-SecretBuffer/source/SECURITY.md> for
instructions how to report security vulnerabilities.

=cut

1;
