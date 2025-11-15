package Crypt::SecretBuffer::Span;
# VERSION
# ABSTRACT: Prevent accidentally leaking a string of sensitive data

use strict;
use warnings;
use Crypt::SecretBuffer; # loads XS methods into this package

=head1 SYNOPSIS

  use Crypt::SecretBuffer;
  my $buf= Crypt::SecretBuffer->new->load_file("secrets.conf");
  
  # Create a span, linked to $buf
  my $s= $buf->span->utf8;
  
  # Trim leading whitespace
  $s->ltrim(qr/[\s]+/);
  
  # Try parsing a '[' from the current position
  if ($s->parse('[')) {
    # start of a INI-style "[header]"
    $header= $s->parse(qr/[^]\n]+/);  # capture until ']' or end of line
    
    $s->parse(']')
      or die "Didn't find ']' at end of header";

    $s->ltrim(qr/[\s]+/);
  }

=head1 DESCRIPTION

This module represents a span of bytes in a L<Crypt::SecretBuffer>, optionally with a character
encoding.  The methods on this object inspect the bytes of the SecretBuffer to alter the byte
range or return new Span objects for sub-ranges.  When you've narrowed-in on the data you
wanted, you can extract it to another SecretBuffer object or a non-secret scalar.

(While all of this can be done better using Perl's regexes, I currently have no practical way
to apply regexes to the buffer without it getting copied into scalars, defeating the purpose
of SecretBuffer).

=attribute buf

The C<SecretBuffer> this span refers to.  Spans hold a strong reference to the buffer.

=cut

# span holds a ref to buffer, and it's less effort to let perl see it for things like iThread cloning.
sub buf { $_[0]{buf} }
*buffer= *buf;

=attribute pos

The parse position.  This is a byte offset within the SecretBuffer, even when using a multibyte
encoding.  This is never less than zero.

=attribute len

The count of bytes in this span.  This is never less than zero, and will never refer past the
end of the buffer unless you alter the buffer length.

=attribute lim

The "limit" (one-beyond-the-end) position, equal to C<< pos + len >>.  This will never be
greater than the length of the buffer unless you alter the buffer length.

=attribute encoding

Read-only; this determines how characters will be iterated within the SecretBuffer.  This
carries over to Span objects created from this span.

=method span

  $new_span= $span->span(%attributes);
  $new_span= $span->span($ofs);
  $new_span= $span->span($ofs, $len);

You can specify key/value C<%attributes> directly, or if the first argument is numeric this
behaves like C<substr>, including handling of negative indices to refer to positions relative
to the end of the buffer.

=method parse

  $span= $span->parse($pattern);
  $span= $span->parse($pattern, $flags=0);

If the current span begins with C<$pattern>, return the span describing that pattern and advance
L</pos> to the end of that match.  If not, return C<undef> and C<pos> is unchanged.

=over

=item rparse

Alias for C<< parse($pattern, REVERSE) >>.  It parses and removes backward from the end of the
span.

=back

=method trim

  $span->trim($pattern=qr/[\s]+/, $flags=0)->...

Remove C<$pattern> from the start and end of the Span.  Returns the same C<Span> object, for
chaining.  If you need to know how much was removed, use C<parse>/C<rparse> instead.  Note that
if you pass a simple string, this only removes the pattern once.  You need C<< qr/...+/ >> to
remove multiple occurrences, or the C<SPAN> flag.

The default pattern is C<< qr/[\s]+/ >>.

=over

=item ltrim

Only remove from the start of the Span

=item rtrim

Only remove from the end of the Span

=back

=cut

# used by XS, can be localized
$Crypt::SecretBuffer::Span::default_trim_regex= qr/[\s]+/;

=method starts_with

  $bool= $span->starts_with($pattern);

Return a boolean of whether $pattern matches at the start of the string.

=method ends_with

  $bool= $span->ends_with($pattern);

Return a boolean of whether $pattern matches at the end of the string.

=method scan

  $span= $span->scan($pattern, $flags=0);

Look for the first occurrence of a pattern in this Span.  Return a new Span describing where it
was found.  The current Span is unchanged.

=method copy

=method copy_to

  $secret= $span->copy(%options);
  $span->copy_to($scalar_or_secret, %options);

Copy the current span of bytes.  C<copy> returns a new SecretBuffer object.  C<copy_to> writes
into an existing buffer, which can be either a SecretBuffer or a scalar for non-secrets.  There
is intentionally I<not> a method to I<return> a scalar, to avoid easily leaking secrets.

Options:

=over

=item encoding => $encoding

Encode bytes/characters written into the destination using the specified encoding.  The
bytes/characters are read from the current buffer using the Span's C<encoding> attribute.  The
default is to assume the same destination encoding as the source and copy the bytes literally,
*unless* the destination is a Perl scalar and the source encoding was a type of unicode, in which
case the default is to copy as Perl "wide characters" (which is internally UTF-8).  But, if you
specify UTF-8 here, you will instead receive bytes of a UTF-8 rather than perl wide characters.

=back

=cut

1;
