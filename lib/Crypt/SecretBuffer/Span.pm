package Crypt::SecretBuffer::Span;
# VERSION
# ABSTRACT: Reference a span of bytes within a SecretBuffer

use strict;
use warnings;
use Crypt::SecretBuffer; # loads XS methods into this package
use overload 'cmp'  => \&cmp,
             '""'   => sub { 'Span('.($_[0]->buf->stringify_mask||"[REDACTED]").', pos='.$_[0]->pos.', len='.$_[0]->len.')' },
             'bool' => sub{1}; # span objects are always true

=head1 SYNOPSIS

  use Crypt::SecretBuffer;
  my $buf= Crypt::SecretBuffer->new(load_file => "secrets.conf");
  
  # Create a span, linked to $buf
  my $s= $buf->span(encoding => "UTF-8");
  
  # Trim leading whitespace
  $s->ltrim(qr/[\s]+/);
  
  # Try parsing a '[' from the current position
  if ($s->parse('[')) {
    # start of a INI-style "[header]"
    my $header_span= $s->parse(qr/[^]\n]+/);  # capture until ']' or end of line
    
    $s->parse(']')
      or die "Didn't find ']' at end of header";

    $header_span->copy_to(my $header); # no longer a secret
  }

=head1 DESCRIPTION

This module represents a span of bytes in a L<Crypt::SecretBuffer>, optionally with a character
encoding.  The methods on this object inspect the bytes of the SecretBuffer, and update the
boundaries of the span or return new Span objects for sub-spans.  When you've narrowed-in on
the data you want, you can extract it to another SecretBuffer object or a non-secret scalar
using L</copy_to>.

This module provides some basic parsing ability for SecretBuffer text.  While the "right tool for
the job" would normally be Perl's regex engine, I have found no practical way to apply regexes to
the buffer without it getting copied into global scalars, which would defeat the purpose of
SecretBuffer.  L<https://www.perlmonks.org/?node_id=11166676>.

=constructor new

  $span= Crypt::SecretBuffer::Span->new(%attributes);

The only required attribute is C<buf>.  C<pos> defaults to 0, C<lim> defaults to the length of
the buffer, and C<encoding> defaults to C<ISO8859_1> which treats each byte as an 8-bit unicode
codepoint.

If called as a method on an object, this behaves the same as L</clone>.

=constructor clone

  $span= $span->clone(%attributes);

Create a new span that inherits C<pos>, C<lim>, C<buf>, and C<encoding> from the first span
if they weren't overridden in the attributes.

=constructor subspan

  $span= $span->subspan($pos, $len);
  $span= $span->subspan(pos => $pos, lim => $lim);

Like C<clone>, but C<$pos> and C<$lim> (and negative L<$len> values) are relative to the current
span instead of absolute offsets into the buffer.

=attribute buf

The C<SecretBuffer> this span refers to.  Spans hold a strong reference to the buffer.

=over

=item buffer

Alias for C<buf>.

=back

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

=over

=item length

Alias for C<len>.

=back

=attribute lim

The "limit" (one-beyond-the-end) position, equal to C<< pos + len >>.  Note that changes to the
buffer may result in C<pos> or C<lim> referring to non-existent bytes, which will die if you try
to acces them.  (a perl "die", not C "undefined behavior")

=attribute encoding

Read-only; this determines how characters will be iterated within the SecretBuffer.
This carries over to Span objects created from this span.
See L<Crypt::SecretBuffer/Character Encodings>.

=method parse

  $span= $span->parse($pattern);
  $span= $span->parse($pattern, $flags=0);

If the current span begins with C<$pattern>, return the span describing that pattern and advance
L</pos> to the end of that match.  If not, return C<undef> and C<pos> is unchanged.
See L<Crypt::SecretBuffer/Match Flags> for the list of flags.

=over

=item rparse

Alias for C<< parse($pattern, MATCH_REVERSE) >>.  It parses and removes backward from the end of
the span.

=back

=method trim

  $span->trim->...
  $span->trim($pattern)->...
  $span->trim($pattern, $flags)->...

Remove C<$pattern> from the start and end of the Span.  Returns the same C<Span> object, for
chaining.  If you need to know how much was removed, use C<parse>/C<rparse> instead.  Note that
this only removes the pattern once, unless you provide the C<MATCH_MULTI> flag or specify '+' on
the end of your regex.

The default pattern is C<< qr/[\s]+/ >>.

See L<Crypt::SecretBuffer/Match Flags> for the list of flags.

=over

=item ltrim

Only remove from the start of the Span

=item rtrim

Only remove from the end of the Span

=back

=method consume_bom

  # On a buffer which may begin with a BOM:
  $span->consume_bom->cmp("\x{100}");

Look for an optional L<Byte-Order-Mark|https://en.wikipedia.org/wiki/Byte_order_mark> at the
start of the span, and if found, change the encoding and advance the span start to the next
character.

  First bytes       Encoding
  -----------       --------
  FE FF             UTF16BE
  FF FE             UTF16LE
  EF BB BF          UTF8

This returns the original Span object, with C<pos> and C<encoding> modified if a BOM was found.
This allows you to chain methods on a span object while conveniently processing the BOM.

This does not work if another encoding is being used to see those bytes, such as decoding BASE64.
A Span can have only one encoding, so if you need to decode BASE64 and then process a BOM, you
need to use L</copy> to create a new SecretBuffer of raw bytes, then decode the BOM.

=over

=item set_up_us_the_bom

Provided as an alias, for fun.

=back

=cut

# used by XS, can be localized
$Crypt::SecretBuffer::Span::default_trim_regex= qr/[\s]+/;

=method starts_with

  $bool= $span->starts_with($pattern);

Return a boolean of whether $pattern matches from the start of the Span.

=method ends_with

  $bool= $span->ends_with($pattern);

Return a boolean of whether $pattern matches ending at the end of the Span.

=method scan

  $span= $span->scan($pattern, $flags=0);

Look for the first occurrence of a pattern in this Span.  Return a new Span describing where it
was found.  The current Span is unchanged.
See L<Crypt::SecretBuffer/Match Flags> for the list of flags.

=method copy

=method copy_to

=method append_to

  $secret= $span->copy(%options);
  $span->copy_to($scalar_or_secret, %options);
  $span->append_to($scalar_or_secret, %options);

Copy the current span of bytes.  C<copy> returns a new SecretBuffer object.  C<copy_to> replaces
the content of a SecretBuffer or scalar.  C<append_to> appends to a SecretBuffer or scalar.
(There is intentionally I<not> a method to I<return> a scalar, to avoid easily leaking secrets)

Options:

=over

=item encoding => $encoding

Specify the encoding for the destination.  The bytes/characters are read from the current buffer
using the Span's C<encoding> attribute.  The default is to assume the same destination encoding
as the source and simply duplicate the byte string, *unless* the destination is a Perl scalar
and the source encoding was a type of unicode, in which case the default is to copy as Perl
"wide characters" (which is internally UTF-8).  If you specify UTF-8 here, you will receive
bytes of UTF-8 rather than perl wide characters.

=back

=method memcmp

  $cmp= $span->memcmp($other_thing);

Compare contents of the span byte-by-byte to another Span (or SecretBuffer, or plain scalar) in
the same manner as the C function C<memcmp>.  (returns C<< <0 >>, C<0>, or C<< >0 >>)

=method cmp

  $cmp= $span->cmp($other_thing);

Iterate codepoints of this Span and compare each numerically to the codepoints of another Span
(or SecretBuffer, or plain scalar).  This method is also used as the overloaded 'cmp' operator.
This is B<not> a locale-aware comparison.

=cut

1;
