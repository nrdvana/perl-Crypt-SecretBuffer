package Crypt::SecretBuffer::Span;
# VERSION
# ABSTRACT: Prevent accidentally leaking a string of sensitive data

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
    my $header= $s->parse(qr/[^]\n]+/);  # capture until ']' or end of line
    
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

  $span->trim(qr/[\s]+/, $flags=0)->...

Remove C<$pattern> from the start and end of the Span.  Returns the same C<Span> object, for
chaining.  If you need to know how much was removed, use C<parse>/C<rparse> instead.  Note that
if you pass a simple string, this only removes the pattern once.  You need C<< qr/...+/ >> to
remove multiple occurrences, or the C<SPAN> flag.

=over

=item ltrim

Only remove from the start of the Span

=item rtrim

Only remove from the end of the Span

=back

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

=method as_secret

  $secret_buffer= $span->as_secret(%options);

Return a new SecretBuffer for the currently described Span of bytes.

=over

=item encoding => $encoding

Derive character codepoints from the old buffer according to this Span's L</encoding> and
write new characters into the new buffer according to C<$encoding>.  This is especially useful
with the constant L</HEX> which can convert from ascii to raw bytes in the new SecretBuffer.

=back

=method as_nonsecret

  $scalar= $span->as_nonsecret(%options);

Options:

=over

=item encoding => $encoding

Derive character codepoints from the old buffer according to this Span's L</encoding> and
write new characters into the new buffer according to C<$encoding>.

=back

=cut

