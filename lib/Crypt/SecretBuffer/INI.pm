package Crypt::SecretBuffer::INI;
# VERSION
# ABSTRACT: Parse and Render INI format in a SecretBuffer

use strict;
use warnings;
use Carp;

=head1 SYNOPSIS

  use Crypt::SecretBuffer qw/ secret /;
  use Crypt::SecretBuffer::INI qw/ AS_SECRETBUFFER FORMAT_HEX /;
  
  # For file contents:
  #
  # [test]
  # name = value
  # aes_key = 00112233
  
  $sb= secret(load_file => $path);
  my $ini= Crypt::SecretBuffer::INI->new(%config);
  my $config= $ini->parse(
    aes_key => AS_SECRETBUFFER|FORMAT_HEX,
  );
  
  # Now you have:
  # config => {
  #   test => {
  #     name    => 'value',
  #     aes_key => secret("\x00\x11\x22\x33"),
  #   }
  # }
  
  # Produce a file with secrets:
  $out= secret;
  $ini->buffer($out);
  $ini->render_tree($config);
  $out->save_file($path);

=head1 DESCRIPTION

One of the challenges of trying to keep secrets hidden in a SecretBuffer is that they typically
start inside of config files, and in parsing the config file to load them you leak them into
the Perl interpreter's buffers.

This module lets you parse out the simple common C<< "name=value\n" >> found in many config
files, exposing the keys but selectively loading the value in a SecretBuffer.

=attribute utf8

Boolean, whether to encode as UTF-8 and validate UTF-8 when decoding.

=attribute opt_hash_comment

Boolean, whether to allow '#' as a comment character as well as the default ';'

=attribute opt_inline_comment

Boolean, whether to allow comments on the end of lines containing other directives,
which also means your values can't contain the comment character.

=attribute section_separator

If set, the L</parse> function will split the section headers on this regex to create a
tree of data.  If not set, each section becomes a top-level key of the configuration.

=cut

sub section_separator {
   @_ > 1? ($_[0]{section_separator}= $_[1]) : $_[0]{section_separator}
}

=attribute buffer

The L</Crypt::SecretBuffer> instance being parsed or written.  Setting this attribute resets
all parse-related attributes.

=cut

sub buffer {
   if (@_ > 1) {
      !defined $_[1] or (blessed $_[1] && $_[1]->isa('Crypt::SecretBuffer'))
         or croak "Not a SecretBuffer object";
      $_[0]{buffer}= $_[1];
      $_[0]->reset_parse;
   }
   $_[0]{buffer};
}

=attribute pos

The byte offset which will be parsed or rendered next.

=attribute context

Return the 1-based line number and character offset represented by C<pos>, as a list.

=attribute eof

True if C<pos> is past the end of the buffer's data.

=attribute section

After a successful parse, this indicates the most recent '[SECTION]' seen in the file.
The initial value is C<''> if C<name=value> parameters are discovered before a section.

=attribute key

After a successful parse, this is the whitespace-trimmed "key" half of "key=value".

=cut

sub section { $_[0]{section} }
sub key     { $_[0]{key} }

=attribute value

After a successful parse, this returns the "value" half of "key=value".  This is actually an
alias for the L</decode_value> method, and can take flags for how to decode the value.

=method parse_next

  $ini->parse_next
    or die $ini->error;

This advances 'pos', capturing any section it passes over, and recording the 'key' and beginning
and end offsets of the 'value'.  It returns true if it successfully found a `key = value`
syntax, and false on parse errors or EOF.  If it fails, pos is updated, key and value are
cleared, and a message is stored in L</error> unless the stream ended "cleanly" at end of file.

If you call C<parse_next> when C<error> is defined, it will clear the error and attempt to skip
over garbage in search of the next line of text to resume parsing.

The following position attributes are also updated by a successful C<parse_next>:

=over

=item section_ofs

=item section_len

=item key_ofs

=item key_len

=item value_ofs

=item value_len

=back

=method parse

  $tree= $ini->parse(
    $literal_key     => $decoding_flags,
    qr/$key_pattern/ => $decoding_flags,
    $section => [
      $name_pattern => $decoding_flags,
    ],
    qr/$section_pattern/ => [
      $name_pattern => $decoding_flags,
    ],
    ...
  );

This is a convenient loop around L</parse_next> which takes a specification of L</decode_value>
flags for various names of keys it might encounter.  The patters are given as a list so that
you can use Regexp-refs as the left hand side.  Bare names match keys of I<every> section, but
if the right-hand side is an arrayref or hashref then the left side is treated as a section name
with the rules only applying within matching sections.

The first matching rule is used to decode the value, so put your highest-priority rules first.

This function dies on any parse errors.

=cut

sub _find_format {
   my $self= shift;
   my $path= shift;
   croak "Expected an even number of arguments for (pattern => flag) pairs"
      if @_ & 1;
   for (my $i= 0; $i < $#_; $i += 2) {
      my ($name, $flag)= @_[$i,$i+1];
      # ref on RHS means compare to the section only
      if (ref $flag eq 'ARRAY' || ref $flag eq 'HASH') {
         next unless ref $name eq 'Regexp' ? ($path->[0] =~ $name)
                                           : ($path->[0] eq $name);
         my @subpath= @{$path}[1..$#$path];
         my $found= $self->_find_format(\@subpath, ref $flag eq 'ARRAY'? @$flag : %$flag);
         return $found if defined $found;
      }
      # else comparing to key.
      elsif (ref $name eq 'Regexp') {
         return $flag if $self->key =~ $name;
      }
      else {
         return $flag if $self->key eq $name;
         if (defined (my $sep= $self->section_separator)) {
            # also compare paths, if section_separator is defined.
            # can't join on section_separator because it could be a regex.
            my @matchpath= split $sep, $name;
            return $flag if join("\0", @$path, $self->key) eq join("\0", @matchpath);
         }
      }
   }
   return undef;
}

sub parse {
   my $self= shift;
   my $prev_sec= 0;
   my $root= {};
   my $sep= $self->section_separator;
   my @path;
   my $node;
   while ($self->parse_next) {
      if ($self->section_ofs != $prev_sec) {
         $node= $root;
         @path= defined $sep? split($sep, $self->section) : ( $self->section );
         for (@path) {
            $node->{$_}= {}
               unless ref $node->{$_} eq 'HASH';
            $node= $node->{$_};
         }
      }
      $node->{$self->key}= $self->decode_value($self->_find_format(\@path, @_) // 0);
   }
   croak "Parse error: ".$self->error." at input line ".join(' char ', $self->context)
      if defined $self->error;
   return $root;
}

=method decode_value

  if ($ini->parse_next) {
    $val= $is_a_secret_field{$ini->key}? $ini->decode_secret($flags)
                                       : $ini->decode_value($flags);
  }

Copy the value of the most recent L</parse_next> from L</buffer> into either a plain scalar or
a C<Crypt::SecretBuffer> object.  In addition, it processes any escapes or encoding in the raw
encoded value to give you the logical data.  C<$flags> are an OR-ed combination of:

=over

=item L</AS_SECRETBUFFER>

=item L</FORMAT_HEX>

=back

=method decode_secret

An alias for decode_value that implies C<AS_SECRETBUFFER> in the flags.

=export AS_SECRETBUFFER

Symbolic constant that tells L</decode_value> to return the value in a C<Crypt::SecretBuffer>

=export FORMAT_HEX

Symbolic constant that tells L<decode_value> to parse hexadecimal or tells C<encode_value> to
generate hexadecimal.

=cut

1;
