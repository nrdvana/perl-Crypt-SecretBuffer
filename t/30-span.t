use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Encode qw( encode decode );
use MIME::Base64;
use Crypt::SecretBuffer qw( secret span UTF8 ISO8859_1 UTF16LE UTF16BE
  HEX BASE64 MATCH_NEGATE MATCH_MULTI );

subtest constructors => sub {
   my $buf= secret("abcdef");
   is $buf->span,
      object {
         call pos => 0;
         call len => 6;
         call length => 6;
         call lim => 6;
         call buf => $buf;
         call buffer => $buf;
         call encoding => ISO8859_1;
      },
      'full buffer span';

   is $buf->span->clone,
      object {
         call pos => 0;
         call len => 6;
         call length => 6;
         call lim => 6;
         call buf => $buf;
         call buffer => $buf;
         call encoding => ISO8859_1;
      },
      'full buffer span clone';

   is $buf->span(1,-1),
      object { call pos => 1; call len => 4; call lim => 5; },
      'span using negative pos and len';

   is $buf->span(pos => 1, lim => 5),
      object { call pos => 1; call len => 4; call lim => 5; },
      'using attribute names';

   is( Crypt::SecretBuffer::Span->new(buf => secret(""), pos => 2, len => 2, encoding => 'UTF8'),
      object {
         call buf => object { call length => 0; };
         call pos => 0;
         call len => 0;
         call encoding => UTF8;
      },
      'class constructor, all attributes, pos truncated' );

   my $s= Crypt::SecretBuffer::Span->new(buf => secret("abcdefgh"), pos => -4, len => -1);
   is $s,
      object {
         call buf => object { call length => 8; };
         call pos => 4;
         call lim => 7;
         call len => 3;
         call encoding => ISO8859_1;
      },
      'class constructor, negative pos';

   $s->encoding(UTF8);
   is $s->clone(pos => -3),
      object {
         call pos => 5;
         call lim => 7;
         call len => 2;
         call buf => object { call length => 8; };
         call encoding => UTF8;
      },
      'clone with negative pos override';

   is $s->clone(-3),
      object {
         call pos => 5;
         call lim => 7;
         call len => 2;
         call buf => object { call length => 8; };
         call encoding => UTF8;
      },
      'clone with positional negative pos override';

   is $s->clone(len => 1),
      object { call pos => 4; call lim => 5; call len => 1; },
      'clone with new len';

   is $s->clone(len => 5),
      object { call pos => 4; call lim => 8; call len => 4; },
      'clone with len that gets truncated';

   is $s->clone(lim => 8),
      object { call pos => 4; call lim => 8; call len => 4; },
      'clone with new lim';

   $s->pos(1);
   $s->lim(7);
   is $s->len, 6, 'pos/lim modified, len updated';
   $s->encoding(UTF8);
   is $s->encoding, UTF8, 'encoding changed to enum';

   is $buf->span(2,3,UTF8)->subspan(1),
      object {
         call pos => 3;
         call len => 2;
         call lim => 5;
         call encoding => UTF8;
      },
      'sub-span adds pos and preserves encoding';

   is $buf->span(2,3)->subspan(-2, -1),
      object {
         call pos => 3;
         call lim => 4;
         call len => 1;
      },
      'sub-span negative indices relative to parent span';

   is span(secret("AB\xC8\x80"), 2, 2, UTF8)->cmp("\x{200}"), 0, 'span of secret';
   is span(secret("AB\xC8\x80")->span(1), 1, 2)->cmp("\xC8\x80"), 0, 'span of span';
   is span("AB\xC8\x80", encoding => UTF8)->cmp("AB\x{200}"), 0, 'span of scalar';
};

subtest starts_with => sub {
   my $s= secret("abc123def")->span;
   ok( $s->starts_with('a'), 'starts_with character' );
   ok( $s->starts_with('ab'), 'starts_with string' );
   ok( !$s->starts_with('b'), 'doesnt start with char' );
   ok( $s->starts_with(qr/[a-z]/), 'starts with char class' );
   ok( $s->starts_with(qr/[a-z]+/), 'starts with char class repeated' );
   ok( !$s->starts_with(qr/[0-9]/), 'doesnt start with digit' );

   my $x= "\x{100}\x{200}\x{300}";
   utf8::encode($x);
   # ascii doesn't take effect until attempting to scan chars, so this works
   $s= secret($x)->span(encoding => 'ASCII');
   # it will fail because ASCII is strict 7-bit
   ok !eval{ $s->starts_with(qr/[a]/); 1 }, 'ASCII dies on 0x80..0xFF';
   note $@;
   # it will return a byte of the UTF8 encoding
   $s->encoding(ISO8859_1);
   ok $s->starts_with(qr/[\xC4]/), 'starts with byte (using charset)';
   ok $s->starts_with("\xC4"), 'starts with byte (using literal)';
   # it will decode the character
   $s->encoding('UTF-8');
   ok $s->starts_with(qr/[\x{100}]/), 'starts with utf-8 char (using charset)';
   ok $s->starts_with("\x{100}"), 'starts with utf-8 char (using literal)';

   $s= secret("\x01\xFF")->span;
   ok( $s->starts_with(secret("\x01\xFF")->span), 'starts_with a ISO-8859-1 span' );
   ok( $s->starts_with(secret("01FF")->span(encoding => HEX)), 'starts_with a HEX span' );
   $x= "\x01\xFF";
   utf8::encode($x);
   ok( $s->starts_with(secret($x)->span(encoding => UTF8)), 'starts_with a UTF-8 span' );
};

subtest ends_with => sub {
   my $s= secret("abc123def")->span;
   ok( $s->ends_with('f'), 'ends_with character' );
   ok( $s->ends_with('ef'), 'ends_with string' );
   ok( !$s->ends_with('a'), 'doesnt end with char' );
   ok( $s->ends_with(qr/[a-z]/), 'ends with char class' );
   ok( $s->ends_with(qr/[a-z]+/), 'ends with char class repeated' );
   ok( !$s->ends_with(qr/[0-9]/), 'doesnt end with digit' );

   # This tests the reverse decoding of various encodings
   $s= $s->buf;
   ok( $s->span(encoding => HEX)->ends_with(qr/[\xEF]/), 'parse hex in reverse' );
   $s= secret(encode_base64("A"));
   ok( $s->span(encoding => BASE64)->ends_with('A'), 'parse base64 in reverse' );
   $s= secret(encode_base64("AB"));
   ok( $s->span(encoding => BASE64)->ends_with('AB'), 'parse base64 in reverse' );
   $s= secret(encode_base64("ABC"));
   ok( $s->span(encoding => BASE64)->ends_with('ABC'), 'parse base64 in reverse' );
   $s= secret(encode('UTF-8', "123\x{123}"));
   ok( $s->span(encoding => UTF8)->ends_with("23\x{123}"), 'parse utf8 2-byte in reverse' );
   $s= secret(encode('UTF-8', "123\x{1234}"));
   ok( $s->span(encoding => UTF8)->ends_with("23\x{1234}"), 'parse utf8 3-byte in reverse' );
   $s= secret(encode('UTF-8', "123\x{12345}"));
   ok( $s->span(encoding => UTF8)->ends_with(qr/[\x{12345}]/), 'parse utf8 4-byte in reverse' );
   $s= secret(encode('UTF-16LE', "123\x{1234}"));
   ok( $s->span(encoding => UTF16LE)->ends_with("23\x{1234}"), 'parse utf-16le in reverse' );
   $s= secret(encode('UTF-16LE', "123\x{12345}"));
   ok( $s->span(encoding => UTF16LE)->ends_with("23\x{12345}"), 'parse utf-16le surrogates in reverse' );
   $s= secret(encode('UTF-16BE', "123\x{1234}"));
   ok( $s->span(encoding => UTF16BE)->ends_with("23\x{1234}"), 'parse utf-16be in reverse' );
   $s= secret(encode('UTF-16BE', "123\x{12345}"));
   ok( $s->span(encoding => UTF16BE)->ends_with(qr/[\x{12345}]/), 'parse utf-16be surrogates in reverse' );
};

subtest parse => sub {
   my $s= secret("name=val")->span;
   is $s->parse("="), undef, 'no = anchored at start';
   is $s->parse(qr/[a-z]+/), object { call pos => 0; call len => 4; }, 'parse name';
   is $s->parse("="), object { call pos => 4; call len => 1; }, 'parse =';
   is $s, object { call pos => 5; call len => 3; }, 'remaining value';

   $s= $s->buf->span;
   is $s->parse('=', MATCH_NEGATE|MATCH_MULTI),
      object { call pos => 0; call len => 4; },
      'parse name by MATCH_NEGATE =';

   $s= secret("1=2==3=4")->span;
   is $s->rparse('==', MATCH_NEGATE|MATCH_MULTI),
      object { call pos => 5; call len => 3; },
      'parse value by reverse MATCH_NEGATE =';
   is $s, object { call pos => 0; call len => 5; }, 'remianing buffer';
   
   # capture entire line with a negated match
   $s= secret("qwerty")->span;
   is $s->parse('0', MATCH_NEGATE|MATCH_MULTI),
      object { call pos => 0; call len => 6; },
      'parse entire line with negated match';

   $s= secret('')->span;
   is $s->parse('-', MATCH_NEGATE|MATCH_MULTI),
      object { call pos => 0; call len => 0; },
      'parse from empty buffer';

   $s= secret('-')->span;
   is $s->parse('', MATCH_MULTI),
      object { call len => 0; },
      'parse nothing from nonempty buffer';
   is $s->parse('', MATCH_NEGATE|MATCH_MULTI),
      undef,
      'parse nothing from nonempty buffer';
};

subtest parse_packed => sub {
   plan skip_all => 'parse_packed is not implemented in this build'
      unless Crypt::SecretBuffer::Span->can('parse_packed');

   my @tests= (
      [ 'ccccc',     [ 0, 1, -1, 127, -128 ] ],
      [ 'C4',        [ 0, 1, 128, 255 ] ],
      [ 'x C x C',   [ 0xAA, 0xBB ], [ 0x11, 0xAA, 0x22, 0xBB ] ],
      [ 's[4]',      [ 0, 1, 0x7FFF, -0x8000 ] ],
      [ 's< s>',     [ 1, 1 ] ],
      [ 'l[4]',      [ 0, 1, 0x7FFFFFFF, -0x80000000 ] ],
      [ 'l< l>',     [ 1, 1 ] ],
      [ 'v[3]',      [ 0, 1, 0xFFFF ] ],
      [ 'V[3]',      [ 0, 1, 0xFFFFFFFF ] ],
      [ 'n[3]',      [ 0, 1, 0xFFFF ] ],
      [ 'N[3]',      [ 0, 1, 0xFFFFFFFF ] ],
      [ 'w3',        [ 1, 0xFEDCBA98, 0xFFFFFFFF ] ],
      [ '(C s<)[2]', [ 7, 0x1234, 8, 0x5678 ] ],
      [ '(((((((C s< s)[2])1))2)))', [ 7, 0x1234, 1, 8, 0x5678, 1, 7, 0x1234, 1, 8, 0x5678, 1 ] ],
   );

   for my $test (@tests) {
      my ($fmt, $vals, $packed_bytes)= @$test;
      subtest "Format $fmt" => sub {
         my $packed= defined $packed_bytes
            ? pack('C*', @$packed_bytes)
            : pack($fmt, @$vals);
         my $sb= secret($packed);
         my $span= $sb->span;

         is( [ $span->unpack($fmt) ], $vals, "unpack" );
         is( $span->pos, 0, ' unpack does not consume bytes' );
         is( $span->len, length($packed), ' unpack leaves span length unchanged' );

         is( $span->unpack_to_array($fmt), $vals, "unpack_to_array" );
         is( $span->pos, 0, ' unpack_to_array does not consume bytes' );

         is( [ $span->parse_packed($fmt) ], $vals, "parse_packed" );
         is( $span->len, 0, ' parse_packed consumed all bytes' );
         is( $span->last_error, undef, ' parse_packed left no error' );

         $span= $sb->span;
         is( $span->parse_packed_to_array($fmt), $vals,
            "parse_packed_to_array" );
         is( $span->len, 0, ' parse_packed_to_array consumed all bytes' );
         is( $span->last_error, undef, ' parse_packed_to_array left no error' );
      }
   }
   
   # Q should be supported regardless of whether perl has 64-bit SVs, using automatic BigInts
   is( '' . secret("\x01\x00\x00\x00\x00\x00\x00\x02")->span->unpack('Q<'), "144115188075855873", 'Q<' );
   is( '' . secret("\x01\x00\x00\x00\x00\x00\x00\x02")->span->unpack('Q>'), "72057594037927938", 'Q>' );
   
   like( dies { secret->span->unpack("("x1000) }, qr/too deep/, 'recursion limit' );

   subtest 'failed parses do not consume input' => sub {
      my $span= secret(pack('C', 0x7F))->span;
      is( [ $span->parse_packed('C C') ], [],
         'list context parse failure returns empty list' );
      is( $span->pos, 0, 'pos unchanged after list parse failure' );
      like( $span->last_error, qr/end of span/i, 'last_error reports end of span' );

      is( $span->parse_packed_to_array('C C'), undef,
         'arrayref parse failure returns undef' );
      is( $span->pos, 0, 'pos unchanged after arrayref parse failure' );
      like( $span->last_error, qr/end of span/i, 'last_error still reports end of span' );
   };

   subtest 'format errors croak' => sub {
      my $span= secret(pack('C', 0))->span;
      ok( !eval { $span->unpack('Z'); 1 }, 'unsupported format dies' );
      like( $@, qr/unsupported pack notation/, 'unsupported format error message' );

      ok( !eval { $span->unpack('(C'); 1 }, 'unmatched open paren dies' );
      like( $@, qr/Unmatched '\('/, 'unmatched open paren error message' );

      ok( !eval { $span->unpack('C[abc]'); 1 }, 'invalid bracket repeat dies' );
      like( $@, qr/missing digits|repeat count|unsupported pack notation/,
         'invalid repeat error message' );
   };
};

subtest trim => sub {
   my $buf= secret(" 1\r\n2\t3\r\n");
   is $buf->span->trim,
      object {
         call pos => 1;
         call len => 6;
      },
      'trim whole buffer';
   is $buf->span(2, 6)->trim,
      object {
         call pos => 4;
         call len => 3;
      },
      'trim sub-span';
   # ltrim
   is $buf->span->ltrim,
      object {
         call pos => 1;
         call len => 8;
      },
      'ltrim';
   is $buf->span->rtrim,
      object {
         call pos => 0;
         call len => 7;
      },
      'rtrim';
};

subtest bom => sub {
   is secret("\xFE\xFF\x001\x002\x003")->span->set_up_us_the_bom,
      object {
         call [ cmp => "123" ], 0;
         call encoding => "UTF-16BE";
      },
      'UTF16BE';
   is secret("\xFF\xFE1\x002\x003\x00")->span->set_up_us_the_bom,
      object {
         call [ cmp => "123" ], 0;
         call encoding => "UTF-16LE";
      },
      'UTF16LE';
   is secret("\xEF\xBB\xBF123")->span->set_up_us_the_bom,
      object {
         call [ cmp => "123" ], 0;
         call encoding => "UTF-8";
      },
      'UTF8';
};

subtest copy_iso8859 => sub {
   my $s= secret("abcdef")->span;
   is $s->copy,
      object {
         call stringify => '[REDACTED]';
         call length => 6;
         call sub { shift->span->starts_with("abcdef") } => T;
      },
      'copy';
   my $str= 'will get overwritten';
   $s->copy_to($str);
   is( $str, "abcdef", "copy to scalar" );
   $s->append_to($str);
   is( $str, "abcdefabcdef", "append to scalar" );

   my $buf= secret("will get overwritten");
   $s->copy_to($buf);
   is $buf,
      object {
         call stringify => '[REDACTED]';
         call length => 6;
         call [ memcmp => "abcdef" ] => 0;
      },
      'copy to secret';
   $s->append_to($buf);
   is $buf,
      object {
         call stringify => '[REDACTED]';
         call length => 12;
         call [ memcmp => "abcdefabcdef" ] => 0;
      },
      'append to secret';

   # Try to specify something out of bounds
   $s->buf->length(4);
   is( $s->length, 6, 'span is 6 bytes' );
   ok( !eval { $s->copy }, 'copy died' );
   like( $@, qr/ends beyond buffer/, 'error message' );

   # Copy empty span
   my $x;
   secret("-")->span(0,0)->copy_to($x);
   is( $x, '', 'empty string from empty span' );
   secret->span->copy_to($x);
   is( $x, '', 'empty string from buffer lacking any storage' );
};

subtest copy_widechar => sub {
   my $unicode= "\0\x{10}\x{100}\x{1000}\x{10000}\x{10FFFD}";

   my $utf8= encode('UTF-8', $unicode);
   my $buf= 'will get overwritten';
   secret($utf8)->span(encoding => UTF8)->copy_to($buf);
   is( $buf, $unicode, 'round trip through UTF-8' )
      or note map escape_nonprintable($_)."\n", $utf8, $buf;
   secret($utf8)->span(encoding => UTF8)->append_to($buf);
   is( $buf, $unicode x 2, 'round trip through UTF-8, append' )
      or note map escape_nonprintable($_)."\n", $utf8, $buf;

   my $utf16le= encode('UTF-16LE', $unicode);
   $buf= '';
   secret($utf16le)->span(encoding => UTF16LE)->copy_to($buf);
   is( $buf, $unicode, 'round trip through UTF-16LE' )
      or diag explain $buf;

   my $utf16be= encode('UTF-16BE', $unicode);
   $buf= '';
   secret($utf16be)->span(encoding => UTF16BE)->copy_to($buf);
   is( $buf, $unicode, 'round trip through UTF-16BE' )
      or diag explain $buf;
};

subtest copy_hex => sub {
   my $s= secret("\x01\x02\x03");
   is( $s->span->copy(encoding => HEX),
      object {
         call sub { shift->span->starts_with("010203") }, T;
         call length => 6;
      },
      'convert to hex' );

   $s= secret("010203");
   is( $s->span(encoding => HEX)->copy(encoding => ISO8859_1),
      object {
         call sub { shift->span->starts_with("\x01\x02\x03") }, T;
         call length => 3;
      },
      'convert from hex' );
};

subtest copy_base64 => sub {
   for my $str (qw( 123 three_times4 remainder1 remainder_2 )) {
      my $b64= encode_base64($str, '');
      my $tmp;
      secret($str)->span->copy_to($tmp, encoding => BASE64);
      is( $tmp, $b64, "encode $str" );
      undef $tmp;
      secret($b64)->span(encoding => BASE64)->copy_to($tmp, encoding => ISO8859_1);
      is( $tmp, $str, "decode $b64" );
   }

   my $tmp;
   secret("abcdefghijkl")->span->copy_to($tmp,
      encoding => BASE64,
      wrap => 8,
      wrap_delim => '--',
   );
   is( $tmp, "YWJjZGVm--Z2hpamts", 'base64 wrap and join' );

   secret("abcdefghijkl")->span->copy_to($tmp,
      encoding => BASE64,
      wrap => 8,
   );
   is( $tmp, "YWJjZGVm\nZ2hpamts", 'base64 wrap default join newline' );
};

subtest copy_hex_wrap => sub {
   my $tmp;
   secret("abcdef")->span->copy_to($tmp,
      encoding => HEX,
      wrap => 4,
      wrap_delim => ':',
   );
   is( $tmp, '6162:6364:6566', 'hex wrap and join' );
};

subtest codepointcmp => sub {
   is( secret("A")->span cmp secret("B")->span, -1, 'A cmp B' );
   is( secret("\xFF")->span cmp "\x{100}", -1, '0xFF cmp 0x100' );

   my $unicode= "\0\x{10}\x{100}\x{1000}\x{10000}\x{10FFFD}";
   my $utf16= encode('UTF-16LE', $unicode);
   is( secret($utf16)->span(encoding => 'UTF16LE') cmp $unicode, 0, 'utf16 cmp utf8' );
};

subtest clean_namespace => sub {
   my $ns= \%Crypt::SecretBuffer::Span::;
   my @public= qw(
      append_to buf buffer can clone cmp consume_bom copy copy_to default_trim_regex encoding
      ends_with last_error len length lim ltrim memcmp new parse parse_asn1_der_length
      parse_base128be parse_base128le parse_lenprefixed parse_packed parse_packed_to_array pos
      rparse rtrim scan set_up_us_the_bom starts_with subspan trim unpack unpack_to_array
   );
   is( [ grep /^[a-z]/ && $_ ne 'isa', sort keys %$ns ], \@public )
      or diag explain $ns;
};

done_testing;
