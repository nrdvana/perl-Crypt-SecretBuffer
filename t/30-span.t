use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw( secret UTF8 ISO8859_1 );

subtest attributes => sub {
   my $buf= secret("abcdef");
   is $buf->span,
      object {
         call pos => 0;
         call len => 6;
         call length => 6;
         call lim => 6;
         call buf => $buf;
         call buffer => $buf;
         call encoding => 'ISO8859_1';
      },
      'full buffer span';

   my $s= secret("abcdef")->span(5);
   is( $s->pos, 5, 'pos' );
   is( $s->len, 1, 'len' );
   is( $s->lim, 6, 'lim' );

   $s= secret("abcdef")->span(2,3);
   is( $s->pos, 2, 'pos' );
   is( $s->len, 3, 'len' );
   is( $s->lim, 5, 'lim' );

   $s->encoding(UTF8);
   is $s->encoding, 'UTF8', 'encoding changed to enum';

   is $s->span(1),
      object {
         call pos => 3;
         call len => 2;
         call lim => 5;
         call encoding => 'UTF8';
      },
      'sub-span adds pos and preserves encoding';

   is $s->span(-2, -1),
      object {
         call pos => 3;
         call len => 1;
         call lim => 4;
      },
      'sub-span negative indices relative to parent span';

   my $x= "\x{100}\x{200}\x{300}";
   utf8::encode($x);
   # ascii doesn't take effect until attempting to scan chars, so this works
   is secret($x)->span(pos => 1, len => 5, encoding => 'ASCII'),
      object {
         call pos => 1;
         call len => 5;
         call lim => 6;
         call encoding => 'ASCII';
      },
      'buf->span with attributes';

   is( Crypt::SecretBuffer::Span->new(buf => secret(""), pos => 2, len => 2, encoding => 'UTF8'),
      object {
         call buf => object { call length => 0; };
         call pos => 0;
         call len => 0;
         call encoding => 'UTF8';
      },
      'class constructor with attributes' );
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
   ok $s->starts_with(qr/[\xC4]/), 'starts with byte';
   # it will decode the character
   $s->encoding('UTF8');
   ok $s->starts_with(qr/[\x{100}]/), 'starts with utf-8 char';
};

subtest ends_with => sub {
   my $s= secret("abc123def")->span;
   ok( $s->ends_with('f'), 'ends_with character' );
   ok( $s->ends_with('ef'), 'ends_with string' );
   ok( !$s->ends_with('a'), 'doesnt end with char' );
   ok( $s->ends_with(qr/[a-z]/), 'ends with char class' );
   ok( $s->ends_with(qr/[a-z]+/), 'ends with char class repeated' );
   ok( !$s->ends_with(qr/[0-9]/), 'doesnt end with digit' );
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

subtest copy_bytes => sub {
   my $s= secret("abcdef")->span;
   is $s->copy,
      object {
         call stringify => '[REDACTED]';
         call length => 6;
         call sub { shift->span->starts_with("abcdef") } => T;
      },
      'copy';
   my $str;
   $s->copy_to($str);
   is( $str, "abcdef", "copy to scalar" );
   my $buf= secret("");
   $s->copy_to($buf);
   is $buf,
      object {
         call stringify => '[REDACTED]';
         call length => 6;
         call sub { shift->span->starts_with("abcdef") } => T;
      },
      'copy to secret';

   # Try to specify something out of bounds
   $s->buf->length(4);
   is( $s->length, 6, 'span is 6 bytes' );
   ok( !eval { $s->copy }, 'copy died' );
   like( $@, qr/ends beyond buffer/, 'error message' );
};

done_testing;
