use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw(secret);

subtest attributes => sub {
   my $s= secret("abcdef")->span;
   is( $s->pos, 0, 'pos' );
   is( $s->len, 6, 'len' );
   is( $s->lim, 6, 'lim' );

   $s= secret("abcdef")->span(5);
   is( $s->pos, 5, 'pos' );
   is( $s->len, 1, 'len' );
   is( $s->lim, 6, 'lim' );

   $s= secret("abcdef")->span(2,3);
   is( $s->pos, 2, 'pos' );
   is( $s->len, 3, 'len' );
   is( $s->lim, 5, 'lim' );
};

subtest starts_with => sub {
   my $s= secret("abc123def")->span;
   ok( $s->starts_with('a'), 'starts_with character' );
   ok( $s->starts_with('ab'), 'starts_with string' );
   ok( !$s->starts_with('b'), 'doesnt start with char' );
   ok( $s->starts_with(qr/[a-z]/), 'starts with char class' );
   ok( $s->starts_with(qr/[a-z]+/), 'starts with char class repeated' );
   ok( !$s->starts_with(qr/[0-9]/), 'doesnt start with digit' );
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

done_testing;
