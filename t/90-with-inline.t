use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw(secret);

skip_all "Require Inline::C for this test"
   unless eval { require Inline::C };

note explain(Crypt::SecretBuffer->Inline('C'));
note explain(@INC);
note `find .`;

if (ok eval <<END_PM )
package TestSecretBufferWithInline;
use Inline with => 'Crypt::SecretBuffer';
use Inline C => <<END_C;

#include <SecretBuffer.h>

int test(secret_buffer *buf) {
   return buf->len;
}

END_C

1;
END_PM
{
   my $secret= secret(length => 10);
   is( TestSecretBufferWithInline::test($secret), 10, 'called Inline fn on SecretBuffer' );
}
else {
   diag $@;
}

done_testing;
