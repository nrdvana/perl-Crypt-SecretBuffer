use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use MIME::Base64;
use Config;
use Crypt::SecretBuffer qw( secret span UTF8 ISO8859_1 UTF16LE UTF16BE
  HEX BASE64 MATCH_NEGATE MATCH_MULTI );

my @vals= map +( (1<<$_)-1, (1<<$_) ), 0..31;
push @vals, map +( (1<<$_)-1, (1<<$_) ), 32..63
   if $Config{uvsize} >= 8;

sub test_encode_decode {
   my ($enc_method, $dec_method)= @_;
   # encode each into its own buffer, testing that we can parse up to the end of the buffer
   subtest "$enc_method individual buffers" => sub {
      for (@vals) {
         my $s= secret;
         $s->$enc_method($_);
         is( $s->span->$dec_method, $_, "val=$_" )
            or note $s->unmask_to(\&escape_nonprintable);
         # append_base128be should actually be identical to ->append(pack("w", $_))
         if ($enc_method eq 'append_base128be') {
            is( $s->memcmp(pack('w', $_)), 0, "matches pack('w',$_)" )
               or note $s->unmask_to(\&escape_nonprintable), ' ', escape_nonprintable(pack 'w', $_);
         }
      }
   };
   subtest "$enc_method concatenated" => sub {
      # now all in the same buffer forward
      my $s= secret;
      $s->$enc_method($_) for @vals;
      my $span= $s->span;
      for (@vals) {
         is( $span->$dec_method, $_, "val=$_" );
      }
   };
   subtest "$enc_method concatenated reverse" => sub {
      # now all in the same buffer backward
      my $s= secret;
      $s->$enc_method($_) for reverse @vals;
      my $span= $s->span;
      for (reverse @vals) {
         is( $span->$dec_method, $_, "val=$_" );
      }
   };
}

test_encode_decode 'append_asn1_der_length', 'parse_asn1_der_length';
test_encode_decode 'append_base128le', 'parse_base128le';
test_encode_decode 'append_base128be', 'parse_base128be';

subtest lenprefixed => sub {
   my $s= secret;
   my @input= ( secret("Some Data"), secret("Other Data")->span(0,5), "Nonsecret" );
   $s->append_lenprefixed(\@input);
   my @output;
   my $span= $s->span;
   note $s->unmask_to(\&escape_nonprintable);
   is( $span->parse_lenprefixed->memcmp("Some Data"), 0, 'from buffer' );
   is( $span->parse_lenprefixed->memcmp("Other"), 0, 'from span' );
   is( $span->parse_lenprefixed->memcmp("Nonsecret"), 0, 'from scalar' );
   is( $span->len, 0, 'consumed all data' );
};

done_testing;
