use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use Crypt::SecretBuffer qw(secret);

my $buf = Crypt::SecretBuffer->new("abc123\0abc456");

subtest index_char => sub {
   is($buf->index('abc'), 0, 'find first substring');
   is($buf->index('123'), 3, 'find middle substring');
   is($buf->index("\0"), 6, 'find middle substring');
   is($buf->index("\0", 6), 6, 'find NUL byte');
   is($buf->index('abc', 4), 7, 'find substring after offset');
   is($buf->index('nope'), -1, 'return -1 when not found');
   is($buf->index('abc', -4), -1, 'negative offset beyond substring');
   is($buf->index("6", $buf->length-1), $buf->length-1, 'find last byte starting from last byte');
   is($buf->index("6", -1), $buf->length-1, 'find last byte using negative index');
};

sub _render_char {
   $_[0] >= 0x21 && $_[0] <= 0x7E? chr $_[0] : sprintf("\\x%02X", $_[0])
}
sub bitmap_to_chars {
   my $str= '';
   my $range_start= -1;
   for (0..0x100) {
      if (vec($_[0], $_, 1)) {
         if ($range_start < 0) {
            $range_start= $_;
            $str .= _render_char($_);
         }
      } elsif ($range_start >= 0) {
         my $ofs= $_ - $range_start;
         $str .= '-' if $ofs > 2;
         $str .= _render_char($_ - 1) if $ofs > 1;
         $range_start= -1;
      }
   }
   return $str;
}

subtest charset => sub {
   # tests below use \x{100} to force perl-interpretation of a regex
   # as a baseline to compare the parsed bitmap to the perl-generated one.
   my $uni_literal= "\x{1000}";
   my @tests= (
      [ qr/[a-z]/                      => 'a-z', 0 ],
      [ qr/[a-z]/i                     => 'A-Za-z', 0 ],
      [ qr/[a-z 5\x{100}]/ixx          => '5A-Za-z', 2 ],
      [ qr/[a-z 5]/ixx                 => '5A-Za-z', 0 ],
      [ qr/[\0-\108\7777-9]/           => '\x00-\x087-9', 2 ],
      [ qr/[\t\r\n]/                   => '\x09\x0A\x0D', 0 ],
      [ qr/[[:alpha:]]/                => 'A-Za-z', 2 ],
      [ qr/[\x00-\e]/                  => '\x00-\x1B', 0 ],
      [ qr/[$uni_literal]/             => '', 2 ],
   );
   for (@tests) {
      my ($re, $ranges, $above7F)= @$_;
      my $cset= Crypt::SecretBuffer::Exports::_debug_charset($re);
      $cset->{bitmap}= bitmap_to_chars($cset->{bitmap});
      is( $cset, { bitmap => $ranges, unicode_above_7F => $above7F }, "$re" );
   }
};

done_testing;

