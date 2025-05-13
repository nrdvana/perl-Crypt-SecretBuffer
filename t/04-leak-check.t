use Test2::V0;
use Crypt::SecretBuffer qw( secret );

skip_all 'Require /proc/self/maps for this test'
   unless -r '/proc/self/maps';

sub count_copies_in_mem {
   my $buf= shift;
   my $map_spec= do { local $/; open my $fh, '</proc/self/maps'; <$fh> };
   my $n= 0;
   while ($map_spec =~ /^([0-9a-f]+)-([0-9a-f]+) r/mg) {
      my ($start, $lim)= (hex $1, hex $2);
      $n += $buf->_count_matches_in_mem($start, $lim-$start);
   }
   return $n;
}

my $buf= secret(length => 64); # random bytes
is( count_copies_in_mem($buf), 1 );

my $clone= secret($buf);
is( count_copies_in_mem($buf), 2 );

my $clone2= secret($buf);
is( count_copies_in_mem($buf), 3 );

undef $clone;
$clone2->clear;
is( count_copies_in_mem($buf), 1 );

done_testing;
