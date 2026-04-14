use FindBin;
use lib "$FindBin::Bin/lib";
use Test2AndUtils;
use IO::Handle;
use File::Temp;
use Crypt::SecretBuffer qw(NONBLOCK);

sub check_content {
   my ($buf, $expected, $msg) = @_;
   local $buf->{stringify_mask} = undef;
   is("$buf", $expected, $msg);
}

subtest 'append_sysread basic' => sub {
   my ($r, $w) = pipe_with_data('hello world');
   my $buf = Crypt::SecretBuffer->new;
   my $got = $buf->append_sysread($r, 5);
   is($got, 5, 'read 5 bytes');
   check_content($buf, 'hello', 'buffer has hello');
   $got = $buf->append_sysread($r, 6);
   is($got, 6, 'read remaining bytes');
   check_content($buf, 'hello world', 'all data read');
   close $r; close $w;
};

subtest 'append_sysread EOF' => sub {
   my ($r, $w) = pipe_with_data('abc');
   close $w;
   my $buf = Crypt::SecretBuffer->new;
   my $got = $buf->append_sysread($r, 10);
   is($got, 3, 'only three bytes');
   check_content($buf, 'abc', 'buffer has abc');
   $got = $buf->append_sysread($r, 1);
   is($got, 0, 'zero at EOF');
   close $r;
};

use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC );
subtest 'append sysread timeout' => sub {
   my ($r, $w) = pipe_with_data('abc');
   socketpair(my $crl_r, my $ctl_w, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
      or die "socketpair: $!";
   $ctl_w->autoflush(1);
   $w->autoflush(1);

   my $ppid= $$;
   my $pid= fork or do {
      # child proc.  Wait up to 10 seconds for message from main thread
      # that the test is done, else kill parent prodcess.
      my $rin= '';
      vec($rin, fileno($crl_r), 1)= 1;
      my $n= select(my $rout = $rin, undef, undef, 10);
      if ($n <= 0) {
         # timeout.  stop parent from hanging forever.
         kill TERM => $ppid;
      }
      exit 0;
   };
   my $buf= Crypt::SecretBuffer->new;
   # first read should return immediately
   $buf->append_sysread($r, 10, .1);
   is( $buf->length, 3, 'got first 3 chars from pipe' );
   # second read should block, but then time out after .1 seconds.
   # In case it doesn't, the child will kill us.
   my $ret= $buf->append_sysread($r, 10, .1);
   ok( $!{EINTR}, 'timed out (EINTR)' )
      or note "errno=$!";
   is( $ret, undef, 'returned undef' );
   is( $buf->length, 3, 'buffer unchanged' );
   # inform child that we can exit cleanly
   $ctl_w->print("done");
   waitpid($pid, 0);
};

subtest load_file => sub {
   my $content= "1234"x50;
   my $f= File::Temp->new;
   $f->print($content);
   $f->close;
   my $buf= Crypt::SecretBuffer->new(load_file => "$f");
   check_content($buf, $content);
};

done_testing;

