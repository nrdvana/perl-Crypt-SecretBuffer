use FindBin;
use lib "$FindBin::Bin/lib";
use Test2WithExplain;
use IO::Handle;
use Crypt::SecretBuffer qw(FULLCOUNT NONBLOCK);
use TestUtils 'pipe_with_data';

sub check { my ($buf,$exp,$msg)=@_; local $buf->{stringify_mask}=undef; is("$buf",$exp,$msg) }

subtest 'append_read basic' => sub {
    my ($r,$w)= pipe_with_data('hello');
    my $buf = Crypt::SecretBuffer->new;
    my $n = $buf->append_read($r,5);
    is($n,5,'read all');
    check($buf,'hello','content');
    close $r; close $w;
};

subtest 'append_read FULLCOUNT' => sub {
    my ($r,$w)= pipe_with_data('abc');
    my $buf = Crypt::SecretBuffer->new;
    my $n = $buf->append_read($r,5,FULLCOUNT);
    is($n,3,'only available bytes');
    check($buf,'abc','got data');
    close $r;
};

subtest 'append_read NONBLOCK' => sub {
    my ($r,$w)= pipe_with_data('x');
    $r->blocking(0);
    my $buf = Crypt::SecretBuffer->new;
    my $n = $buf->append_read($r,1,NONBLOCK);
    ok($n==1,'one byte');
    $n = $buf->append_read($r,1,NONBLOCK);
    ok($n==0 || ($n==-1 && $!{EAGAIN}), 'no data available');
    close $r; close $w;
};

done_testing;

