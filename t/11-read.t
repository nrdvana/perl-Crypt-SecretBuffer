#!/usr/bin/env perl
use FindBin;
use lib "$FindBin::Bin/lib";
use Test2WithExplain;
use IO::Handle;
use Crypt::SecretBuffer qw(FULLCOUNT NONBLOCK);
use Fcntl qw(:DEFAULT);
use Errno qw(EAGAIN);
use Time::HiRes 'sleep';

# Helper function to create a pipe with optional data
sub pipe_with_data {
   my $data = shift;
   pipe(my $read_fh, my $write_fh) or die "Cannot create pipe: $!";
   $write_fh->autoflush(1);
   $write_fh->print($data) if defined $data;
   return ($read_fh, $write_fh);
}

# Test basic append_read functionality
subtest 'Basic append_read' => sub {
   my ($r, $w) = pipe_with_data("test data");
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   my $bytes_read = $buf->append_read($r, 4);
   is($bytes_read, 4, 'Read 4 bytes');
   is("$buf", "test", 'Buffer contains first 4 bytes');
   
   $bytes_read = $buf->append_read($r, 6);
   is($bytes_read, 5, 'Read 5 more bytes (all available)');
   is("$buf", "test data", 'Buffer contains all data');
   
   close($r);
   close($w);
};

# Test append_read with EOF
subtest 'append_read with EOF' => sub {
   my ($r, $w) = pipe_with_data("test");
   close($w);  # Close write end to simulate EOF
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   my $bytes_read = $buf->append_read($r, 10);
   is($bytes_read, 4, 'Read only 4 bytes before EOF');
   is("$buf", "test", 'Buffer contains all available data');
   
   $bytes_read = $buf->append_read($r, 1);
   is($bytes_read, 0, 'Read 0 bytes at EOF');
   is("$buf", "test", 'Buffer unchanged at EOF');
   
   close($r);
};

# Test append_read with NONBLOCK flag
subtest 'append_read with NONBLOCK' => sub {
   my ($r, $w) = pipe_with_data("test");
   $r->blocking(0);  # Set to non-blocking mode
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   my $bytes_read = $buf->append_read($r, 4, NONBLOCK);
   is($bytes_read, 4, 'Read 4 bytes in non-blocking mode');
   is("$buf", "test", 'Buffer contains expected data');
   
   # Now there's nothing more to read, but the pipe is still open
   $bytes_read = $buf->append_read($r, 4, NONBLOCK);
   
   # If no data available, should get EAGAIN (but specific behavior might vary by OS)
   if ($bytes_read == -1 && $! == EAGAIN) {
      pass('Got expected EAGAIN in non-blocking mode');
   } elsif ($bytes_read == 0) {
      pass('Got 0 bytes in non-blocking mode with no data available');
   } else {
      fail("Unexpected result in non-blocking mode: $bytes_read bytes, errno=$!");
   }
   
   close($r);
   close($w);
};

# Test append_read with FULLCOUNT flag
subtest 'append_read with FULLCOUNT' => sub {
   # Use a larger buffer to simulate multiple reads
   my ($r, $w) = pipe_with_data("test data more data");
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   # Should read all 10 bytes even if sysread returns less
   my $bytes_read = $buf->append_read($r, 10, FULLCOUNT);
   is($bytes_read, 10, 'Read full requested count with FULLCOUNT flag');
   is("$buf", "test data ", 'Buffer contains exactly 10 bytes');
   
   # Write more data while reading
   my $ppid = $$;
   if (my $pid = fork()) {
      # Parent process
      # Should block until child writes enough data
      $bytes_read = $buf->append_read($r, 14, FULLCOUNT);
      is($bytes_read, 14, 'Read full 14 bytes with FULLCOUNT, waiting for data');
      is("$buf", "test data more data more", 'Buffer contains all expected data');
      
      # Clean up
      waitpid($pid, 0);
   } else {
      # Child process
      # Wait to ensure parent is blocking
      if ($^O eq 'Win32') {
         sleep 2;
      } else {
         my $in= '';
         vec($in, fileno($r), 1)= 1;
         while (scalar select($in, undef, undef, .1)) { sleep .1; }
      }
      $w->print(" more");
      close($w);
      exit(0);
   }
   
   close($r);
   close($w);
};

# Test appending to existing buffer
subtest 'Append to existing buffer' => sub {
   my ($r, $w) = pipe_with_data("more data");
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   # Pre-fill buffer with data
   $buf->length(5);  # Initialize with 5 random bytes
   my $initial_length = $buf->length;
   my $initial_content = "$buf";
   
   my $bytes_read = $buf->append_read($r, 9);
   is($bytes_read, 9, 'Read 9 bytes');
   is($buf->length, $initial_length + 9, 'Buffer length increased correctly');
   like("$buf", qr/^$initial_content/, 'Original buffer content preserved');
   like("$buf", qr/more data$/, 'New data appended correctly');
   
   close($r);
   close($w);
};

# Test reading zero bytes
subtest 'Read zero bytes' => sub {
   my ($r, $w) = pipe_with_data("data");
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   my $bytes_read = $buf->append_read($r, 0);
   is($bytes_read, 0, 'Reading 0 bytes returns 0');
   is("$buf", "", 'Buffer remains empty');
   
   close($r);
   close($w);
};

# Test partial read with FULLCOUNT
subtest 'Partial read with FULLCOUNT' => sub {
   my ($r, $w) = pipe_with_data("partial");
   
   my $buf = Crypt::SecretBuffer->new;
   local $buf->{stringify_mask} = undef;
   
   close($w);  # Close write end to force EOF
   
   # Should try to read 10 bytes but only get 7 due to EOF
   my $bytes_read = $buf->append_read($r, 10, FULLCOUNT);
   is($bytes_read, 7, 'FULLCOUNT returns actual bytes on EOF');
   is("$buf", "partial", 'Buffer contains all available data');
   
   close($r);
};

done_testing;