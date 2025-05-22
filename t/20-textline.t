use FindBin;
use lib "$FindBin::Bin/lib";
use Test2WithExplain;
use Crypt::SecretBuffer qw( secret NONBLOCK );
use IO::Handle;
use File::Temp qw(tempfile);
use POSIX qw(:sys_wait_h);
use Time::HiRes qw( sleep );

sub pipe_with_data {
   my $data= shift;
   pipe(my $read_fh, my $write_fh) or die "Cannot create pipe: $!";
   $write_fh->autoflush(1);
   $write_fh->print($data) if defined $data;
   return ($read_fh, $write_fh);
}

my %escape_to_char= ( "\\" => "\\", r => "\r", n => "\n", t => "\t" );
my %char_to_escape= reverse %escape_to_char;
sub escape_nonprintable {
   my $str= shift;
   $str =~ s/([^\x21-\x7E])/ defined $char_to_escape{$1}? "\\".$char_to_escape{$1} : sprintf("\\x%02X", ord $1) /ge;
   $str;
}
sub unescape_nonprintable {
   my $str= shift;
   $str =~ s/\\(x([0-9A-F]{2})|.)/ defined $2? chr hex $2 : $escape_to_char{$1} /ge;
   $str;
}

# Test normal file handle reading
subtest 'append_console_line with file' => sub {
   my ($fh, $filename) = tempfile();
   print $fh "test data\nmore test data\nwindows newline\r\nline afterward\r\n";
   seek($fh, 0, 0); # Rewind

   my $buf = secret;
   $buf->{stringify_mask}= undef;

   my $result = $buf->append_console_line($fh);
   is($result, T, 'append_console_line returns true for complete line');

   is("$buf", "test data", 'Buffer contains expected data');
   is($buf->length, 9, 'Buffer length is correct');

   # Test reading another line
   $result = $buf->append_console_line($fh);
   ok($result, 'Second append_console_line returns true');

   is("$buf", "test datamore test data", 'Buffer contains appended data');
   is($buf->length, 23, 'Updated buffer length is correct');

   # Test reading with windows line ending
   $result = $buf->clear->append_console_line($fh);
   ok($result, 'Third append_console_line returns true');

   is("$buf", "windows newline", 'Buffer contains appended data');
   is($buf->length, 15, 'Updated buffer length is correct');

   # Test reading following windows line ending
   $result = $buf->append_console_line($fh);
   ok($result, 'Fourth append_console_line returns true');

   is("$buf", "windows newlineline afterward", 'Buffer contains appended data');
   is($buf->length, 29, 'Updated buffer length is correct');

   # Test EOF condition
   $result = $buf->append_console_line($fh);
   is($result, DF, 'append_console_line returns false on EOF');
};

# Test with an in-memory file handle using a reference to a scalar
subtest 'append_console_line with scalar ref handle' => sub {
   my $data = "password\n";
   open my $fh, '<', \$data or die "Cannot open scalar ref: $!";

   my $buf = Crypt::SecretBuffer->new;
   my $result = $buf->append_console_line($fh);
   ok($result, 'append_console_line returns true with scalar ref handle');

   $buf->{stringify_mask} = undef;
   is("$buf", "password", 'Buffer contains expected password');
   is($buf->length, 8, 'Buffer length matches password length');
};

# Test with empty line
subtest 'append_console_line with empty line' => sub {
   my ($r, $w)= pipe_with_data("\n");
   $w->close;

   my $buf = Crypt::SecretBuffer->new;
   my $result = $buf->append_console_line($r);
   ok($result, 'append_console_line returns true with empty line');
   is($buf->length, 0, 'Buffer length is zero for empty line');
};

# Test with no newline
subtest 'append_console_line with no newline' => sub {
   my ($r, $w)= pipe_with_data("incomplete");
   $r->blocking(0);

   my $buf = Crypt::SecretBuffer->new;
   $buf->{stringify_mask} = undef;

   my $result = $buf->append_console_line($r);
   is($result, undef, 'append_console_line returns undef on nonblocking incomplete line');

   is("$buf", "incomplete", 'Buffer contains partial data');
   is($buf->length, 10, 'Buffer length matches input length');
};

subtest 'parent/child pipe communication' => sub {
   my ($read_fh, $write_fh)= pipe_with_data();
   
   my $pid = fork();
   die "Cannot fork: $!" unless defined $pid;
   
   if ($pid == 0) {
      # Child process
      print $write_fh "secret from child process\n";
      exit(0);
   }
   
   # Parent process
   my $buf = Crypt::SecretBuffer->new();
   my $result = $buf->append_console_line($read_fh);
   
   is($result, T, 'append_console_line returns true when reading from child process pipe');
   is($buf->length, 25, 'buffer contains correct number of characters from child process');
   
   $buf->{stringify_mask} = undef;
   is("$buf", 'secret from child process', 'content from child process is correct');
   
   waitpid($pid, 0);
   close($read_fh);
};

# Main test block for TTY functionality
subtest 'TTY functionality' => sub {
   # Skip tests if IO::Pty is not available
   skip_all("IO::Pty required for TTY tests")
      unless eval { require POSIX; require IO::Pty; IO::Pty->new(); 1 };

   sub pack_msg {
      my ($action, $data)= @_;
      $data= "" unless defined $data;
      $action . ' ' . escape_nonprintable($data) . "\n";
   }
   sub unpack_msg {
      my ($action, $data)= ($_[0] =~ /(\S+)\s+(.*)\n/);
      return ($action, unescape_nonprintable($data));
   }

   # Helper function to remote-control a PTY via child process
   sub setup_tty_helper {
      my $code= shift;
      # Create a PTY
      my $pty= IO::Pty->new();
      my $tty= $pty->slave;
      $tty->autoflush(1);
      $pty->autoflush(1);
      # Create pipes for synchronization and data exchange
      pipe(my $parent_read, my $child_write) or die "Cannot create pipe: $!";
      pipe(my $child_read, my $parent_write) or die "Cannot create pipe: $!";
      $parent_write->autoflush(1);
      $child_write->autoflush(1);

      defined(my $pid= fork()) or die "fork: $!";
      if (!$pid) {
         # Child - respond to commands by reading or writing PTY
         eval {
            # Ensure test ends
            local $SIG{ALRM}= sub { die "Child timeout" };
            alarm(10);

            close $parent_read;
            close $parent_write;
            close $tty;

            while (<$child_read>) {
               #warn "# child received command $_";
               my ($action, $data)= unpack_msg($_);
               if ($action eq 'test_echo') {
                  $pty->print("test\r");
                  sysread($pty, my $buffer= "", 4096);
                  warn "# Echo not working: ".escape_nonprintable($buffer)
                     unless $buffer eq "test\r\n";
               }
               elsif ($action eq 'type') {
                  for (split //, $data) {
                     #print "# write ".escape_nonprintable($_)."\n";
                     syswrite($pty, $_) or warn "# syswrite: $!";
                     sleep .05;
                  }
               }
               elsif ($action eq 'sleep') {
                  sleep $data;
               }
               elsif ($action eq 'read_pty') {
                  sysread($pty, my $buffer= "", 4096);
                  #print "# read ".length($buffer)." bytes from pty: ".escape_nonprintable($buffer)."\n";
                  $child_write->print(pack_msg(read => $buffer));
               }
               elsif ($action eq 'exit') {
                  POSIX::exit(0);
               }
            }
         };
         warn "# child error: $@" if defined $@;
         POSIX::exit(2);
      }
      # parent
      else {
         local $SIG{ALRM}= sub { die "parent timeout" };
         alarm 20;

         close $child_read;
         close $child_write;
         close $pty;

         my $send= sub { note "write command: ".pack_msg(@_); $parent_write->print(pack_msg(@_)) };
         my $recv= sub { my $msg= <$parent_read>; note "parent received $msg"; unpack_msg $msg };
         #note "test_echo";
         #$send->('test_echo');
         #note "test_echo output: ".scalar(<$tty>);
         $code->($send, $recv, $tty);
         note "sending exit command";
         $send->('exit');
         note "reaping $pid";
         is( waitpid($pid, 0), $pid, 'reaped tty controller' )
            or kill TERM => $pid;
         note "exited with $?";
         is( $?, 0, 'controller exited successfully' );
         alarm 0;
      }
   }

   # Test 1: Basic TTY input - read until newline
   subtest "input until newline" => sub {
      setup_tty_helper(sub{
         my ($send_msg, $recv_msg, $tty)= @_;
         my $buf= secret();
         $tty->print("Enter Password: ");
         $send_msg->(sleep => .1);
         $send_msg->(type => "password123\r"); # type \r to receive \n on tty
         is( $buf->append_console_line($tty), T, 'received full line' );
         is( $buf->length, 11, 'got 11 chars' );
         is( do { local $buf->{stringify_mask}= undef; "$buf" }, "password123", 'got password' );
         $send_msg->('read_pty');
         is( [ $recv_msg->() ], ['read', "Enter Password: "], 'Saw prompt, and no echo' );
         $send_msg->(type => "x\r");
         $send_msg->(sleep => .1);
         $send_msg->('read_pty');
         is( [ $recv_msg->() ], ['read', "x\r\n"], 'Echo resumed' );
      });
      done_testing;
   };
};

subtest 'PerlIO buffer interaction' => sub {
   my ($read_fh, $write_fh)= pipe_with_data("line one");
   
   my $buf = Crypt::SecretBuffer->new();
   $buf->{stringify_mask} = undef;

   # Trigger perl's internal I/O buffering by reading less than is available on the pipe
   $read_fh->read(my $temp, 5);  # Read "line ", leave "one" in perls buffer

   # write the rest of the line into the pipe
   $write_fh->print("\nline two\n");

   # The getline function will now read "one" from perl's buffer and then "\n" from a sysread
   is($buf->append_console_line($read_fh), T, 'append_console_line got a line');
   is($buf->length, 3, 'buffer->len');
   is("$buf", 'one', 'first line is correct');
};

subtest 'multiple buffers with append_console_line' => sub {
   my ($read_fh, $write_fh)= pipe_with_data("line1\nline2\nline3\n");
   close($write_fh);
   
   my $buf1 = Crypt::SecretBuffer->new();
   my $buf2 = Crypt::SecretBuffer->new();
   my $buf3 = Crypt::SecretBuffer->new();
   
   my $result1 = $buf1->append_console_line($read_fh);
   my $result2 = $buf2->append_console_line($read_fh);
   my $result3 = $buf3->append_console_line($read_fh);
   
   is($result1, T, 'first buffer got true result');
   is($result2, T, 'second buffer got true result');
   is($result3, T, 'third buffer got true result');
   
   {
      local $buf1->{stringify_mask} = undef;
      local $buf2->{stringify_mask} = undef;
      local $buf3->{stringify_mask} = undef;
      
      is("$buf1", 'line1', 'first buffer got first line');
      is("$buf2", 'line2', 'second buffer got second line');
      is("$buf3", 'line3', 'third buffer got third line');
   }
   
   # Try reading when no more lines (should be EOF)
   my $buf4 = Crypt::SecretBuffer->new();
   my $result4 = $buf4->append_console_line($read_fh);
   
   is($result4, DF, 'reading when no more lines returns "EOF"');
   is($buf4->length, 0, 'buffer is empty when EOF reached');
   
   close($read_fh);
};

done_testing;