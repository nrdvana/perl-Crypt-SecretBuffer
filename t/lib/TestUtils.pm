package TestUtils;
use strict;
use warnings;
use Exporter 'import';
use IO::Handle;
use IO::Pty;
use POSIX qw(:sys_wait_h);
use Time::HiRes 'sleep';

our @EXPORT = qw(pipe_with_data escape_nonprintable unescape_nonprintable pack_msg unpack_msg setup_tty_helper);

sub pipe_with_data {
    my $data = shift;
    pipe(my $r, my $w) or die "Cannot create pipe: $!";
    $w->autoflush(1);
    $w->print($data) if defined $data;
    return ($r, $w);
}

my %escape_to_char = ( "\\" => "\\", r => "\r", n => "\n", t => "\t" );
my %char_to_escape = reverse %escape_to_char;

sub escape_nonprintable {
    my $str = shift;
    $str =~ s/([^\x21-\x7E])/ defined $char_to_escape{$1}? "\\".$char_to_escape{$1} : sprintf("\\x%02X", ord $1) /ge;
    return $str;
}

sub unescape_nonprintable {
    my $str = shift;
    $str =~ s/\\(x([0-9A-F]{2})|.)/ defined $2? chr hex $2 : $escape_to_char{$1} /ge;
    return $str;
}

sub pack_msg {
    my ($action, $data) = @_;
    $data = '' unless defined $data;
    return $action . ' ' . escape_nonprintable($data) . "\n";
}

sub unpack_msg {
    my ($action, $data) = ($_[0] =~ /(\S+)\s+(.*)\n/);
    return ($action, unescape_nonprintable($data));
}

sub setup_tty_helper {
    my $code = shift;
    my $pty = IO::Pty->new;
    my $tty = $pty->slave;
    $tty->autoflush(1);
    $pty->autoflush(1);
    pipe(my $parent_read, my $child_write) or die "Cannot create pipe: $!";
    pipe(my $child_read, my $parent_write) or die "Cannot create pipe: $!";
    $parent_write->autoflush(1);
    $child_write->autoflush(1);

    defined(my $pid = fork()) or die "fork: $!";
    if (!$pid) {
        eval {
            local $SIG{ALRM} = sub { die "Child timeout" };
            alarm(10);
            close $parent_read;
            close $parent_write;
            close $tty;
            while (<$child_read>) {
                my ($action, $data) = unpack_msg($_);
                if ($action eq 'test_echo') {
                    $pty->print("test\r");
                    sysread($pty, my $buffer = '', 4096);
                    warn "# Echo not working: " . escape_nonprintable($buffer)
                        unless $buffer eq "test\r\n";
                } elsif ($action eq 'type') {
                    for (split //, $data) {
                        syswrite($pty, $_) or warn "# syswrite: $!";
                        sleep 0.05;
                    }
                } elsif ($action eq 'sleep') {
                    sleep $data;
                } elsif ($action eq 'read_pty') {
                    sysread($pty, my $buffer = '', 4096);
                    $child_write->print(pack_msg(read => $buffer));
                } elsif ($action eq 'exit') {
                    POSIX::_exit(0);
                }
            }
        };
        warn "# child error: $@" if $@;
        POSIX::_exit(2);
    } else {
        local $SIG{ALRM} = sub { die "parent timeout" };
        alarm 20;
        close $child_read;
        close $child_write;
        close $pty;
        my $send = sub { $parent_write->print(pack_msg(@_)) };
        my $recv = sub { my $msg = <$parent_read>; unpack_msg $msg };
        $code->($send, $recv, $tty);
        $send->('exit');
        waitpid($pid, 0);
        alarm 0;
    }
}

1;
