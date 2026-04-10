package Crypt::SecretBuffer::ConsoleState;
# VERSION
# ABSTRACT: Disable TTY echo within a scope

1;
__END__

=head1 DESCRIPTION

This object provides a cross-platform way to inspect the TTY echo flag on Unix or the Console
echo flag on Windows, disable echo, and restore it on scope end.

=constructor new

  $console_state= Crypt::SecretBuffer::ConsoleState->new($handle);
  $console_state= Crypt::SecretBuffer::ConsoleState->new(%options);

Return a new object which caches the console/tty state of the provided file handle.
If the handle is not a console/tty, this dies.

Options:

  handle        => $fh,
  auto_restore  => $bool
  echo          => $bool
  line_input    => $bool

=constructor maybe_new

  $console_state= Crypt::SecretBuffer::ConsoleState->maybe_new($handle);
  $console_state= Crypt::SecretBuffer::ConsoleState->maybe_new(%options);

Return a new object B<unless> the C<$handle> is not a console/tty, or if you request an echo
state and the console/tty is already in that state.  In other words, instead of writing

  my $st= eval { Crypt::SecretBuffer::ConsoleState->new($handle) };
  if ($st && $st->echo) {
    $st->echo(0);
    $st->auto_restore(1);
  }

you can write

  my $scope_guard= Crypt::SecretBuffer::ConsoleState->maybe_new(
    handle => $fh,
    auto_restore => 1,
    echo => 0
  );

and if it is not a tty or echo is already off, it returns C<undef> and skips the creation of
the object entirely.

=attribute auto_restore

Automatically call C<restore> on object destruction, such as when it goes out of scope.
Boolean, read/write.

=attribute echo

Get or set the C<ECHO> flag on the console/tty.
Boolean, read/write.

=attribute line_input

Get or set the line-buffering feature of the console/tty.  On Windows this is the
C<ENABLE_LINE_INPUT> flag.  On Posix, this is the C<ICANON> flag, with the caveat that disabling
it also enables the C<ISIG> flag so that the OS continues to handle C<^C> for you.
Boolean, read/write.

=method restore

Set the console/tty state to the original value seen when the object was created.

=method wait_char_readable

  $bool= $console_state->wait_char_readable;
  $bool= $console_state->wait_char_readable($timeout_seconds);

Wait until a character is available to be read from the console/tty represented by this object.

If C<$timeout_seconds> is omitted or undef, waits indefinitely.
Returns true if a character is ready, or false if the timeout expires first.

On Windows, this filters out console events that do not produce a character, such as
modifier-only key presses, mouse events, and window resize events.  When using this as a test
before C<< $secret_buffer->append_sysread($fh, 1) >> beware that in the Windows codepage
65001 (UTF-8) one readable char can be returned as multiple bytes, so either request a larger
read, or check the code page and UTF-8 nature of the bytes received.

=cut

