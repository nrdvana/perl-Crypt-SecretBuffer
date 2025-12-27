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

Get or set the ECHO flag on the console/tty.
Boolean, read/write.

=method restore

Set the console/tty state to the original value seen when the object was created.

=cut

