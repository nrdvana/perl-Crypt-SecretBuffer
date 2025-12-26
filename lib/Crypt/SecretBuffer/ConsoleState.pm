package Crypt::SecretBuffer::ConsoleState;
# VERSION
# ABSTRACT: Disable TTY echo within a block scope

1;
__END__

=head1 DESCRIPTION

This object provides a cross-platform way to inspect the TTY echo flag on Unix or the Console
echo flag on Windows, disable echo, and restore it on scope end.

=constructor maybe_new

Return a new object which caches the state of the provided file handle.  If the handle is not
a console/tty, this returns C<undef>.

=constructor maybe_scope_guard

Returns a new object like L<maybe_new> and automatically sets L</auto_restore> so that it calls
L</restore> when the object goes out of scope.

=constructor maybe_scope_guard_if_disable_echo

Like L</maybe_scope_guard> but also return C<undef> if the echo is already disabled on the
console/tty.  This is the most efficient approach for disabling echo because nothing gets
created if it isn't a console or echo is already disabled.

=attribute auto_restore

Automatically call C<restore> on object destruction (such as when it goes out of scope)

=attribute echo

Get or set the ECHO flag on the console/tty.

=method restore

Set the console/tty state to the original value seen when the object was created.

=cut

