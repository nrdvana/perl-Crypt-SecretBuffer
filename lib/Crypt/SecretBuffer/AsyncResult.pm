package Crypt::SecretBuffer::AsyncResult;
#ABSTRACT: Observe results of a write_async operation
#VERSION
1;
__END__

=head1 DESCRIPTION

This object holds a reference to a background write operation started by L<Crypt::SecretBuffer::write_async>.
There is only one method currently:

=method wait

  if (($bytes_written, $os_error)= $result->wait($seconds_or_undef)) {
   ...
  }

This waits up to C<$seconds> (or indefinitely if you pass undef) for the write operation to
complete, then if it has completed, returns the number of bytes written, and the OS error code,
if any.

=cut

