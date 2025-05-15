#ifndef CRYPT_SECRETBUFFER_H

typedef struct {
   char *data;
   size_t len, capacity;
   SV *stringify_sv;
} secret_buffer;

#define SECRET_BUFFER_NONBLOCK  1
#define SECRET_BUFFER_FULLCOUNT 2

/* Reallocate (or free) the buffer of secret_buffer, fully erasing it before deallocation.
 * If capacity is zero, the buffer will be freed and 'data' pointer set to NULL.
 * Any other size will allocate exactly that number of bytes, copy any previous bytes,
 * wipe the old buffer, and free it.
 */
extern void secret_buffer_realloc(secret_buffer *buf, size_t new_capacity);

/* Reallocate the buffer to have at least this many bytes.  This is a request for minimum total
 * capacity, not additional capacity.  If the buffer is already large enough, this does nothing.
 */
extern void secret_buffer_alloc_at_least(secret_buffer *buf, size_t min_capacity);

/* This is just exposing the wipe function of this library for general use.
 * It will be one of `explicit_bzero`, `SecureZeroMemory`, or just `bzero` which should
 * be fine since it's in an extern function..
 */
extern void secret_buffer_wipe(char *buf, size_t len);

/* Append N bytes of cryptographic quality random bytes to the end of the buffer.
 * This may block if your entropy pool is low.
 * If you request the flag 'NONBLOCK' it performs a non-blocking read.
 * If you request the flag 'FULLCOUNT' it repeatedly runs blocking reads until it reaches the
 * desired count.
 */
extern size_t secret_buffer_append_random(secret_buffer *buf, size_t n, unsigned flags);

/* Append one line of text from a TTY after disabling echo, not including the terminating
 * newline character.  If max_chars is non-negative, this will stop after reading that
 * many characters (bytes) before the end of line is seen.  This is useful for things like
 * prompting a user for an exact number of digits without making them hit 'Enter'.
 */
extern size_t secret_buffer_append_tty_line(secret_buffer *buf, PerlIO *tty, int max_chars, unsigned flags);

/* Append 'count' bytes from a file, skipping application buffering.
 * This can be useful when you want to read from a sensitive file without loading it
 * generically into perl scalars.
 */
extern size_t secret_buffer_append_sysread(secret_buffer *buf, PerlIO *fh, size_t count, unsigned flags);

/* Write a segment of this buffer into the supplied file handle.
 * If SECRET_BUFFER_NONBLOCK flag is requested, this writes only as much as one syscall can fit
 * into the pipe (or handle, or socket, etc).
 * If SECRET_BUFFER_FULLCOUNT flag is requested, this continues looping as long as it doesn't
 * get an error until the full requested 'count' is written.
 * If you specify both NONBLOCK and FULLCOUNT flags, and the first write does not deliver the
 * full count, then this forks off a thread to continue pumping data into the pipe.
 * On Win32, you get a thread instead of a fork().
 */
extern size_t secret_buffer_syswrite(secret_buffer *buf, PerlIO *fh, size_t offset, size_t count, unsigned flags);

/* Return a magical SV which exposes the secret buffer.
 * This should be used sparingly, if at all, for interoperating with perl code that isn't
 * aware of SecretBuffer and can't be fed the secret any other way.  Beware that the secret
 * may "get loose" unintentionally when allowing Perl to read the value as an SV.
 */
extern SV* secret_buffer_get_stringify_sv(secret_buffer *buf);

/* Given a SV which you expect to be a reference to a blessed object with SecretBuffer
 * magic, return the secret_buffer struct pointer.
 * With no flags, this returns NULL is any of the above assumption is not correct.
 * Specify AUTOCREATE to create a new secret_buffer (and attach with magic) if it is a blessed
 * object and doesn't have the magic yet.
 * Specify OR_DIE if you want an exception instead of NULL return value.
 * Specify UNDEF_OK if you want input C<undef> to translate to C<NULL> even when OR_DIE is
 * requested.
 */
#define SECRET_BUFFER_MAGIC_AUTOCREATE 1
#define SECRET_BUFFER_MAGIC_OR_DIE     2
#define SECRET_BUFFER_MAGIC_UNDEF_OK   4
extern secret_buffer* secret_buffer_from_magic(SV *obj, int flags);

/* Create a new Crypt::SecretBuffer object with a mortal ref and return the secret_buffer.
 * If ref_out is NULL then the mortal ref remains mortal and the buffer is freed at the next
 * FREETMPS as your function exits.  If you supply a pointer to receive ref_out, you can then
 * increment the refcount or copy the ref if you want to keep the object.
 * Always returns a secret_buffer, or croaks on failure.
 */
extern secret_buffer* secret_buffer_new(size_t capacity, SV **ref_out);

#endif
