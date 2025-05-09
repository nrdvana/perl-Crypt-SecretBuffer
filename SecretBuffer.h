#ifndef CRYPT_SECRETBUFFER_H

typedef struct {
   char *data;
   size_t len, capacity;
} secret_buffer;

/* Reallocate (or free) the buffer of secret_buffer, fully erasing it before deallocation.
 * If capacity is zero, the buffer will be freed and 'data' pointer set to NULL.
 * Any other size will allocate exactly that number of bytes, copy any previous bytes,
 * wipe the old buffer, and free it.
 */
extern void secret_buffer_reallic(secret_buffer *buf, size_t new_capacity);

/* Reallocate the buffer to have at least this many bytes.  This is a request for minimum total
 * capacity, not additional capacity.  If the buffer is already large enough, this does nothing.
 */
extern void secret_buffer_alloc_at_least(secret_buffer *buf, size_t min_capacity);

/* This is just exposing the wipe function of this library for general use.
 * It will be OPENSSL_cleanse if openssl (and headers) were available when this package was
 * compiled, or a simple 'explicit_bzero' or 'bzero' otherwise.
 */
extern void secret_buffer_wipe(char *buf, size_t len);

#define SECRET_BUFFER_MAGIC_AUTOCREATE 1
#define SECRET_BUFFER_MAGIC_OR_DIE     2
#define SECRET_BUFFER_MAGIC_UNDEF_OK   4
extern secret_buffer* secret_buffer_from_magic(SV *obj, int flags);

#endif
