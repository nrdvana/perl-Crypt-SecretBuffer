#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "SecretBuffer.h"

#include <termios.h>
#include <unistd.h>

/**********************************************************************************************\
* Implementation of SecretBuffer
\**********************************************************************************************/

/* Reallocate (or free) the buffer of secret_buffer, fully erasing it before deallocation.
 * If capacity is zero, the buffer will be freed and 'data' pointer set to NULL.
 * Any other size will allocate exactly that number of bytes, copy any previous bytes,
 * wipe the old buffer, and free it.
 * Note that the entire capacity is copied regardless of 'len', to prevent timing attacks from
 * deducing the exact length of the secret.
 */
void secret_buffer_realloc(secret_buffer *buf, size_t new_capacity) {
   if (buf->capacity != new_capacity) {
      if (new_capacity) {
         char *old= buf->data;
         Newxz(buf->data, new_capacity, char);
         if (old && buf->capacity) {
            memcpy(buf->data, old, new_capacity < buf->capacity? new_capacity : buf->capacity);
            secret_buffer_wipe(old, buf->capacity);
            Safefree(old);
         }
      } else { /* new capacity is zero, so free the buffer */
         if (buf->data && buf->capacity) {
            secret_buffer_wipe(buf->data, buf->capacity);
            Safefree(buf->data);
            buf->data= NULL;
         }
      }
      buf->capacity= new_capacity;
      if (buf->len > buf->capacity)
         buf->len= buf->capacity;
   }
}

/* Reallocate the buffer to have at least this many bytes.  This is a request for minimum total
 * capacity, not additional capacity.  If the buffer is already large enough, this does nothing.
 */
void secret_buffer_alloc_at_least(secret_buffer *buf, size_t min_capacity) {
   if (buf->capacity < min_capacity)
      /* round up to a multiple of 64 */
      secret_buffer_realloc(buf, (min_capacity + 63) & ~(size_t)63);
   }
}

void secret_buffer_copy(secret_buffer *dst, secret_buffer *src) {
   if (src->data && src->capacity) {
      secret_buffer_alloc_at_least(dst, src->len);
      memcpy(dst->data, src->data, src->capacity < dst->capacity? src->capacity : dst->capacity);
      dst->len= src->len;
   } else {
      dst->len= 0;
   }
}

/* This is just exposing the wipe function of this library for general use.
 * It will be OPENSSL_cleanse if openssl (and headers) were available when this package was
 * compiled, or a simple 'explicit_bzero' or 'bzero' otherwise.
 */
void secret_buffer_wipe(char *buf, size_t len) {
#if defined HAVE_EXPLICIT_BZERO
   explicit_bzero(buf, len);
#else
   /* this ought to be sufficient anyway because its within an extern function */
   bzero(buf, len);
#endif
}

#endif

static int secret_buffer_magic_stringify(pTHX_ SV *sv, MAGIC *mg) {
   HV *self= (HV*) mg->mg_obj;
   secret_buffer *buf= (secret_buffer*) mg->mg_ptr;
   SV **mask_sv= hv_fetch(self, "stringify_mask", 14, 0);

   /* Default behavior (mask key doesn't exist): use [REDACTED] */
   if (!mask_sv || !*mask_sv) {
      sv_setpv(sv, "[REDACTED]");
   }
   /* user-supplied stringification mask */
   else if (SvOK(*mask_sv)) {
      sv_setsv(sv, *mask_sv);
   }
   /* undef mask means expose actual secret */
   else {
      sv_setpvn(sv, buf->data, buf->len);
   }
   return 0;
}

static int secret_buffer_magic_free(pTHX_ SV *sv, MAGIC *mg) {
   if (mg->mg_ptr) {
      secret_buffer_realloc((secret_buffer *)mg->mg_ptr, 0);
      Safefree(mg->mg_ptr);
      mg->mg_ptr = NULL;
   }
   return 0;
}

#ifdef USE_ITHREADS
static int secret_bufer_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   secret_buffer *clone, *orig = (secret_buffer *)mg->mg_ptr;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, secret_buffer);
   mg->mg_ptr = (char *)clone;
   secret_buffer_copy(clone, orig);
   return 0;
}
#else
#define cmk_secretbuf_magic_dup NULL
#endif

static MGVTBL secret_buffer_magic_vtbl = {
   secret_buffer_magic_stringify,
   NULL, NULL, NULL,
   cmk_secretbuf_magic_free,
   NULL,
   cmk_secretbuf_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

#define SECRET_BUFFER_MAGIC_AUTOCREATE 1
#define SECRET_BUFFER_MAGIC_OR_DIE     2
#define SECRET_BUFFER_MAGIC_UNDEF_OK   4
secret_buffer* secret_buffer_from_magic(SV *obj, int flags);
   SV *sv;
   MAGIC *magic;
   secret_buffer *buf;

   if ((!obj || !SvOK(obj)) && (flags & SECRET_BUFFER_MAGIC_UNDEF_OK))
      return NULL;

   if (!sv_isobject(obj)) {
      if (flags & SECRET_BUFFER_MAGIC_OR_DIE)
         croak("Not an object");
      return NULL;
   }
   sv = SvRV(obj);
   if (SvMAGICAL(sv) && (magic = mg_findext(sv, PERL_MAGIC_ext, &secret_buffer_magic_vtbl)))
      return (secret_buffer*) magic->mg_ptr;

   if (flags & SECRET_BUFFER_MAGIC_AUTOCREATE) {
      Newxz(buf, 1, secret_buffer);
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, &secret_magic_vt, (const char*) buf, 0);
#ifdef USE_ITHREADS
      magic->mg_flags |= MGf_DUP;
#endif
      return buf;
   }
   if (flags & SECRET_BUFFER_MAGIC_OR_DIE)
      croak("Object lacks 'secret_buffer' magic");
   return NULL;
}

typedef secret_buffer  *auto_secret_buffer;
typedef secret_buffer  *maybe_secret_buffer;

/**********************************************************************************************\
* Crypt::SecretBuffer API
\**********************************************************************************************/
MODULE = Crypt::SecretBuffer                     PACKAGE = Crypt::SecretBuffer

void
assign(buf, source= NULL) {
   auto_secret_buffer buf
   SV *source;
   INIT:
      secret_buffer *peer_buf;
      const char *str;
      STRLEN len;
   PPCODE:
      /* re-initializing? throw away previous value */
      if (buf->cap)
         secret_buffer_realloc(buf, 0);
      if (source) {
         if ((peer_buf= secret_buffer_from_magic(source, 0))) {
            secret_buffer_copy(buf, peer_buf);
         }
         else if (!SvROK(source)) {
            str= SvPVbyte(source, len);
            if (len) {
               secret_buffer_alloc_at_least(buf, len);
               memcpy(buf->data, str, len);
               buf->len = len;
            }
         }
         else {
            croak("Don't know how to copy data from %s", SvPV_nolen(source));
         }
      }

UV
length(buf)
   auto_secret_buffer buf
   CODE:
      RETVAL= buf->len
   OUTPUT:
      RETVAL

int
read_tty(buf, tty) {
   auto_secret_buffer buf
   PerlIO *tty
   INIT:
      int tty_fd= PerlIO_fileno(tty), ch, start_len= buf->len;
      struct termios old, raw;
   PPCODE:
      if (tty_fd < 0)
         croak("Invalid file descriptor");

      if (tcgetattr(tty_fd, &old) != 0)
         croak("Failed to get terminal settings: %s");
      raw = old;
      raw.c_lflag &= ~ECHO;
      if (tcsetattr(tty_fd, TCSAFLUSH, &raw) != 0) // disable echo
         croak("Failed to disable echo");

      /* Read line using PerlIO_getc, so that we have control over buffer allocations */
      while ((ch = PerlIO_getc(tty)) != EOF && ch != '\n') {
         if (buf->len + 1 >= buf->capacity)
            secret_buffer_alloc_at_least(buf, buf->len + 1);
         buf->data[buf->len++] = (char)ch;
      }

      tcsetattr(tty_fd, TCSAFLUSH, &old);  // restore echo

      str= SvPV(tmpsv, len);
      if (buf->len > 0 && buf->data[buf->len-1] == '\r')
         buf->len--;
      RETVAL = buf->len - start_len;
   OUTPUT:
      RETVAL

