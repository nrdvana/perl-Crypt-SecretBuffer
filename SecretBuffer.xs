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
      
      /* If has been exposed as "stringify" sv, update that SV */
      if (buf->stringify_sv) {
         SvPVX(buf->stringify_sv)= buf->data;
         SvCUR(buf->stringify_sv)= buf->len;
      }
   }
}

/* Reallocate the buffer to have at least this many bytes.  This is a request for minimum total
 * capacity, not additional capacity.  If the buffer is already large enough, this does nothing.
 */
void secret_buffer_alloc_at_least(secret_buffer *buf, size_t min_capacity) {
   if (buf->capacity < min_capacity) {
      /* round up to a multiple of 64 */
      secret_buffer_realloc(buf, (min_capacity + 63) & ~(size_t)63);
   }
}

void secret_buffer_copy(secret_buffer *dst, secret_buffer *src) {
   warn("secret_buffer_copy");
   if (src->data && src->capacity) {
      secret_buffer_alloc_at_least(dst, src->len);
      memcpy(dst->data, src->data, src->capacity < dst->capacity? src->capacity : dst->capacity);
      dst->len= src->len;
   } else {
      dst->len= 0;
   }
   if (dst->stringify_sv)
      SvCUR(dst->stringify_sv)= dst->len;
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

/*
 * SecretBuffer_magic_reader
 */

static int
secret_buffer_stringify_magic_get(pTHX_ SV *sv, MAGIC *mg) {
   secret_buffer *buf= (secret_buffer *)mg->mg_ptr;
   warn("secret_buffer_stringify_magic_get %p %p", buf->stringify_sv, sv);
   assert(buf->stringify_sv == sv);
   SvPVX(sv)= buf->data;
   SvCUR(sv)= buf->len;
   SvPOK_on(sv);
   SvUTF8_off(sv);
   SvREADONLY_on(sv);
   return 0;
}

static int
secret_buffer_stringify_magic_set(pTHX_ SV *sv, MAGIC *mg) {
   warn("Attempt to assign stringify scalar");
}

static int
secret_buffer_stringify_magic_free(pTHX_ SV *sv, MAGIC *mg) {
   warn("Freeing stringify scalar");
}

static MGVTBL secret_buffer_stringify_magic_vtbl = {
   secret_buffer_stringify_magic_get,
   secret_buffer_stringify_magic_get,
   NULL, NULL,
   secret_buffer_stringify_magic_free,
   NULL,
   NULL
#ifdef MGf_LOCAL
   ,NULL
#endif
};

SV* secret_buffer_create_stringify_sv(secret_buffer *buf) {
   MAGIC *magic;
   SV *sv;
   warn("secret_buffer_create_stringify_sv");
   assert(buf->stringify_sv == NULL);
   sv= buf->stringify_sv= newSV(0);
   magic= sv_magicext(sv, NULL, PERL_MAGIC_ext, &secret_buffer_stringify_magic_vtbl, (const char *)buf, 0);
   SvPVX(sv)= buf->data;
   SvCUR(sv)= buf->len;
   SvPOK_on(sv);
   SvUTF8_off(sv);
   SvREADONLY_on(sv);
   return sv;
}

/*
 * SecretBuffer Magic
 */

static int secret_buffer_magic_free(pTHX_ SV *sv, MAGIC *mg) {
   secret_buffer *buf= (secret_buffer*) mg->mg_ptr;
   if (buf) {
      secret_buffer_realloc(buf, 0);
      if (buf->stringify_sv)
         sv_2mortal(buf->stringify_sv);
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
#define secret_buffer_magic_dup NULL
#endif

static MGVTBL secret_buffer_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   secret_buffer_magic_free,
   NULL,
   secret_buffer_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};


#define SECRET_BUFFER_MAGIC_AUTOCREATE 1
#define SECRET_BUFFER_MAGIC_OR_DIE     2
#define SECRET_BUFFER_MAGIC_UNDEF_OK   4
secret_buffer* secret_buffer_from_magic(SV *obj, int flags) {
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
      magic = sv_magicext(sv, NULL, PERL_MAGIC_ext, &secret_buffer_magic_vtbl, (const char*) buf, 0);
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
assign(buf, source= NULL)
   auto_secret_buffer buf
   SV *source;
   INIT:
      secret_buffer *peer_buf;
      const char *str;
      STRLEN len;
   PPCODE:
      /* re-initializing? throw away previous value */
      if (buf->data)
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
      RETVAL= buf->len;
   OUTPUT:
      RETVAL

int
read_tty(buf, tty)
   auto_secret_buffer buf
   PerlIO *tty
   INIT:
      int tty_fd= PerlIO_fileno(tty), ch, start_len= buf->len;
      struct termios old, raw;
   CODE:
      if (tty_fd < 0)
         croak("Invalid file descriptor");

      if (tcgetattr(tty_fd, &old) != 0)
         croak("Failed to get terminal settings");
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

      if (buf->len > 0 && buf->data[buf->len-1] == '\r')
         buf->len--;
      RETVAL = buf->len - start_len;
   OUTPUT:
      RETVAL

SV *
stringify(buf, ...)
   auto_secret_buffer buf
   INIT:
      SV **field= hv_fetch((HV*)SvRV(ST(0)), "stringify_mask", 14, 0);
   PPCODE:
      if (!field || !*field) {
         ST(0)= sv_2mortal(newSVpvn("[REDACTED]", 10));
      } else if (SvOK(*field)) {
         ST(0)= *field;
      } else {
         if (!buf->stringify_sv)
            secret_buffer_create_stringify_sv(buf);
         ST(0)= buf->stringify_sv;
      }
      XSRETURN(1);
