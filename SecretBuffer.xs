#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "SecretBuffer.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#if HAVE_LIBSSL
#include <openssl/rand.h>
#include <openssl/crypto.h>
#endif

#if HAVE_GETRANDOM
#include <sys/random.h>
#endif

/**********************************************************************************************\
* MAGIC vtables
\**********************************************************************************************/

#ifdef USE_ITHREADS
static int secret_bufer_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param);
static int secret_buffer_stringify_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *params);
#else
#define secret_buffer_magic_dup NULL
#define secret_buffer_stringify_magic_dup NULL
#endif

static int secret_buffer_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL secret_buffer_magic_vtbl = {
   NULL, NULL, NULL, NULL,
   secret_buffer_magic_free,
   NULL,
   secret_buffer_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

static int secret_buffer_stringify_magic_get(pTHX_ SV *sv, MAGIC *mg);
static int secret_buffer_stringify_magic_set(pTHX_ SV *sv, MAGIC *mg);
static int secret_buffer_stringify_magic_free(pTHX_ SV *sv, MAGIC *mg);
static MGVTBL secret_buffer_stringify_magic_vtbl = {
   secret_buffer_stringify_magic_get,
   secret_buffer_stringify_magic_get,
   NULL, NULL,
   secret_buffer_stringify_magic_free,
   NULL,
   secret_buffer_stringify_magic_dup
#ifdef MGf_LOCAL
   ,NULL
#endif
};

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
#if defined HAVE_LIBSSL
   OPENSSL_cleanse(buf, len);
#elif defined HAVE_EXPLICIT_BZERO
   explicit_bzero(buf, len);
#else
   /* this ought to be sufficient anyway because its within an extern function */
   bzero(buf, len);
#endif
}

size_t secret_buffer_append_random(secret_buffer *buf, size_t n, unsigned flags) {
   size_t orig_len= buf->len;
   char *dest;
   IV got;
   int fd;

   if (!n)
      return 0;
   if (buf->capacity < buf->len + n)
      secret_buffer_alloc_at_least(buf, buf->len + n);
   dest= buf->data + buf->len;
#if defined HAVE_GETRANDOM
   got= getrandom(dest, n, GRND_RANDOM | (flags & SECRET_BUFFER_APPEND_NONBLOCK? GRND_NONBLOCK : 0));
   if (got < 0) {
      if (errno != EAGAIN)
         croak("getrandom() failed");
      got= 0;
   }
   buf->len += got;
#else
   fd= open("/dev/random", O_RDONLY | (flags & SECRET_BUFFER_APPEND_NONBLOCK? O_NONBLOCK : 0));
   if (fd < 0) croak("Failed opening /dev/random");
   while (n > 0) {
      got= read(fd, dest, n);
      if (got <= 0) {
         if (errno != EAGAIN)
            close(fd), croak("Failed to read from /dev/random");
      }
      else {
         dest += got;
         buf->len += got;
         n -= got;
      }
      if (!(flags & SECRET_BUFFER_APPEND_FULLCOUNT))
         break;
   }
   close(fd);
#endif
   return buf->len - orig_len;
}

size_t secret_buffer_append_tty_line(secret_buffer *buf, PerlIO *tty, int max_chars, unsigned flags) {
   size_t orig_len = buf->len;
   int tty_fd = PerlIO_fileno(tty), ch;
   struct termios old, raw;
   
   if (tty_fd < 0)
      croak("Invalid file descriptor");

   if (tcgetattr(tty_fd, &old) != 0)
      croak("Failed to get terminal settings");
   raw = old;
   raw.c_lflag &= ~ECHO;
   if (tcsetattr(tty_fd, TCSAFLUSH, &raw) != 0) // disable echo
      croak("Failed to disable echo");

   /* Read line using PerlIO_getc, so that we have control over buffer allocations */
   while (max_chars != 0 && (ch = PerlIO_getc(tty)) != EOF && ch != '\n' && ch != '\r') {
      if (buf->capacity < buf->len + 1)
         secret_buffer_alloc_at_least(buf, buf->len + 1);
      buf->data[buf->len++] = (char)ch;
      if (max_chars > 0)
         --max_chars;
   }

   tcsetattr(tty_fd, TCSAFLUSH, &old);  // restore echo
   
   return buf->len - orig_len;  // Return number of bytes read
}

size_t secret_buffer_append_sysread(secret_buffer *buf, PerlIO *fh, size_t count, unsigned flags) {
   size_t orig_len = buf->len;
   int fd = PerlIO_fileno(fh);
   ssize_t got;
   char *dest;
   
   if (fd < 0)
      croak("Invalid file descriptor");
      
   if (!count)
      return 0;
   
   /* Ensure we have enough space in the buffer */
   if (buf->capacity < buf->len + count)
      secret_buffer_alloc_at_least(buf, buf->len + count);
   
   dest = buf->data + buf->len;
   
   /* Read directly using recv with MSG_DONTWAIT */
   while (count > 0) {
      got = recv(fd, dest, count, 
                 (flags & SECRET_BUFFER_APPEND_NONBLOCK) ? MSG_DONTWAIT : 0);
      
      if (got > 0) {
         dest += got;
         buf->len += got;
         count -= got;
      } 
      else if (got == 0
         || ((errno == EAGAIN || errno == EWOULDBLOCK) && (flags & SECRET_BUFFER_APPEND_NONBLOCK))
      ) {
         /* End of file, or end of available bytes in nonblocking mode */
         break;
      }
      else
         croak("Failed to read from file: %s", strerror(errno));
      
      /* If not in FULLCOUNT mode, exit after first read attempt */
      if (!(flags & SECRET_BUFFER_APPEND_FULLCOUNT))
         break;
   }
   
   return buf->len - orig_len;  // Return number of bytes read
}

SV* secret_buffer_as_pipe(secret_buffer *buf) {
   int pipefd[2] = { -1, -1 };
   pid_t pid;
   ssize_t written;
   const char *err = NULL;
   SV *fh = NULL;
   PerlIO *pio = NULL, *old_io= NULL;
   GV *gv;
   
   /* Create the pipe */
   if (pipe(pipefd) == -1) {
      err = "Failed to create pipe";
      goto cleanup;
   }
   
   /* Get and set non-blocking mode */
   int flags = fcntl(pipefd[1], F_GETFL);
   if (flags == -1) {
      err = "Failed to get pipe write end flags";
      goto cleanup;
   }
   
   if (fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK) == -1) {
      err = "Failed to set non-blocking mode on pipe write end";
      goto cleanup;
   }
   
   /* Attempt to write buffer */
   written = write(pipefd[1], buf->data, buf->len);
   if (written < 0) {
      err = "Unexpected error writing to pipe";
      goto cleanup;
   }
   
   /* Check if a full write didn't occur */
   if (written < buf->len) {
      /* Entire buffer fit in pipe, close write end */
      close(pipefd[1]);
   }
   else {
      /* Need to fork to complete writing */
      pid = fork();
      
      if (pid < 0) {
         err = "Failed to fork pipe writer";
         goto cleanup;
      }
      
      if (pid == 0) {
         /* Child process */
         size_t total_written = written;

         close(pipefd[0]);  /* Close read end in child */
         
         /* Set blocking mode */
         if (fcntl(pipefd[1], F_SETFL, flags) == -1) {
            warn("Failed to set blocking mode on pipe write end");
            exit(1);
         }
         
         /* Write remaining buffer */
         while (total_written < buf->len) {
            ssize_t chunk_written = write(pipefd[1], buf->data + total_written, buf->len - total_written);
            
            if (chunk_written < 0) {
               if (errno == EPIPE) {
                     /* Reader closed, just exit */
                     exit(0);
               }
               warn("Error writing to pipe: %s", strerror(errno));
               exit(1);
            }
            
            total_written += chunk_written;
         }
         
         close(pipefd[1]);
         exit(0);
      }
      
      /* Parent process continues */
      close(pipefd[1]);
      pipefd[1] = -1;
   }
   
   /* Create a Perl filehandle for the pipe read end */
   pio = PerlIO_fdopen(pipefd[0], "r");
   if (!pio) {
      close(pipefd[0]);
      croak("Failed to create Perl file handle for pipe");
   }
   gv= newGVgen("Crypt::SecretBuffer::_pipe");
   old_io= IoIFP(GvIOp(gv));
   if (old_io) PerlIO_close(old_io);
   IoIFP(GvIOp(gv))= pio;
   IoOFP(GvIOp(gv))= pio;
   
   fh= (SV*) newRV_noinc((SV *)gv);
   sv_bless(fh, gv_stashpv("IO::Handle", 1));
   
   /* Successfully created file handle, so return it */
   return fh;
   
   cleanup: {
      int err_save= errno;
      /* Close any open file descriptors */
      if (pipefd[0] >= 0) close(pipefd[0]);
      if (pipefd[1] >= 0) close(pipefd[1]);
      /* Raise Perl exception with detailed error */
      errno = err_save;
      croak("%s: %s", err, strerror(errno));
   }
}

/*
 * SecretBuffer stringify magic
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

SV* secret_buffer_get_stringify_sv(secret_buffer *buf) {
   MAGIC *magic;
   SV *sv= buf->stringify_sv;
   if (!sv) {
      sv= buf->stringify_sv= newSV(0);
      magic= sv_magicext(sv, NULL, PERL_MAGIC_ext, &secret_buffer_stringify_magic_vtbl, (const char *)buf, 0);
      SvPOK_on(sv);
      SvUTF8_off(sv);
      SvREADONLY_on(sv);
   }
   SvPVX(sv)= buf->data;
   SvCUR(sv)= buf->len;
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
#endif

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
      XSRETURN(1); /* return self for chaining */

void
length(buf, val=NULL)
   auto_secret_buffer buf
   SV *val
   PPCODE:
      if (val) { /* writing */
         IV ival= SvIV(val);
         if (ival > buf->len)
            secret_buffer_append_random(buf, ival - buf->len, SECRET_BUFFER_APPEND_FULLCOUNT);
         else
            buf->len= ival > 0? ival : 0;
         /* return self, for chaining */
      }
      else /* reading */
         ST(0)= sv_2mortal(newSViv(buf->len));
      XSRETURN(1);

void
capacity(buf, val=NULL, or_larger= NULL)
   auto_secret_buffer buf
   SV *val
   SV *or_larger
   PPCODE:
      if (val) { /* wiritng */
         IV ival= SvIV(val);
         if (ival < 0) ival= 0;
         if (or_larger && SvTRUE(or_larger))
            secret_buffer_alloc_at_least(buf, ival);
         else
            secret_buffer_realloc(buf, ival);
         /* return self, for chaining */
      }
      else /* reading */
         ST(0)= sv_2mortal(newSViv(buf->capacity));
      XSRETURN(1);

UV
append_random(buf, count, flags=0)
   auto_secret_buffer buf
   UV count
   UV flags
   CODE:
      RETVAL= secret_buffer_append_random(buf, count, flags);
   OUTPUT:
      RETVAL

UV
append_tty_line(buf, tty, max_chars= -1, flags=0)
   auto_secret_buffer buf
   PerlIO *tty
   IV max_chars
   UV flags
   CODE:
      RETVAL= secret_buffer_append_tty_line(buf, tty, max_chars, flags);
   OUTPUT:
      RETVAL

UV
append_sysread(buf, io, count, flags=0)
   auto_secret_buffer buf
   PerlIO *io
   UV count
   UV flags
   CODE:
      RETVAL= secret_buffer_append_sysread(buf, io, count, flags);
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
         ST(0)= secret_buffer_get_stringify_sv(buf);
      }
      XSRETURN(1);
