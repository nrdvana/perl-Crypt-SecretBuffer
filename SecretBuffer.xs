#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "SecretBuffer.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#if HAVE_GETRANDOM
#include <sys/random.h>
#endif

#ifdef WIN32
#include <wincrypt.h>

void croak_with_windows_error(const char *prefix, DWORD err_code) {
   char message_buffer[512];
   DWORD length;

   length = FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      error_code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      message_buffer,
      sizeof(message_buffer),
      NULL
   );

   if (length)
      croak("%s: %s (%lu)", prefix, message_buffer, error_code);
   else
      croak("%s: %lu", prefix, error_code);
}

#else /* not WIN32 */
#include <pthread.h>
#endif

/**********************************************************************************************\
* MAGIC vtables
\**********************************************************************************************/

#ifdef USE_ITHREADS
static int secret_buffer_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param);
static int secret_buffer_stringify_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *params);
#else
#define secret_buffer_magic_dup 0
#define secret_buffer_stringify_magic_dup 0
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

/* Given a SV which you expect to be a reference to a blessed object with SecretBuffer
 * magic, return the secret_buffer struct pointer.
 * With no flags, this returns NULL is any of the above assumption is not correct.
 * Specify AUTOCREATE to create a new secret_buffer (and attach with magic) if it is a blessed
 * object and doesn't have the magic yet.
 * Specify OR_DIE if you want an exception instead of NULL return value.
 * Specify UNDEF_OK if you want input C<undef> to translate to C<NULL> even when OR_DIE is
 * requested.
 */
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

/* Create a new Crypt::SecretBuffer object with a mortal ref and return the secret_buffer.
 * If ref_out is NULL then the mortal ref remains mortal and the buffer is freed at the next
 * FREETMPS as your function exits.  If you supply a pointer to receive ref_out, you can then
 * increment the refcount or copy the ref if you want to keep the object.
 * Always returns a secret_buffer, or croaks on failure.
 */
secret_buffer* secret_buffer_new(size_t capacity, SV **ref_out) {
   SV *ref= sv_2mortal(newRV_noinc((SV*) newHV()));
   sv_bless(ref, gv_stashpv("Crypt::SecretBuffer", GV_ADD));
   secret_buffer *buf= secret_buffer_from_magic(ref, SECRET_BUFFER_MAGIC_AUTOCREATE);
   if (capacity) secret_buffer_alloc_at_least(buf, capacity);
   if (ref_out) *ref_out= ref;
   return buf;
}

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
   //warn("secret_buffer_copy");
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
#if defined WIN32
   SecureZeroMemory(buf, len);
#elif defined(HAVE_EXPLICIT_BZERO)
   explicit_bzero(buf, len);
#else
   /* this ought to be sufficient anyway because its within an extern function */
   bzero(buf, len);
#endif
}

size_t secret_buffer_append_random(secret_buffer *buf, size_t n, unsigned flags) {
   size_t orig_len= buf->len;
   char *dest;

   if (!n)
      return 0;
   if (buf->capacity < buf->len + n)
      secret_buffer_alloc_at_least(buf, buf->len + n);
   dest= buf->data + buf->len;

#ifdef WIN32
   {
      HCRYPTPROV hProv;

      if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
         croak_with_windows_error("CryptAcquireContext failed", GetLastError());

      if (!CryptGenRandom(hProv, sizeof(buffer), buffer)) {
         DWORD err_id= GetLastError();
         CryptReleaseContext(hProv, 0);
         croak_with_windows_error("CryptGenRandom failed", err_id);
      }

      CryptReleaseContext(hProv, 0);
   }
#elif defined(HAVE_GETRANDOM)
   {
      IV got= getrandom(dest, n, GRND_RANDOM | (flags & SECRET_BUFFER_NONBLOCK? GRND_NONBLOCK : 0));
      if (got < 0) {
         if (errno != EAGAIN)
            croak("getrandom() failed");
         got= 0;
      }
      buf->len += got;
   }
#else
   {
      int fd= open("/dev/random", O_RDONLY | (flags & SECRET_BUFFER_NONBLOCK? O_NONBLOCK : 0));
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
         if (!(flags & SECRET_BUFFER_FULLCOUNT))
            break;
      }
      close(fd);
   }
#endif
   return buf->len - orig_len;
}

size_t secret_buffer_append_tty_line(secret_buffer *buf, PerlIO *tty, int max_chars, unsigned flags) {
   size_t orig_len = buf->len;
#ifdef WIN32
   HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
   DWORD old_mode, new_mode;
   BOOL success;
   char ch;
   DWORD chars_read;

   if (hConsole == INVALID_HANDLE_VALUE)
      croak("Invalid console handle");

   /* Get current console mode */
   if (!GetConsoleMode(hConsole, &old_mode))
      croak_with_windows_error("Failed to get console mode", GetLastError());

   /* Set console mode to disable echo */
   new_mode = old_mode & ~ENABLE_ECHO_INPUT;
   if (!SetConsoleMode(hConsole, new_mode))
      croak_with_windows_error("Failed to set console mode", GetLastError());

   /* Read characters until newline or max_chars */
   while (max_chars != 0) {
      /* Handle non-blocking read if requested */
      if (flags & SECRET_BUFFER_NONBLOCK) {
         /* Check if input is available */
         DWORD available = 0;
         PeekConsoleInput(hConsole, NULL, 0, &available);
         if (available == 0) break;
      }
      success = ReadConsole(hConsole, &ch, 1, &chars_read, NULL);
      if (!success || chars_read == 0)
         break;
     
      if (ch == '\r' || ch == '\n')
         break;
     
      /* Ensure buffer capacity */
      if (buf->capacity < buf->len + 1)
         secret_buffer_alloc_at_least(buf, buf->len + 1);
         
      buf->data[buf->len++] = ch;

      if (max_chars > 0)
         --max_chars;
   }

   /* Restore original console mode */
   SetConsoleMode(hConsole, old_mode);
#else
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
#endif   
   return buf->len - orig_len;  // Return number of bytes read
}

size_t secret_buffer_append_sysread(secret_buffer *buf, PerlIO *fh, size_t count, unsigned flags) {
   size_t orig_len = buf->len;

   if (!count)
      return 0;

   if (buf->capacity < buf->len + count)
      secret_buffer_alloc_at_least(buf, buf->len + count);

#ifdef WIN32
   {
      HANDLE hFile = (HANDLE)_get_osfhandle(PerlIO_fileno(fh));
      DWORD bytes_read, error_code;
      BOOL success;
    
      if (hFile == INVALID_HANDLE_VALUE)
         croak("Invalid file handle");
    
      /* Use overlapped I/O for non-blocking operation if requested */
      if (flags & SECRET_BUFFER_NONBLOCK) {
         OVERLAPPED overlapped = {0};
         overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
         if (!overlapped.hEvent)
            croak_with_windows_error("Failed to create event for overlapped I/O", GetLastError());
        
         success = ReadFile(hFile, buf->data + buf->len, (DWORD)count, NULL, &overlapped);
        
         if (!success) {
            error_code = GetLastError();
            if (error_code == ERROR_IO_PENDING) {
               /* I/O is pending, check if we want to wait */
               if (flags & SECRET_BUFFER_FULLCOUNT) {
                  if (WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0) {
                     GetOverlappedResult(hFile, &overlapped, &bytes_read, TRUE);
                     buf->len += bytes_read;
                  }
               } else {
                  /* Just return what we have so far */
                  CancelIo(hFile);
               }
            } else {
               CloseHandle(overlapped.hEvent);
               croak_with_windows_error("Failed to read from file", error_code);
            }
         } else {
            GetOverlappedResult(hFile, &overlapped, &bytes_read, TRUE);
            buf->len += bytes_read;
         }
        
         CloseHandle(overlapped.hEvent);
      } else {
         /* Blocking read */
         success = ReadFile(hFile, buf->data + buf->len, (DWORD)count, &bytes_read, NULL);
        
         if (!success)
            croak("Failed to read from file: %lu", GetLastError());
        
         buf->len += bytes_read;
      }
   } /* win32 */
#else
   { /* posix */
      int fd = PerlIO_fileno(fh);
      ssize_t got;
      char *dest= buf->data + buf->len;
      /* Use recv so we can perform a nonblocking read without altering the fd state */
      while (count > 0) {
         got = recv(fd, dest, count, 
                    (flags & SECRET_BUFFER_NONBLOCK) ? MSG_DONTWAIT : 0);
         
         if (got > 0) {
            dest += got;
            buf->len += got;
            count -= got;
         } 
         else if (got == 0
            || ((errno == EAGAIN || errno == EWOULDBLOCK) && (flags & SECRET_BUFFER_NONBLOCK))
         ) {
            /* End of file, or end of available bytes in nonblocking mode */
            break;
         }
         else
            croak("Failed to read from file: %s", strerror(errno));
         
         /* If not in FULLCOUNT mode, exit after first read attempt */
         if (!(flags & SECRET_BUFFER_FULLCOUNT))
            break;
      }
   } /* posix */
#endif
   return buf->len - orig_len;  // Return number of bytes read
}

#ifdef WIN32
/* Structure to pass data to thread */
typedef struct {
   HANDLE hFile;
   size_t count;
   char bytes[]
} WriteThread_Params;

/* Thread procedure for Windows background writing */
DWORD WINAPI WriteThread_Proc(LPVOID lpParameter) {
   WriteThreadData *params = (WriteThreadData*)lpParameter;
   DWORD wrote;
   size_t total_written= 0;
   BOOL success;
   /* Write remaining data in blocking mode */
   while (total_written < params->count) {
      BOOL success = WriteFile(
         params->hFile, 
         params->bytes + total_written, 
         (DWORD)(params->count - total_written), 
         &wrote, NULL);

      if (!success || wrote == 0) {
         /* Handle might be closed or error occurred */
         break;
      }
      total_written += wrote;
   }
   /* Clean up */
   CloseHandle(params->hFile);
   secret_buffer_wipe(params->bytes, params->count);
   free(params);
   return 0;
}
#else /* not WIN32 */
/* Structure to pass data to thread */
typedef struct {
   int fd;
   size_t count;
   char bytes[];
} WriteThread_Params;

/* POSIX background writer thread */
void *WriteThread_Proc(void *arg) {
   WriteThread_Params *params = (WriteThread_Params *)arg;
   ssize_t written;
   size_t total_written = 0;

   /* Blocking mode assumed */
   while (total_written < params->count) {
      written = write(params->fd, params->bytes + total_written,
                      params->count - total_written);
      if (written < 0) {
         if (errno == EINTR)
            continue;
         if (errno != EPIPE)
            warn("Error writing to file: %s", strerror(errno));
         break;
      }
      if (written == 0) {
         /* Extremely rare in blocking write, but avoid busy loop */
         usleep(1000);
         continue;
      }
      total_written += written;
   }

   /* Clean sensitive data */
   secret_buffer_wipe(params->bytes, params->count);
   free(params);
   return NULL;
}
#endif /* not WIN32 */

size_t secret_buffer_syswrite(secret_buffer *buf, PerlIO *fh, size_t offset, size_t count, unsigned flags) {
   const char *err = NULL;
   int saved_errno = 0;
   size_t bytes_written = 0;
    
   if (offset > buf->len)
      croak("Offset exceeds buffer length");
    
   if (offset + count > buf->len)
      count = buf->len - offset;
    
   if (count == 0)
      return 0;

#ifdef WIN32
   {
      HANDLE hFile = (HANDLE)_get_osfhandle(PerlIO_fileno(fh));
      DWORD written = 0;
      BOOL success;

      if (hFile == INVALID_HANDLE_VALUE)
         croak("Invalid file handle");

      /* First attempt to write in non-blocking mode if requested */
      if (flags & SECRET_BUFFER_NONBLOCK) {
         OVERLAPPED overlapped = {0};
         overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
         if (!overlapped.hEvent)
            croak_with_windows_error("Failed to create event for overlapped I/O", GetLastError());

         success = WriteFile(hFile, buf->data + offset, (DWORD)count, NULL, &overlapped);
         if (!success && GetLastError() == ERROR_IO_PENDING)
            /* Check if the write completed immediately */
            success = GetOverlappedResult(hFile, &overlapped, &written, FALSE);

         CloseHandle(overlapped.hEvent);
         if (success)
            bytes_written = written;
      } else {
         /* Blocking write */
         success = WriteFile(hFile, buf->data + offset, (DWORD)count, &written, NULL);
         if (success)
            bytes_written = written;
      }

      /* If both NONBLOCK and FULLCOUNT are specified, and we haven't written everything,
         create a thread to complete the write */
      if ((flags & (SECRET_BUFFER_NONBLOCK | SECRET_BUFFER_FULLCOUNT)) == 
        (SECRET_BUFFER_NONBLOCK | SECRET_BUFFER_FULLCOUNT) && 
        bytes_written < count
      ) {
         size_t remaining= count - bytes_written;
         WriteThread_Params *params= (WriteThread_Params*) malloc(sizeof(WriteThread_Params) + remaining);
         if (!params)
            croak("Failed to allocate memory for thread data");
        
         /* Duplicate the file handle for the thread */
         if (!DuplicateHandle(
            GetCurrentProcess(), 
            hFile, 
            GetCurrentProcess(), 
            &params->hFile, 
            0, 
            FALSE, 
            DUPLICATE_SAME_ACCESS)
         ) {
            free(params);
            croak_with_windows_error("Failed to duplicate handle for thread", GetLastError());
         }

         /* Copy the part of the buffer we need to write */
         memcpy(params->bytes, buf->data + offset + bytes_written, remaining);
         params->count= remaining;

         /* Launch thread */
         HANDLE hThread = CreateThread(
            NULL,                   /* default security attributes */
            0,                      /* default stack size */
            (LPTHREAD_START_ROUTINE)WriteFileThreadProc,
            params,                 /* thread parameter */
            0,                      /* default creation flags */
            NULL);                  /* receive thread identifier */

         if (hThread == NULL) {
            CloseHandle(params->hFile);
            secret_buffer_wipe(params->bytes, params->count);
            free(params);
            croak_with_windows_error("Failed to create thread", GetLastError());
         }

         /* We don't need to wait for the thread, so just close the handle */
         CloseHandle(hThread);
      }
   } /* Win32 */
#else
   { /* POSIX */
      int fd = PerlIO_fileno(fh);
      ssize_t written;
    
      if (fd < 0)
         croak("Invalid file descriptor");
    
      /* Set non-blocking mode if requested */
      int old_flags = 0;
      if (flags & SECRET_BUFFER_NONBLOCK) {
         old_flags = fcntl(fd, F_GETFL);
         if (old_flags >= 0)
            fcntl(fd, F_SETFL, old_flags | O_NONBLOCK);
      }

      /* First write attempt */
      written = write(fd, buf->data + offset, count);

      /* Restore blocking mode if we changed it */
      if ((flags & SECRET_BUFFER_NONBLOCK) && old_flags >= 0) {
         fcntl(fd, F_SETFL, old_flags);
      }

      if (written < 0) {
         if (errno == EAGAIN || errno == EWOULDBLOCK) {
            written = 0;
         } else {
            croak("Failed to write to file: %s", strerror(errno));
         }
      }

      bytes_written = (written > 0) ? written : 0;
    
      /* If both NONBLOCK and FULLCOUNT are specified, and we haven't written everything,
         fork a child process to complete the write */
      if ((flags & (SECRET_BUFFER_NONBLOCK | SECRET_BUFFER_FULLCOUNT)) == 
         (SECRET_BUFFER_NONBLOCK | SECRET_BUFFER_FULLCOUNT) && 
         bytes_written < count
      ) {
         size_t remaining = count - bytes_written;
         pthread_t thread;
         WriteThread_Params *params = malloc(sizeof(WriteThread_Params) + remaining);
         if (!params)
            croak("Failed to allocate memory for thread data");

         params->fd = dup(fd);
         /* Set blocking mode for remaining writes */
         if (params->fd < 0 || fcntl(params->fd, F_SETFL, fcntl(params->fd, F_GETFL) & ~O_NONBLOCK) < 0) {
            free(params);
            croak("dup: %s", strerror(errno));
         }
         /* Give it a copy of the unwritten secret */
         memcpy(params->bytes, buf->data + offset + bytes_written, remaining);
         params->count= remaining;
         /* Launch pthread */
         if (pthread_create(&thread, NULL, WriteThread_Proc, params) != 0) {
            close(params->fd);
            secret_buffer_wipe(params->bytes, params->count);
            free(params);
            croak("Failed to create POSIX writer thread: %s", strerror(errno));
         }
         /* Detach so resources are freed on exit */
         pthread_detach(thread); /* Parent continues without waiting for child */
      }
   } /* POSIX */
#endif
   return bytes_written;
}

/**********************************************************************************************\
* SecretBuffer stringify magic
\**********************************************************************************************/

static int
secret_buffer_stringify_magic_get(pTHX_ SV *sv, MAGIC *mg) {
   secret_buffer *buf= (secret_buffer *)mg->mg_ptr;
//   warn("secret_buffer_stringify_magic_get %p %p", buf->stringify_sv, sv);
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
//   warn("Freeing stringify scalar");
}

#ifdef USE_ITHREADS
static int
secret_buffer_stringify_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   croak("Can't dup stringify_sv");
}
#endif

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
static int secret_buffer_magic_dup(pTHX_ MAGIC *mg, CLONE_PARAMS *param) {
   secret_buffer *clone, *orig = (secret_buffer *)mg->mg_ptr;
   PERL_UNUSED_VAR(param);
   Newxz(clone, 1, secret_buffer);
   mg->mg_ptr = (char *)clone;
   secret_buffer_copy(clone, orig);
   return 0;
}
#endif

/* Aliases for typemap */
typedef secret_buffer  *auto_secret_buffer;
typedef secret_buffer  *maybe_secret_buffer;

/* For exported constant dualvars */
#define EXPORT_ENUM(x) newCONSTSUB(stash, #x, new_enum_dualvar(aTHX_ x, newSVpvs_share(#x)))
static SV * new_enum_dualvar(pTHX_ IV ival, SV *name) {
   SvUPGRADE(name, SVt_PVNV);
   SvIV_set(name, ival);
   SvIOK_on(name);
   SvREADONLY_on(name);
   return name;
}

/* flag for capacity */
#define SECRET_BUFFER_AT_LEAST 1

/* Convenience to convert string parameters to the corresponding integer so that Perl-side
 * doesn't always need to import the flag constants.
 */
static IV parse_flags(SV *sv) {
   if (!sv || !SvOK(sv))
      return 0;
   if (SvIOK(sv))
      return SvIV(sv);
   if (SvPOK(sv)) {
      const char *str= SvPV_nolen(sv);
      if (!str[0]) return 0;
      if (strcmp(str, "NONBLOCK") == 0)  return SECRET_BUFFER_NONBLOCK;
      if (strcmp(str, "FULLCOUNT") == 0) return SECRET_BUFFER_FULLCOUNT;
      if (strcmp(str, "AT_LEAST") == 0)  return SECRET_BUFFER_AT_LEAST;
   }
   croak("Unknown flag %s", SvPV_nolen(sv));
}

/**********************************************************************************************\
 * Debug helpers
\**********************************************************************************************/

// Helper function to check if a memory page is accessible (committed and readable)
#if defined(WIN32)

static bool is_page_accessible(uintptr_t addr) {
   MEMORY_BASIC_INFORMATION memInfo;
   if (VirtualQuery((LPCVOID)addr, &memInfo, sizeof(memInfo)) == 0)
      return FALSE;
   return (memInfo.State == MEM_COMMIT) && 
          (memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
}
#define HAVE_IS_PAGE_ACESSIBLE

static size_t get_page_size() {
   long pagesize = sysconf(_SC_PAGESIZE);


#elif defined(HAVE_MINCORE)

#include <sys/mman.h>
static bool is_page_accessible(uintptr_t addr) {
   unsigned char vec;
   return mincore((void*)addr, 1, &vec) == 0;
}
#define HAVE_IS_PAGE_ACESSIBLE

#endif

#if defined(HAVE_IS_PAGE_ACESSIBLE)

#ifndef HAVE_MEMMEM
static void* memmem(
   const void *haystack, size_t haystacklen,
   const void *needle, size_t needlelen
) {
   const char *p= (const char*) haystack;
   const char *lim= p + haystacklen - needlelen;
   char first_ch= needle[0];
   while (p < lim) {
      if (*p == first_ch) {
         // Check each position for the needle
         if (memcmp(p, needle, needle_len) == 0) {
            ++count;
            p += needle_len;
            continue;
         }
      }
      ++p;
   }
}
#endif /* HAVE_MEMMEM */

size_t scan_mapped_memory_in_range(uintptr_t p, uintptr_t lim, const char *needle, size_t needle_len) {
   long pagesize = sysconf(_SC_PAGESIZE);
   unsigned char vec;
   size_t count= 0;
   void *at;
   uintptr_t run_start = p, run_lim;
   p = (p & ~(pagesize - 1)); /* round to nearest page, from here out */
   while (p < lim) {
      // Skip pages that aren't mapped
      while (p < lim && !is_page_accessible(p)) {
         p += pagesize;
         run_start= p;
      }
      // This page is mapped.  Find the end of this mapped range, if it comes before lim
      while (p < lim && is_page_accessible(p)) {
         p += pagesize;
      }
      run_lim= p < lim? p : lim;
      // Scan memory from run_start to run_lim
      while (run_start < run_lim && (at= memmem((void*)run_start, run_lim - run_start, needle, needle_len))) {
         ++count;
         run_start= ((intptr_t)at) + needle_len;
      }
   }
   return count;
}
#else
size_t scan_mapped_memory_in_range(uintptr_t p, uintptr_t lim, const char *needle, size_t needle_len) {
   croak("Unimplemented");
}
#endif

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
            secret_buffer_append_random(buf, ival - buf->len, SECRET_BUFFER_FULLCOUNT);
         else
            buf->len= ival > 0? ival : 0;
         /* return self, for chaining */
      }
      else /* reading */
         ST(0)= sv_2mortal(newSViv(buf->len));
      XSRETURN(1);

void
capacity(buf, val=NULL, flag= NULL)
   auto_secret_buffer buf
   SV *val
   SV *flag
   PPCODE:
      if (val) { /* wiritng */
         IV ival= SvIV(val);
         IV iflag= parse_flags(flag);
         if (ival < 0) ival= 0;
         if (iflag & SECRET_BUFFER_AT_LEAST)
            secret_buffer_alloc_at_least(buf, ival);
         else
            secret_buffer_realloc(buf, ival);
         /* return self, for chaining */
      }
      else /* reading */
         ST(0)= sv_2mortal(newSViv(buf->capacity));
      XSRETURN(1);

void
clear(buf)
   auto_secret_buffer buf
   PPCODE:
      secret_buffer_realloc(buf, 0);
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

UV
syswrite(buf, io, offset=0, count=buf->len, flags=0)
   auto_secret_buffer buf
   PerlIO *io
   UV offset
   UV count
   UV flags
   CODE:
      RETVAL= secret_buffer_syswrite(buf, io, offset, count, flags);
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

IV
_count_matches_in_mem(buf, addr0, addr1)
   secret_buffer *buf
   UV addr0
   UV addr1
   CODE:
      if (!buf->len)
         croak("Empty buffer");
      RETVAL= scan_mapped_memory_in_range(addr0, addr1, buf->data, buf->len);
   OUTPUT:
      RETVAL

BOOT:
   HV *stash= gv_stashpvn("Crypt::SecretBuffer", 19, 1);
   newCONSTSUB(stash, "NONBLOCK",  new_enum_dualvar(aTHX_ SECRET_BUFFER_NONBLOCK,  newSVpvs_share("NONBLOCK")));
   newCONSTSUB(stash, "FULLCOUNT", new_enum_dualvar(aTHX_ SECRET_BUFFER_FULLCOUNT, newSVpvs_share("FULLCOUNT")));
   newCONSTSUB(stash, "AT_LEAST",  new_enum_dualvar(aTHX_ SECRET_BUFFER_AT_LEAST,  newSVpvs_share("AT_LEAST")));
