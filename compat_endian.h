/* compat_endian.h - substitute for endian.h on systems that lack it
 *
 * Provides:
 *   compat_endian_htole16, compat_endian_le16toh, compat_endian_htobe16, compat_endian_be16toh
 *   compat_endian_htole32, compat_endian_le32toh, compat_endian_htobe32, compat_endian_be32toh
 *   compat_endian_htole64, compat_endian_le64toh, compat_endian_htobe64, compat_endian_be64toh
 *
 * Then, if the *unprefixed* names are missing, defines them to the compat_ versions:
 *   htole16 le16toh htobe16 be16toh
 *   htole32 le32toh htobe32 be32toh
 *   htole64 le64toh htobe64 be64toh
 */

#ifndef COMPAT_ENDIAN_H
#define COMPAT_ENDIAN_H

#include <stdint.h>

/* ---- pure-C byteswap helpers (no intrinsics / builtins required) ---- */

PERL_STATIC_INLINE uint16_t compat_endian_bswap16_u(uint16_t x)
{
    return ((x & 0x00FFu) <<  8) |
           ((x & 0xFF00u) >>  8);
}

PERL_STATIC_INLINE uint32_t compat_endian_bswap32_u(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) <<  8) |
           ((x & 0x00FF0000u) >>  8) |
           ((x & 0xFF000000u) >> 24);
}

PERL_STATIC_INLINE uint64_t compat_endian_bswap64_u(uint64_t x)
{
    return ((x & 0x00000000000000FFull) << 56) |
           ((x & 0x000000000000FF00ull) << 40) |
           ((x & 0x0000000000FF0000ull) << 24) |
           ((x & 0x00000000FF000000ull) <<  8) |
           ((x & 0x000000FF00000000ull) >>  8) |
           ((x & 0x0000FF0000000000ull) >> 24) |
           ((x & 0x00FF000000000000ull) >> 40) |
           ((x & 0xFF00000000000000ull) >> 56);
}

/* ---- endianness detection ----
 * Prefer compile-time macros when present; otherwise use a tiny runtime probe.
 */

#if defined(_WIN32) || defined(__i386__) || defined(__x86_64__) || defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    (defined(BYTE_ORDER) && defined(LITTLE_ENDIAN) && (BYTE_ORDER == LITTLE_ENDIAN))

PERL_STATIC_INLINE int compat_endian_is_le(void) { return 1; }

PERL_STATIC_INLINE uint16_t compat_endian_htole16(uint16_t x) { return x; }
PERL_STATIC_INLINE uint16_t compat_endian_htobe16(uint16_t x) { return compat_endian_bswap16_u(x); }
PERL_STATIC_INLINE uint16_t compat_endian_le16toh(uint16_t x) { return x; }
PERL_STATIC_INLINE uint16_t compat_endian_be16toh(uint16_t x) { return compat_endian_bswap16_u(x); }

PERL_STATIC_INLINE uint32_t compat_endian_htole32(uint32_t x) { return x; }
PERL_STATIC_INLINE uint32_t compat_endian_htobe32(uint32_t x) { return compat_endian_bswap32_u(x); }
PERL_STATIC_INLINE uint32_t compat_endian_le32toh(uint32_t x) { return x; }
PERL_STATIC_INLINE uint32_t compat_endian_be32toh(uint32_t x) { return compat_endian_bswap32_u(x); }

PERL_STATIC_INLINE uint64_t compat_endian_htole64(uint64_t x) { return x; }
PERL_STATIC_INLINE uint64_t compat_endian_htobe64(uint64_t x) { return compat_endian_bswap64_u(x); }
PERL_STATIC_INLINE uint64_t compat_endian_le64toh(uint64_t x) { return x; }
PERL_STATIC_INLINE uint64_t compat_endian_be64toh(uint64_t x) { return compat_endian_bswap64_u(x); }

#elif defined(__BIG_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)) || \
      (defined(BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN))

PERL_STATIC_INLINE int compat_endian_is_le(void) { return 0; }

PERL_STATIC_INLINE uint16_t compat_endian_htole16(uint16_t x) { return compat_endian_bswap16_u(x); }
PERL_STATIC_INLINE uint16_t compat_endian_htobe16(uint16_t x) { return x; }
PERL_STATIC_INLINE uint16_t compat_endian_le16toh(uint16_t x) { return compat_endian_bswap16_u(x); }
PERL_STATIC_INLINE uint16_t compat_endian_be16toh(uint16_t x) { return x; }

PERL_STATIC_INLINE uint32_t compat_endian_htole32(uint32_t x) { return compat_endian_bswap32_u(x); }
PERL_STATIC_INLINE uint32_t compat_endian_htobe32(uint32_t x) { return x; }
PERL_STATIC_INLINE uint32_t compat_endian_le32toh(uint32_t x) { return compat_endian_bswap32_u(x); }
PERL_STATIC_INLINE uint32_t compat_endian_be32toh(uint32_t x) { return x; }

PERL_STATIC_INLINE uint64_t compat_endian_htole64(uint64_t x) { return compat_endian_bswap64_u(x); }
PERL_STATIC_INLINE uint64_t compat_endian_htobe64(uint64_t x) { return x; }
PERL_STATIC_INLINE uint64_t compat_endian_le64toh(uint64_t x) { return compat_endian_bswap64_u(x); }
PERL_STATIC_INLINE uint64_t compat_endian_be64toh(uint64_t x) { return x; }

#else

PERL_STATIC_INLINE int compat_endian_is_le(void) {
   const uint16_t one = 1;
   return *((const uint8_t *)&one) == 1;
}

PERL_STATIC_INLINE uint16_t compat_endian_htole16(uint16_t x) { return compat_endian_is_le()? x : compat_endian_bswap16_u(x); }
PERL_STATIC_INLINE uint16_t compat_endian_htobe16(uint16_t x) { return compat_endian_is_le()? compat_endian_bswap16_u(x) : x; }
PERL_STATIC_INLINE uint16_t compat_endian_le16toh(uint16_t x) { return compat_endian_is_le()? x : compat_endian_bswap16_u(x); }
PERL_STATIC_INLINE uint16_t compat_endian_be16toh(uint16_t x) { return compat_endian_is_le()? compat_endian_bswap16_u(x) : x; }

PERL_STATIC_INLINE uint32_t compat_endian_htole32(uint32_t x) { return compat_endian_is_le()? x : compat_endian_bswap32_u(x); }
PERL_STATIC_INLINE uint32_t compat_endian_htobe32(uint32_t x) { return compat_endian_is_le()? compat_endian_bswap32_u(x) : x; }
PERL_STATIC_INLINE uint32_t compat_endian_le32toh(uint32_t x) { return compat_endian_is_le()? x : compat_endian_bswap32_u(x); }
PERL_STATIC_INLINE uint32_t compat_endian_be32toh(uint32_t x) { return compat_endian_is_le()? compat_endian_bswap32_u(x) : x; }

PERL_STATIC_INLINE uint64_t compat_endian_htole64(uint64_t x) { return compat_endian_is_le()? x : compat_endian_bswap64_u(x); }
PERL_STATIC_INLINE uint64_t compat_endian_htobe64(uint64_t x) { return compat_endian_is_le()? compat_endian_bswap64_u(x) : x; }
PERL_STATIC_INLINE uint64_t compat_endian_le64toh(uint64_t x) { return compat_endian_is_le()? x : compat_endian_bswap64_u(x); }
PERL_STATIC_INLINE uint64_t compat_endian_be64toh(uint64_t x) { return compat_endian_is_le()? compat_endian_bswap64_u(x) : x; }

#endif

/* ---- supply standard API if missing ---- */

#ifndef htole16
  #define htole16(x) compat_endian_htole16(x)
#endif
#ifndef htobe16
  #define htobe16(x) compat_endian_htobe16(x)
#endif
#ifndef le16toh
  #define le16toh(x) compat_endian_le16toh(x)
#endif
#ifndef be16toh
  #define be16toh(x) compat_endian_be16toh(x)
#endif

#ifndef htole32
  #define htole32(x) compat_endian_htole32(x)
#endif
#ifndef htobe32
  #define htobe32(x) compat_endian_htobe32(x)
#endif
#ifndef le32toh
  #define le32toh(x) compat_endian_le32toh(x)
#endif
#ifndef be32toh
  #define be32toh(x) compat_endian_be32toh(x)
#endif

#ifndef htole64
  #define htole64(x) compat_endian_htole64(x)
#endif
#ifndef htobe64
  #define htobe64(x) compat_endian_htobe64(x)
#endif
#ifndef le64toh
  #define le64toh(x) compat_endian_le64toh(x)
#endif
#ifndef be64toh
  #define be64toh(x) compat_endian_be64toh(x)
#endif

#endif /* COMPAT_ENDIAN_H */
