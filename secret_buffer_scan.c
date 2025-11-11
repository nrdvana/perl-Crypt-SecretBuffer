
/* These local parse functions are independenct of the SecretBuffer instance,
 * needing only the 'data' pointer to whch the parse_state refers.
 * The pos/lim of the parse state must already be checked against the length
 * of the data before calling these.
 */
static int parse_prev_codepoint(secret_buffer_parse *parse_state, const U8 *data);
static int parse_next_codepoint(secret_buffer_parse *parse_state, const U8 *data);
static bool parse_scan_charset_bytes(secret_buffer_parse *parse_state, const U8 *data, const secret_buffer_charset *cset, int flags);
static bool parse_scan_charset_codepoints(secret_buffer_parse *parse_state, const U8 *data, const secret_buffer_charset *cset, int flags);
static bool parse_scan_bytestr(secret_buffer_parse *parse_state, const U8 *data, const U8 *bytestr, size_t bytestr_len, int flags);

/* Public API: Scan for a pattern which may be a regex or literal string.
 * Regexes are currently limited to a single charclass.
 */
bool secret_buffer_scan(
   secret_buffer *sb,
   SV *pattern,
   secret_buffer_parse *parse_state,
   int flags
) {
   REGEXP *rx= SvRX(pattern);
   if (rx) {
      secret_buffer_charset *cset= secret_buffer_charset_from_regexpref(pattern);
      return secret_buffer_scan_charset(sb, cset, parse_state, flags);
   } else {
      STRLEN len;
      U8 *str= (U8*) SvPVbyte(pattern, len);
      return secret_buffer_scan_bytestr(sb, str, len, parse_state, flags);
   }      
}

/* Public API: Scan for a pattern which is a set of characters */
bool secret_buffer_scan_charset(
   secret_buffer *sb,
   secret_buffer_charset *cset,
   secret_buffer_parse *parse_state,
   int flags
) {
   // Sanity check this parse state vs. the buffer
   if (parse_state->lim > sb->len || parse_state->pos > parse_state->lim) {
      parse_state->error= "Invalid parse boundaries";
      return false;
   }
   parse_state->error = NULL;
   if (parse_state->pos >= parse_state->lim) // empty range
      return false;

   // byte matching gets to use a more efficient algorithm
   return parse_state->encoding == SECRET_BUFFER_ENCODING_ASCII
      ? parse_scan_charset_bytes(parse_state, (U8*) sb->data, cset, flags)
      : parse_scan_charset_codepoints(parse_state, (U8*) sb->data, cset, flags);
}

/* Public API: Scan for a pattern which is a literal string of bytes.
 * The caller is responsible for encoding them in the same format as requested
 * by parse_state->encoding.
 */
bool secret_buffer_scan_bytestr(
   secret_buffer *sb, char *data, size_t datalen,
   secret_buffer_parse *parse_state, int flags
) {
   // Sanity check this parse state vs. the buffer
   if (parse_state->lim > sb->len || parse_state->pos > parse_state->lim) {
      parse_state->error= "Invalid parse boundaries";
      return false;
   }
   parse_state->error = NULL;
   if (parse_state->pos >= parse_state->lim) // empty range
      return false;

   return parse_scan_bytestr(parse_state, sb->data, data, datalen, flags);
}

/* Scan raw bytes using only the bitmap */
static bool parse_scan_charset_bytes(
   secret_buffer_parse *parse_state,
   const U8 *data,
   const secret_buffer_charset *cset,
   int flags
) {
   bool negate=  (flags & SECRET_BUFFER_SCAN_NEGATE);
   bool reverse= (flags & SECRET_BUFFER_SCAN_REVERSE);
   bool span=    (flags & SECRET_BUFFER_SCAN_SPAN);
   int step= reverse? -1 : 1;
   const U8 *pos= reverse? data + parse_state->lim-1 : data + parse_state->pos,
            *lim= reverse? data + parse_state->pos-1 : data + parse_state->lim,
            *span_start= NULL;
   //warn("scan_charset_bytes pos=%d lim=%d len=%d",
   //   (int)parse_state->pos,
   //   (int)parse_state->lim,
   //   (int)(parse_state->lim - parse_state->pos));

   while (pos != lim) {
      if (sbc_bitmap_test(cset->bitmap, *pos) != negate) {
         // Found.  Now are we looking for a span?
         if (span_start)
            break;
         if (!span) {
            parse_state->pos= pos - data;
            parse_state->lim= parse_state->pos + 1;
            return true;
         }
         span_start= pos;
         negate= !negate;
      }
      pos += step;
   }
   // reached end of defined range, and implicitly ends span
   if (reverse) {
      parse_state->pos= pos + 1 - data;
      parse_state->lim= span_start? span_start + 1 - data : parse_state->pos;
   } else {
      parse_state->lim= pos - data;
      parse_state->pos= span_start? span_start - data : parse_state->lim;
   }
   return span_start != NULL;
}

// Called by secret_buffer_scan, which verified the range of th
static bool parse_scan_charset_codepoints(
   secret_buffer_parse *parse_state,
   const U8 *data,
   const secret_buffer_charset *cset,
   int flags
) {
   dTHX;
   bool negate= (flags & SECRET_BUFFER_SCAN_NEGATE);
   bool reverse= (flags & SECRET_BUFFER_SCAN_REVERSE);
   bool span= (flags & SECRET_BUFFER_SCAN_SPAN);
   bool span_started= false;
   size_t span_mark= 0, prev_mark= reverse? parse_state->lim : parse_state->pos;

   while (parse_state->pos < parse_state->lim) {
      int codepoint= reverse? parse_prev_codepoint(parse_state, data)
                            : parse_next_codepoint(parse_state, data);
      if (codepoint < 0) // encoding error
         return false;
      if (sbc_test_codepoint(aTHX_ cset, codepoint) != negate) {
         // Found.  Mark boundaries of char.
         // Now are we looking for a span?
         if (span_started)
            break;
         if (!span) {
            if (reverse) {
               parse_state->pos= parse_state->lim;
               parse_state->lim= prev_mark;
            } else {
               parse_state->lim= parse_state->pos;
               parse_state->pos= prev_mark;
            }
            return true;
         }
         span_started= true;
         span_mark= prev_mark;
         negate= !negate;
      }
      prev_mark= reverse? parse_state->lim : parse_state->pos;
   }
   // reached end of defined range
   if (span_started) { // and implicitly ends span
      if (reverse) {
         parse_state->pos= prev_mark;
         parse_state->lim= span_mark;
      }
      else {
         parse_state->pos= span_mark;
         parse_state->lim= prev_mark;
      }
      return true;
   }
   return false;
}

/* UTF-8 decoding helper */
static int parse_next_codepoint(secret_buffer_parse *parse_state, const U8 *data) {
   const U8 *pos= data + parse_state->pos, *lim= data + parse_state->lim;
   int cp;

   if (parse_state->encoding == SECRET_BUFFER_ENCODING_ASCII
    || parse_state->encoding == SECRET_BUFFER_ENCODING_UTF8
   ) {
      if (lim - pos < 1) {
         parse_state->error= "parse range too small";
         return -1;
      }
      cp= *pos++;
      if (cp >= 0x80 && parse_state->encoding == SECRET_BUFFER_ENCODING_UTF8) {
         int min_cp= 0;
         switch ((cp >> 3) & 0xF) {
         case 14:                          // 0b1[1110]yyy
            {  if (lim - pos < 3) goto incomplete;
               min_cp= 0x10000;
               cp &= 0x07;
            }
            if ((*pos & 0xC0) != 0x80) goto invalid;
            cp= (cp << 6) | (*pos++ & 0x3F);
            if (0)
         case 12: case 13:                 // 0b1[110x]yyy
            {  if (lim - pos < 2) goto incomplete;
               min_cp= 0x800;
               cp &= 0x0F;
            }
            if ((*pos & 0xC0) != 0x80) goto invalid;
            cp= (cp << 6) | (*pos++ & 0x3F);
            if (0)
         case 8: case 9: case 10: case 11: // 0b1[10xx]yyy
            {  if (lim - pos < 1) goto incomplete;
               min_cp= 0x80;
               cp &= 0x1F;
            }
            if ((*pos & 0xC0) != 0x80) goto invalid;
            cp= (cp << 6) | (*pos++ & 0x3F);
            break;
         default:
            invalid: parse_state->error= "invalid UTF8 character";
            if (0)
               incomplete: parse_state->error= "incomplete UTF8 character";
            return -1;
         }
         if (cp < min_cp) {
            parse_state->error= "overlong encoding of UTF8 character";
            return -1;
         }
         else if (cp > 0x10FFFF) {
            parse_state->error= "UTF8 character exceeds max";
            return -1;
         }
      }
   }
   else if (parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16LE
         || parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16BE
   ) {
      int low= parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16LE? 0 : 1;
      if (lim - pos < 2) {
         parse_state->error= "parse range too small";
         return -1;
      }
      cp= pos[low] | ((int)pos[low^1] << 8);
      pos += 2;
      if (cp >= 0xD800 && cp <= 0xDFFF) {
         if (lim - pos < 2) {
            parse_state->error= "incomplete UTF16 character";
            return -1;
         }
         int w2= pos[low] | ((int)pos[low^1] << 8);
         pos += 2;
         if (w2 < 0xDC00 || w2 > 0xDFFF) {
            parse_state->error= "invalid UTF16 low surrogate";
            return -1;
         }
         cp = 0x10000 + (((cp & 0x3FF) << 10) | (w2 & 0x3FF));
      }
   }
   else {
      parse_state->error= "unknown encoding";
      return -1;
   }
   parse_state->pos= pos - data;
   return cp;
}

static int parse_prev_codepoint(secret_buffer_parse *parse_state, const U8 *data) {
   const U8 *pos= data + parse_state->pos, *lim= data + parse_state->lim;
   int cp;

   if (parse_state->encoding == SECRET_BUFFER_ENCODING_ASCII
    || parse_state->encoding == SECRET_BUFFER_ENCODING_UTF8
   ) {
      if (lim <= pos) {
         parse_state->error= "parse range too small";
         return -1;
      }
      // handle the simple case first
      if (lim[-1] < 0x80 || parse_state->encoding == SECRET_BUFFER_ENCODING_ASCII) {
         parse_state->lim--;
         return lim[-1];
      }
      // else need to backtrack and then call next_codepoint
      const U8 *prev= lim-1;
      while (prev >= pos && (*prev & 0xC0) == 0x80)
         --prev;
      parse_state->pos= prev - data;
      cp= parse_next_codepoint(parse_state, data);
      if (parse_state->pos == parse_state->lim) // consumed all characters we gave it?
         parse_state->lim= prev - data; // new lim is where we started the parse from
      else {
         if (cp >= 0) { // had a valid char, but extra 0x80 bytes
            parse_state->error= "invalid UTF8 character";
            cp= -1;
         }
         // else use the error message from next_codepoint
      }
      parse_state->pos= pos - data; // restore original pos
   }
   else if (parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16LE
         || parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16BE
   ) {
      if (lim - pos < 2) {
         parse_state->error= "parse range too small";
         return -1;
      }
      // handle the simple case first
      int low= parse_state->encoding == SECRET_BUFFER_ENCODING_UTF16LE? 0 : 1;
      cp= lim[-2 + low] | ((int)pos[-2 + (low^1)] << 8);
      if (cp < 0xD800 || cp > 0xDFFF) {
         parse_state->lim -= 2;
         return cp;
      }
      // else need to backtrack and then call next_codepoint
      parse_state->pos= parse_state->lim - 4;
      cp= parse_next_codepoint(parse_state, data);
      if (cp >= 0)
         parse_state->lim -= 4;
      parse_state->pos= pos - data; // restore original pos
   }
   else {
      parse_state->error= "unknown encoding";
      return -1;
   }
   return cp;
}

bool parse_scan_bytestr(secret_buffer_parse *parse_state, const U8 *data,
   const U8 *bytestr, size_t bytestr_len, int flags
) {
   bool reverse= (flags & SECRET_BUFFER_SCAN_REVERSE);
   bool span=    (flags & SECRET_BUFFER_SCAN_SPAN);
   parse_state->error = NULL;
   if (parse_state->pos >= parse_state->lim) // empty range
      return false;

   // get this edge case out of the way
   if (bytestr_len == 0) {
      if (reverse)
         parse_state->pos= parse_state->lim;
      else
         parse_state->lim= parse_state->pos;
      return true;
   }

   // Consider a reduced range where the length of the string is removed from
   // the buffer limit, resulting in a pointer to the last char ('pmax') which
   // possibly match 'bytestr'.
   const U8 first_ch= *bytestr,
           *pmin= data + parse_state->pos,
           *pmax= data + parse_state->lim - bytestr_len;
   if (reverse) {
      while (pmin <= pmax) {
         if (*pmax == first_ch && 0 == memcmp(pmax, bytestr, bytestr_len)) {
            parse_state->pos= pmax - data;
            parse_state->lim= parse_state->pos + bytestr_len;
            if (span) {
               while (pmax - pmin >= bytestr_len && pmax[-bytestr_len] == first_ch
                  && 0 == memcmp(pmax-bytestr_len, bytestr, bytestr_len))
                  pmax -= bytestr_len;
               parse_state->pos= pmax - data;
            }
            break;
         }
         --pmax;
      }
   } else {
      while (pmin <= pmax) {
         if (*pmin == first_ch && 0 == memcmp(pmin, bytestr, bytestr_len)) {
            parse_state->pos= pmin - data;
            parse_state->lim= parse_state->pos + bytestr_len;
            if (span) {
               while (pmax - pmin >= bytestr_len && pmin[bytestr_len] == first_ch
                  && 0 == memcmp(pmin+bytestr_len, bytestr, bytestr_len))
                  pmin += bytestr_len;
               parse_state->lim= pmin - data + bytestr_len;
            }
            break;
         }
         ++pmin;
      }
   }
   if (pmin > pmax) { // Not found, describe a zero-length range
      parse_state->pos= pmin - data;
      parse_state->lim= parse_state->pos;
      return false;
   }
   return true;
}
