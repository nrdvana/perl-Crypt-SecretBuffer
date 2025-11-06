/* INI-parsing implementation for SecretBuffer.
 * This file is sourced into SecretBuffer.xs
 */

void secret_buffer_ini_init(secret_buffer_ini *ini) {
   memset(ini, 0, sizeof(ini));
}

secret_buffer_ini *secret_buffer_ini_clone(secret_buffer_ini *orig) {
   secret_buffer_ini *clone= NULL;
   Newx(clone, 1, secret_buffer_ini);
   memcpy(clone, orig, sizeof(*orig));
   return clone;
}

void secret_buffer_ini_destroy(secret_buffer_ini *ini) {
   memset(ini, 0, sizeof(ini));
}

static bool is_valid_key_start_char(char c) {
   return c >= 'A' && c <= 'Z'
       || c >= 'a' && c <= 'z'
       || c >= '0' && c <= '9'
       || c == '_';
}
static bool is_valid_key_char(char c) {
   return is_valid_key_start_char(c) || c == '-' || c == ':';
}

// Look for the "end of line", either the '\n' or the start of an inline comment
static char *ini_seek_eol(secret_buffer_ini *ini, char *pos, char *lim) {
   while (pos < lim && *pos != '\n'
      && !(ini->opt_inline_comment && (*pos == ';' || ini->opt_hash_comment && *pos == '#')))
      ++pos;
   return pos;
}

#define PARSE_FAIL(reason) parse->err= reason, parse->pos= pos, return false
bool secret_buffer_ini_parse_next(secret_buffer_ini *ini, secret_buffer *buf) {
   char *lim= buf->data + buf->len;
   char *pos= buf->data + ini->pos;
   while (pos < lim) {
      // Skip leading space/tab for all lines
      while (pos < lim && (*pos == ' ' || *pos == '\t')) pos++;
      // Is it a comment?
      if (*pos == ';' || (*pos == '#' && ini->opt_hash_comment)) {
         // skip to next line
         while (pos < lim && *pos != '\n') pos++;
         pos++; // move past \n
      }
      // Is it a section header?
      else if (*pos == '[') {
         char *start= pos+1, *end;
         // look for matching ']'
         while (pos < lim && *pos != '\n' && *pos != ']') pos++;
         if (pos >= lim || *pos != ']')
            PARSE_FAIL("incomplete section header");
         end= pos++;
         // make sure rest of line is clear
         while (pos < lim && (*pos == ' ' || *pos == '\t')) pos++;
         if (pos >= lim)
            PARSE_FAIL("unexpected end of file on section header line");
         if (*pos != '\n' && !(ini->opt_inline_comment && (*pos == ';' || ini->opt_hash_comment && *pos == '#')))
            PARSE_FAIL("unexpected text after section header");
         // now trim the section name
         while (*start == ' ' || *start == '\t') start++;
         while (end[-1] == ' ' || end[-1] == '\t') end--;
         if (start >= end)
            PARSE_FAIL("empty section header");
         // have a complete header defined; mark it
         ini->section_ofs= start - parse->buf->data;
         ini->section_len= end - start;
         // skip comment if present
         while (pos < lim && *pos != '\n') pos++;
         pos++ // move past \n
      }
      // Is it a key=value ?
      else if (is_valid_key_start_char(*pos)) {
         char *key_start= pos, *key_end, *val_start, *val_end;
         while (pos < lim && is_valid_key_char(*pos)) pos++;
         key_end= pos;
         while (pos < lim && (*pos == ' ' || *pos == '\t')) pos++;
         if (pos >= lim || *pos != '=')
            PARSE_FAIL("expected '=' after key name");
         pos++;
         while (pos < lim && (*pos == ' ' || *pos == '\t')) pos++;
         val_start= pos;
         // here, parse options vary for quoted vs raw values, and optional
         // inline comments, and optional line-wrapping.
         ...
         if (pos >= lim || *pos != '\n')
            PARSE_FAIL("invalid value syntax");
         parse->key_ofs= key_start - parse->buf->data;
         parse->key_len= key_end - key_start;
         parse->value_ofs= val_start - parse->buf->data;
         parse->value_len= pos - val_start;
         parse->pos= ++pos; // start of next line
         return true;
      }
      // blank line?
      else if (*pos == '\n' || (*pos == '\r' && pos+1 < lim && pos[1] == '\n')) {
         if (*pos == '\r') pos++;
         pos++; // step past \n
      }
      // unknown...
      else {
         PARSE_FAIL("not a section header, key, or comment");
      }
   }
   parse->err= NULL; // natural EOF following \n
   return false;
}

// Copy the value from the parse state into a buffer, removing any synatx from the value
static int cmk_serial_parse_utf8(struct cmk_serial_parse_state *parse, char *buf, size_t buflen) {
   char *dst= buf, *dst_lim= buf + buflen;
   char *src= parse->buf->data + parse->value_ofs, *src_lim= src + parse->value_len;
   if (dst >= dst_lim || src >= src_lim)
      return -1;
   // If first char is ' ', then simply copy every line, omitting the first ' ' char on each
   if (*src == ' ') {
      while (src < src_lim) {
         char *line= ++src; // skip over initial space char
         size_t len;
         while (src < src_lim && *src != '\n') {
            // Verify utf8-validity if it is a high character
            if (*src & 0x80) {
               if ((*src & 0xE0) == 0xC0) { // 2-byte sequence
                  if (src+1 >= src_lim || (src[1] & 0xC0) != 0x80)
                     return -1;
               }
               else if ((*src & 0xF0) == 0xE0) { // 3-byte sequence
                  if (src+2 >= src_lim || (src[1] & 0xC0) != 0x80 || (src[2] & 0xC0) != 0x80)
                     return -1;
               }
               else if ((*src & 0xF8) == 0xF0) { // 4-byte sequence
                  if (src+3 >= src_lim || (src[1] & 0xC0) != 0x80 || (src[2] & 0xC0) != 0x80 || (src[3] & 0xC0) != 0x80)
                     return -1;
               }
               else return -1; // invalid start byte
            }
            src++;
         }
         if (src < src_lim) src++; // if ended due to '\n', include '\n' in string
         len= src - line;
         if (len > 0) {
            if (dst + len > dst_lim)
               return -1; // dst buffer overflow
            memcpy(dst, line, len);
            dst += len;
         }
      }
   }
   else {
      return -1; // unknown format
   }
   return (int)(dst - buf);
}
}

// SBINI_FORMAT_HEX
extern size_t secret_buffer_ini_decode_value(secret_buffer_ini *ini, secret_buffer *buf, char *out, size_t out_sz, unsigned flags) {
   
}

