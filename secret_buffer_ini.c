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

bool secret_buffer_ini_parse_next(secret_buffer_ini *ini, secret_buffer *buf) {
   
}

// SBINI_FORMAT_HEX
extern size_t secret_buffer_ini_decode_value(secret_buffer_ini *ini, secret_buffer *buf, char *out, size_t out_sz, unsigned flags) {
   
}

