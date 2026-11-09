#ifndef PATCHIO_H
#define PATCHIO_H

#include <stdint.h>

#define PATCH_BUFFER_SIZE 524288
#define PATCH_MAGIC "ENDSLEY/BSDIFF44"
enum patch_channel { PATCH_CTRL, PATCH_DIFF, PATCH_EXTRA };

/* Sign-magnitude little-endian integers; INT64_MIN cannot be encoded. */
int64_t patch_decode(const uint8_t bytes[8]);
int patch_encode(int64_t value, uint8_t bytes[8]);
int patch_add(int64_t left, int64_t right, int64_t *result);

#endif
