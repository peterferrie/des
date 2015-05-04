

// DES in C
// Odzhan

#ifndef DES_H
#define DES_H

#include <stdint.h>

#define DES_BLK_LEN 8

typedef union _DES_DATA {
  uint8_t v8[8];
  uint32_t v32[2];
} DES_DATA;
  
/* the FIPS 46-3 (1999-10-25) name for triple DES is triple data encryption algorithm so TDEA.
 * Also we only implement the three key mode  */

#ifdef __cplusplus
extern "C" {
#endif

void des_enc (void *out, void *in, void *key);
void des_dec (void *out, void *in, void *key);

#ifdef __cplusplus
}
#endif

#endif
