

// DES in C
// Odzhan

#ifndef DES_H
#define DES_H

#include <stdint.h>

#define DES_BLK_LEN 8
#define DES_ROUNDS 16

#define ROTTABLE      0x7EFC 
#define ROTTABLE_INV  0x3F7E

#define DES_ENCRYPT 0
#define DES_DECRYPT 1

typedef union _des_t {
  uint8_t v8[DES_BLK_LEN];
  uint32_t v32[DES_BLK_LEN/4];
  uint64_t v64;
} des_blk;

#define ROL32(a, n)(((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR32(a, n)((((a) & 0xffffffff) >> (n)) | ((a) << (32 - (n))))

#ifdef BIGENDIAN
# define SWAP32(n) (n)
#else
# define SWAP32(n) \
  ROR32((((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)), 16)
#endif

/* the FIPS 46-3 (1999-10-25) name for triple DES is triple data encryption algorithm so TDEA.
* Also we only implement the three key mode  */

#ifdef __cplusplus
extern "C" {
#endif

  void str2key (void*, des_blk*);

  void des_enc (void*, void*, void*);
  void des_dec (void*, void*, void*);

  void des3_enc (void*, void*, void*, void*, void*);
  void des3_dec (void*, void*, void*, void*, void*);
  
#ifdef __cplusplus
}
#endif

#endif
