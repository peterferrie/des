

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

#define U8V(v)  ((uint8_t)(v)  & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFULL)

#ifdef INTRINSICS
#define ROTL8(v, n) _rotl(v, n)
#define ROTL16(v, n) _rotl(v, n)
#define ROTL32(v, n) _rotl(v, n)
#define ROTL64(v, n) _rotl64(v, n)
#else
#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))
#endif

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

#define SWAP16(v) \
  ROTL16(v, 8)

#ifdef INTRINSICS
#define SWAP32(v) _byteswap_ulong (v)
#else
#define SWAP32(v) \
  ((ROTL32(v,  8) & 0x00FF00FFUL) | \
   (ROTL32(v, 24) & 0xFF00FF00UL))
#endif

#define SWAP64(v) \
  ((ROTL64(v,  8) & 0x000000FF000000FFULL) | \
   (ROTL64(v, 24) & 0x0000FF000000FF00ULL) | \
   (ROTL64(v, 40) & 0x00FF000000FF0000ULL) | \
   (ROTL64(v, 56) & 0xFF000000FF000000ULL))
   
/* the FIPS 46-3 (1999-10-25) name for triple DES is triple data encryption algorithm so TDEA.
* Also we only implement the three key mode  */

#ifdef __cplusplus
extern "C" {
#endif

  void des_str2key (void*, des_blk*);

  void des_enc (void*, void*, void*);
  void des_dec (void*, void*, void*);

  void des3_enc (void*, void*, void*, void*, void*);
  void des3_dec (void*, void*, void*, void*, void*);
  
void des_cbc_enc (void*, void*, void*, uint32_t, void*);
uint32_t des_cbc_dec (void*, void*, void*, uint32_t, void*);
  
#ifdef __cplusplus
}
#endif

#endif
