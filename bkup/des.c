



// Tiny implementation of DES originally by Christopher Hertel
// I've implemented CBC mode
// Odzhan

#include "des.h"

#include <openssl/md4.h>

void permute (uint8_t *dst, uint8_t *src, 
  uint8_t *map, uint8_t mapsize)
{
  uint8_t i;
  
  for (i=0; i<mapsize; i++) {
    dst[i] = 0;
  }
  
  for (i=0; i<mapsize*8; i++)
  {
    if (GETBIT(src, map[i])) {
      SETBIT( dst, i );
    }
  }
}

void KeyShiftLeft (uint8_t *key, uint8_t numbits)
{
  uint8_t i, j;
  uint8_t keep = key[0];  /* Copy the highest order bits of the key. */

  for (i=0; i<numbits; i++)
  {
    for (j=0; j<7; j++)
    {
      if (j && (key[j] & 0x80))   /* If the top bit of this byte is set. */
        key[j-1] |=  0x01;        /* ...shift it to last byte's low bit. */
      key[j] <<= 1;               /* Then left-shift the whole byte.     */
    }

    if (GETBIT(key, 27))     /* If bit 27 is set... */
    {
      CLRBIT(key, 27);        /* ...clear bit 27. */
      SETBIT(key, 55);        /* ...set lowest order bit of 2nd half-key. */
    }

    if (keep & 0x80)
      SETBIT(key, 27);

    keep <<= 1;
  }
}

void KeyShiftRight (uint8_t *key, uint8_t numbits)
{
  int8_t  i, j;
  uint8_t keep = key[6];

  for (i=0; i<numbits; i++)
  {
    for (j=7; j>=0; j--)
    {
      if (j!=7 && (key[j] & 0x01))
        key[j+1] |=  0x80;
      key[j] >>= 1;
    }

    if (GETBIT(key, 28))
    {
      CLRBIT(key, 28);
      SETBIT(key, 0);
    }

    if (keep & 0x01)
      SETBIT(key, 28);

    keep >>= 1;
  }
}

void sbox (uint8_t *dst, const uint8_t *src )
{
  uint8_t i, j, Snum, bitnum;

  for (i=0; i<4; i++)
    dst[i] = 0;

  for (i=0; i<8; i++)
  {
    for (Snum=j=0, bitnum = (i * 6); j<6; j++, bitnum++)
    {
      Snum <<= 1;
      Snum  |= GETBIT( src, bitnum );
    }

    if (0 == (i%2)) {
      dst[i/2] |= ((SBox[i][Snum]) << 4);
    } else {
      dst[i/2] |= SBox[i][Snum];
    }
  }
}

void blkxor (uint8_t *dst, uint8_t *a, uint8_t *b, uint8_t len)
{
  uint8_t i;

  for (i=0; i<len; i++)
    dst[i] = a[i] ^ b[i];
}

void des_setkey (uint8_t *dst, uint8_t *key)
{
  uint8_t i;
  uint8_t tmp[7];

  permute (tmp, key, map8to7, 7);
  
  for (i=0; i<7; i++)
    dst[i] = tmp[i];
}

void des_encrypt (void* out, void* in, void* key)
{
  uint8_t i, j;
  uint8_t *L, *R;
  uint8_t K[7], D[8], Rexp[6], Rn[4], SubK[6];
  
  permute (K, key, KeyPermuteMap, 7);
  permute (D, in, InitialPermuteMap, 8);

  for (i=0; i<16; i++)
  {
    L=D;
    R=&(D[4]);
    
    KeyShiftLeft (K, KeyRotation[i] );
    permute (SubK, K, KeyCompression, 6);

    permute (Rexp, R, DataExpansion, 6);
    blkxor (Rexp, Rexp, SubK, 6);

    sbox (Rn, Rexp);
    permute (Rexp, Rn, PBox, 4);
    blkxor (Rn, L, Rexp, 4);

    for (j=0; j<4; j++)
    {
      L[j] = R[j];
      R[j] = Rn[j];
    }
  }
  permute (out, D, FinalPermuteMap, 8);
}
  
void des_decrypt (void* out, void* in, void* key)
{
  uint8_t i, j;
  uint8_t *L, *R;
  uint8_t K[7], D[8], Rexp[6], Rn[4], SubK[6];
  
  permute (K, key, KeyPermuteMap, 7);
  permute (D, in, InitialPermuteMap, 8);

  for (i=0; i<16; i++)
  {
    L=D;
    R=&(D[4]);
    
    permute (SubK, K, KeyCompression, 6);
    permute (Rexp, R, DataExpansion, 6);
    blkxor (Rexp, Rexp, SubK, 6);

    sbox (Rn, Rexp);
    permute (Rexp, Rn, PBox, 4);
    blkxor (Rn, L, Rexp, 4);

    for (j=0; j<4; j++)
    {
      L[j] = R[j];
      R[j] = Rn[j];
    }
    KeyShiftRight (K, KeyRotation[15 - i] );
  }
  permute (out, D, FinalPermuteMap, 8);
}

void dump (char hdr[], uint8_t bin[], uint8_t len)
{
  uint8_t i;
  printf ("\n%15s : ", hdr);
  for (i=0; i<len; i++) {
    printf ("%02x ", bin[i]);
  }
}

// perform Triple-DES encryption
void des3_encrypt (void *out, void *in, 
  void *key1, void *key2, void *key3)
{
  uint8_t c1[8], c2[8];
  
  des_encrypt (c1, in, key1);
  des_decrypt (c2, c1, key2);
  des_encrypt (out, c2, key3);
}

// perform Triple-DES decryption
void des3_decrypt (void *out, void *in, 
  void *key1, void *key2, void *key3)
{
  uint8_t c1[8], c2[8];
  
  des_decrypt (c1, in, key3);
  des_encrypt (c2, c1, key2);
  des_decrypt (out, c2, key1);
}

// perform encryption in CBC mode
void des_cbc_encrypt (void *out, void *in, 
  uint32_t len, void *iv, void *key)
{
  uint8_t t[DES_BLK_LEN];
  uint8_t *i=(uint8_t*)in;
  uint8_t *o=(uint8_t*)out;
  int j, r;
  
  // encrypt 64-bit blocks
  do {
    // zero t
    memset (t, 0, sizeof t);
    // copy 1 block or whatever is remaining to t
    r=(len > DES_BLK_LEN) ? DES_BLK_LEN : len;
    memcpy (t, i, r);
    // xor iv with t
    blkxor (t, iv, t, DES_BLK_LEN);
    des_encrypt (o, t, key);
    memcpy (iv, o, DES_BLK_LEN);
    len -= r;
    i += DES_BLK_LEN;
    o += DES_BLK_LEN;
  } while (r == DES_BLK_LEN);
}

// perform decryption in CBC mode
void des_cbc_decrypt (void *out, void *in, 
  uint32_t len, void *iv, void *key)
{
  uint8_t t[DES_BLK_LEN];
  uint8_t *i=(uint8_t*)in;
  uint8_t *o=(uint8_t*)out;
  int j, r;
  
  // decrypt 64-bit blocks
  do {
    r=(len>DES_BLK_LEN) ? DES_BLK_LEN : len;
    // decrypt block
    des_decrypt (t, i, key);
    // xor with iv
    blkxor (o, t, iv, DES_BLK_LEN);
    // copy cipher text into iv
    memcpy (iv, i, DES_BLK_LEN);
    len -= r;
    i += DES_BLK_LEN;
    o += DES_BLK_LEN;
  } while (r == DES_BLK_LEN);
}
  
// generate Lanman hash
void lanman (uint8_t *lmhash, uint8_t *pwd)
{
  uint8_t lmpwd[14];
  uint8_t i;
  size_t  len=strlen(pwd);
  // LM passwords don't exceed 14 characters
  len=(len>14) ? 14 : len;
  
  for (i=0; i<14; i++) {
    lmpwd[i]=(i<len) ? toupper (pwd[i]) : 0;
  }
  des_encrypt (&lmhash[0], "KGS!@#$%", &lmpwd[0]);
  des_encrypt (&lmhash[8], "KGS!@#$%", &lmpwd[7]);
}
#ifdef TEST_CODE

// for ms chap
uint8_t chal[24]="\x1f\x3b\xae\x2c\x53\xea\x08\x95\x1f\x3b\xae\x2c\x53\xea\x08\x95\x1f\x3b\xae\x2c\x53\xea\x08\x95"; 
uint8_t lmhash[21]="\x1C\x3A\x2B\x6D\x93\x9A\x10\x21\xAA\xD3\xB4\x35\xB5\x14\x04\xEE\x00\x00\x00\x00\x00";
uint8_t nthash[21]="\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0\x00\x00\x00\x00\x00";

int main (int argc, char *argv[])
{
  uint8_t pwd[32], ct[32], pt[32], iv[32];

  memset (pwd, 0, sizeof pwd);
  strncpy (pwd, argv[1], 7);
  
  memcpy (iv, lmhash, 8);
  
  dump ("PT", chal, 21);
  
  des_cbc_encrypt (ct, chal, 21, iv, pwd);
  dump ("CT", ct, 21);
  dump ("IV", iv, 8);
  
  memcpy (iv, lmhash, 8);
  des_cbc_decrypt (pt, ct, 21, iv, pwd);
  dump ("PT", pt, 21);
  dump ("IV", iv, 8);
  
  return 0;
}
#endif
