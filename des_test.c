

#include "des.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

void blkxor (uint8_t *dst, uint8_t *a, uint8_t *b, uint8_t len)
{
  uint8_t i;

  for (i=0; i<len; i++)
    dst[i] = a[i] ^ b[i];
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
void des3_enc (void *out, void *in, 
  void *key1, void *key2, void *key3)
{
  uint8_t c1[8], c2[8];
  
  des_enc (c1, in, key1);
  des_dec (c2, c1, key2);
  des_enc (out, c2, key3);
}

// perform Triple-DES decryption
void des3_dec (void *out, void *in, 
  void *key1, void *key2, void *key3)
{
  uint8_t c1[8], c2[8];
  
  des_dec (c1, in, key3);
  des_enc (c2, c1, key2);
  des_dec (out, c2, key1);
}

// perform encryption in CBC mode
void des_cbc_enc (void *out, void *in, 
  uint32_t len, void *iv, void *key)
{
  uint8_t t[DES_BLK_LEN];
  uint8_t *i=(uint8_t*)in;
  uint8_t *o=(uint8_t*)out;
  int r;
  
  // encrypt 64-bit blocks
  do {
    // zero t
    memset (t, 0, sizeof t);
    // copy 1 block or whatever is remaining to t
    r=(len > DES_BLK_LEN) ? DES_BLK_LEN : len;
    memcpy (t, i, r);
    // xor iv with t
    blkxor (t, iv, t, DES_BLK_LEN);
    des_enc (o, t, key);
    memcpy (iv, o, DES_BLK_LEN);
    len -= r;
    i += DES_BLK_LEN;
    o += DES_BLK_LEN;
  } while (r == DES_BLK_LEN);
}

// perform decryption in CBC mode
void des_cbc_dec (void *out, void *in, 
  uint32_t len, void *iv, void *key)
{
  uint8_t t[DES_BLK_LEN];
  uint8_t *i=(uint8_t*)in;
  uint8_t *o=(uint8_t*)out;
  int r;
  
  // decrypt 64-bit blocks
  do {
    r=(len>DES_BLK_LEN) ? DES_BLK_LEN : len;
    // decrypt block
    des_dec (t, i, key);
    // xor with iv
    blkxor (o, t, iv, DES_BLK_LEN);
    // copy cipher text into iv
    memcpy (iv, i, DES_BLK_LEN);
    len -= r;
    i += DES_BLK_LEN;
    o += DES_BLK_LEN;
  } while (r == DES_BLK_LEN);
}

#define ROL32(a, n)(((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR32(a, n)((((a) & 0xffffffff) >> (n)) | ((a) << (32 - (n))))

#ifdef BIGENDIAN
# define SWAP32(n) (n)
#else
# define SWAP32(n) \
    ROR32((((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)), 16)
#endif

/**
 *
 *  Convert a string to DES key
 *
 */
void str2key (uint8_t str[], uint8_t key[]) {
  uint32_t x1, x2, r1, r2;
  uint32_t *p1, *p2, *out = (uint32_t*)key;
  int i;

  p1 = (uint32_t*)&str[0];
  p2 = (uint32_t*)&str[3];

  x1 = SWAP32(p1[0]);
  x2 = ROL32(SWAP32(p2[0]), 4);

  for (i = 0, r1 = 0, r2 = 0; i < 4; i++) {
    r1 = ROL32((r1 | (x1 & 0xFE000000)), 8);
    r2 = ROL32((r2 | (x2 & 0xFE000000)), 8);
    x1 <<= 7;
    x2 <<= 7;
  }
  *out++ = SWAP32(r1);
  *out++ = SWAP32(r2);
}

// generate Lanman hash
void lanman (uint8_t *lmhash, uint8_t *pwd)
{
  uint8_t lmpwd[32], key1[16]={0}, key2[16]={0};
  uint8_t i;
  size_t  len=strlen(pwd);
  
  memset (lmpwd, 0, sizeof (lmpwd));
  memset (key1, 0, sizeof (key1));
  memset (key2, 0, sizeof (key2));
  
  // LM passwords don't exceed 14 characters
  len=(len>14) ? 14 : len;
  
  for (i=0; i<14; i++) {
    lmpwd[i]=(i<len) ? toupper (pwd[i]) : 0;
  }
  //des_setkey (key1, &lmpwd[0]);
  str2key (&lmpwd[0], key1);
  str2key (&lmpwd[7], key2);
  //des_setkey (key2, &lmpwd[7]);
  des_enc (&lmhash[0], "KGS!@#$%", key1);
  des_enc (&lmhash[8], "KGS!@#$%", key2);
}

int main (int argc, char *argv[])
{
  uint8_t pwd[32], ct[32]={0}, pt[32], iv[32], key[32]={0};

  uint8_t nes[8]={0x2B,0xD6,0x45,0x9F,0x82,0xC5,0xB3,0x00};
  uint8_t dpt[8]={0xB1,0x0F,0x84,0x30,0x97,0xA0,0xF9,0x32};
  
  if (argc != 2) {
    printf ("\ndes_test <password>\n");
    return 0;
  }
  
  memset (pwd, 0, sizeof pwd);
  strncpy (pwd, argv[1], 14);
  
  lanman (ct, pwd);
  dump ("LM", ct, 16);
  return 0;
}
