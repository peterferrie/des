

// DES in C
// Odzhan

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

char *test_keys[] = 
{ "8000000000000000",
  "0001020304050607",
  "2BD6459F82C5B300",
  "A6A6A6A6A6A6A6A6",
  "9292929292929292" };

char *test_pt[] =
{ "0000000000000000",
  "41AD068548809D02",
  "B10F843097A0F932",
  "11DE2BCE0CB1765A",
  "9292929292929292" };
            
char *test_ct[] =
{ "95A8D72813DAA94D",
  "0011223344556677",
  "EA024714AD5C4D84",
  "A6A6A6A6A6A6A6A6",
  "5B365F2FB2CD7F32" };
  
#ifndef OSSL
#include "des.h"
#else
#include <openssl/des.h>

#pragma comment (lib, "user32.lib")
#pragma comment (lib, "advapi32.lib")

void des_enc (uint8_t out[], uint8_t in[], uint8_t key[])
{
  DES_key_schedule ks;
  
  DES_set_key((const_DES_cblock*)key, &ks);
  DES_ecb_encrypt((const_DES_cblock*) in, (DES_cblock*)out, &ks, DES_ENCRYPT);
}

void des_dec (uint8_t out[], uint8_t in[], uint8_t key[])
{
  DES_key_schedule ks;
  
  DES_set_key((const_DES_cblock*)key, &ks);
  DES_ecb_encrypt((const_DES_cblock*) in, (DES_cblock*)out, &ks, DES_DECRYPT);
}
#endif

void dump (char hdr[], uint8_t bin[], uint8_t len)
{
  uint8_t i;
  printf ("\n%15s : ", hdr);
  for (i=0; i<len; i++) {
    printf ("%02x ", bin[i]);
  }
}

// generate Lanman hash
void lanman (uint8_t *lmhash, uint8_t *pwd)
{
  uint8_t lmpwd[32];
  uint8_t i;
  des_blk key1, key2;
  size_t  len=strlen(pwd);
  
  // LM passwords don't exceed 14 characters
  len=(len>14) ? 14 : len;
  
  for (i=0; i<14; i++) {
    lmpwd[i]=(i<len) ? toupper (pwd[i]) : 0;
  }

  str2key (&lmpwd[0], &key1);
  str2key (&lmpwd[7], &key2);

  des_enc ((des_blk*)&lmhash[0], "KGS!@#$%", &key1);
  des_enc ((des_blk*)&lmhash[8], "KGS!@#$%", &key2);
}
  
size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

void run_tests (void)
{
  int i, plen, clen, klen;

  des_blk ct1, ct2, pt1, pt2, key;
  
  for (i=0; i<sizeof (test_keys)/sizeof(char*); i++)
  { 
    klen=hex2bin (key.v8, test_keys[i]);
    clen=hex2bin (ct1.v8, test_ct[i]);
    plen=hex2bin (pt1.v8, test_pt[i]);
    
    des_enc (ct2.v8, pt1.v8, key.v8);
    
    if (memcmp (ct1.v8, ct2.v8, clen)==0) {
      printf ("\nPassed test #%i", (i+1));
    } else {
      printf ("\nFailed test #%i : "
          "Got %08X %08X instead of %08X %08X for %08X %08X", (i+1), 
          ct2.v32[0], ct2.v32[1], ct1.v32[0], ct1.v32[1],
          pt1.v32[0], pt1.v32[1]);
          
    }
  }
}

void cbc_test (void *pt, int len, void *key, void *iv) {
  des_blk *in=(des_blk*)pt;
  des_blk *ky=(des_blk*)key;
  uint8_t ct[128];
  
  memset (&ct, 0, sizeof (ct));
  
  des_cbc_enc ((des_blk*)ct, in, len, (des_blk*)iv, key);
  dump ("CT", ct, len < DES_BLK_LEN ? DES_BLK_LEN : len);
}

int main (int argc, char *argv[])
{
  char    pwd[16], pt[64], iv[16];
  uint8_t lm[16];
  
  memset (pwd, 0, sizeof (pwd));
  memset (pt, 0,  sizeof (pt));
  memset (iv, 0,  sizeof (iv));
  
  if (argc==2) {
    strncpy (pwd, argv[1], 14);
    lanman (lm, pwd);
    dump ("Lanman", lm, 16);
    return 0;
  } else if (argc == 4) {
    strncpy (pt,  argv[1], sizeof (pt));
    strncpy (pwd, argv[2], DES_BLK_LEN);
    strncpy (iv,  argv[3], DES_BLK_LEN);
    
    cbc_test (pt, strlen(pt), pwd, iv);
  } else {
    run_tests();
  }
  return 0;
}
