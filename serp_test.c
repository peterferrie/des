

// SERPENT in C
// Odzhan

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "serpent.h"

char *plain[]=
{ "00000000000000000000000000000000",
  "4528CACCB954D450655E8CFD71CBFAC7",
  "3DA46FFA6F4D6F30CD258333E5A61369"
};

char *keys[]=
{ "80000000000000000000000000000000",
  "000102030405060708090A0B0C0D0E0F1011121314151617",
  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" 
};

char *cipher[]=
{ "264E5481EFF42A4606ABDA06C0BFDA3D",
  "00112233445566778899AABBCCDDEEFF",
  "00112233445566778899AABBCCDDEEFF"  
};

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

int main (int argc, char *argv[])
{
  uint8_t ct1[32], ct2[32], pt[32], key[64];
  serpent_ctx_t ctx;
  int i;
  size_t klen, plen, clen;
  
  for (i=0; i<3; i++) {
    clen=hex2bin (ct1, cipher[i]);
    plen=hex2bin (pt, plain[i]);
    klen=hex2bin (key, keys[i]);
  
    serpent_init (key, klen*8, &ctx);
    serpent_enc (pt, &ctx);
  
    if (memcmp (pt, ct1, clen) == 0) {
      printf ("\nSelf-test for key length %i OK\n", klen*8);
    } else {
      printf ("\nSelf-test for key length %i failed\n", klen*8);
    }
  }
  return 0;
}
