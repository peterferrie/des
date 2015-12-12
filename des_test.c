

// DES in C
// Odzhan

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

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

// generate Lanman hash
void lanman (uint8_t *lmhash, uint8_t *pwd)
{
  uint8_t lmpwd[32];
  uint8_t i;
  des_blk key1, key2;
  size_t  len=strlen(pwd);
  des_ctx ctx;
  
  memset (lmhash, 0, 16);
  
  // MS Lanman passwords don't exceed 14 characters
  len=(len>14) ? 14 : len;
  
  for (i=0; i<14; i++) {
    lmpwd[i]=(i<len) ? toupper (pwd[i]) : 0;
  }

  des_str2key (&lmpwd[0], &key1);
  des_str2key (&lmpwd[7], &key2);

  des_setkey (&ctx, &key1);
  des_enc (&ctx, "KGS!@#$%", (des_blk*)&lmhash[0], DES_ENCRYPT);
  
  des_setkey (&ctx, &key2);
  des_enc (&ctx, "KGS!@#$%", (des_blk*)&lmhash[8], DES_ENCRYPT);
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

int run_tests (void)
{
  int i, plen, clen, klen, fails=0;

  des_blk ct1, ct2, pt1, pt2, key;
  des_ctx ctx;
  
  for (i=0; i<sizeof (test_keys)/sizeof(char*); i++)
  { 
    klen=hex2bin (key.v8, test_keys[i]);
    clen=hex2bin (ct1.v8, test_ct[i]);
    plen=hex2bin (pt1.v8, test_pt[i]);
    
    //des_enc (ct2.v8, pt1.v8, key.v8);
    des_setkey(&ctx, key.v8);
    des_enc (&ctx, pt1.v8, ct2.v8, DES_ENCRYPT);
    des_enc (&ctx, ct2.v8, pt2.v8, DES_DECRYPT);
    
    if (memcmp (pt1.v8, pt2.v8, clen)==0) {
      printf ("\nPassed Encryption/Decryption test #%i %08X %08X", 
        (i+1), pt1.v32[0], pt2.v32[0]);
    } else {
      fails++;
      printf ("\nFailed test #%i : "
          "Got %08X %08X instead of %08X %08X for %08X %08X", (i+1), 
          ct2.v32[0], ct2.v32[1], ct1.v32[0], ct1.v32[1],
          pt1.v32[0], pt1.v32[1]);
          
    }
  }
  return fails;
}

void progress (uint64_t fs_complete, uint64_t fs_total)
{
  uint32_t total, hours=0, minutes=0, seconds=0, speed=0, avg;
  uint64_t pct;
  static uint32_t start=0, current;
  
  if (start==0) {
    start=time(0);
    return;
  }
  
  pct = (100 * fs_complete) / (1 * fs_total);
  
  total = (time(0) - start);
  
  if (total != 0) {
    // (remaining data * time elapsed) / data completed
    avg = (total * (fs_total - fs_complete)) / fs_complete;
    speed = (fs_complete / total);
    
    minutes = (avg / 60);
    seconds = (avg % 60);
  }
  printf ("\rProcessed %llu MB out of %llu MB %lu MB/s : %llu%% complete. ETA: %02d:%02d     ",
    fs_complete/1000/1000, fs_total/1000/1000, speed/1000/1000, pct, minutes, seconds);
}

void DES_genkey (void *out, char *str) 
{
  //des_str2key (str, out);
}

// generate DES hash of file
void DES_file (char infile[], char outfile[], char *key, int crypt)
{
  FILE        *in, *out;
  des_blk     ctx;
  size_t      len;
  uint8_t     buf_in[DES_BLK_LEN*32+64];
  uint8_t     buf_out[DES_BLK_LEN*32+64];
  uint8_t     k[DES_BLK_LEN], iv[DES_BLK_LEN];
  struct stat st;
  uint32_t    cmp=0, total=0, dec_len=0, pad_len, last=0;
  
  in = fopen (infile, "rb");
  
  if (in!=NULL)
  {
    out = fopen (outfile, "wb");
    
    if (out!=NULL)
    {
      stat (infile, &st);
      total=st.st_size;
    
      memset (iv,      0, sizeof (iv));
      memset (buf_in,  0, sizeof (buf_in));
      memset (buf_out, 0, sizeof (buf_out));
      
      DES_genkey (&ctx, key);

      while (len = fread (buf_in, 1, DES_BLK_LEN*32, in)) {
        cmp += len;
        if (cmp > 1000000 && (cmp % 1000000)==0 || cmp==total) {
          progress (cmp, total);
        }//
        // if encrypting, pad
        if (len < DES_BLK_LEN*32) 
        {
          last=1;
          if (crypt==DES_ENCRYPT) 
          {
            memset (&buf_in[len], 0, DES_BLK_LEN*32 - len);
            pad_len=(len % DES_BLK_LEN);
            if (pad_len != 0) 
            {
              dec_len=DES_BLK_LEN - pad_len;

              while (pad_len++ < DES_BLK_LEN) {
                printf ("\npadding");
                buf_in[len++] = dec_len;
              }
            }
          }
        }
        if (crypt==DES_ENCRYPT) {
          des_cbc_enc (&ctx, buf_in, buf_out, len, iv);
        } else {
          des_cbc_dec (&ctx, buf_in, buf_out, len, iv);
          if (last && buf_out[len-1] < DES_BLK_LEN) {
            printf ("\nundoing");
            dec_len=(uint8_t)buf_out[len-1];
            len-= dec_len;
          }
        }
        fwrite (buf_out, 1, len, out);
      }
      fclose (out);
    } else {
      perror ("fopen()");
    }
    fclose (in);
  } else {
    perror ("fopen()");
  }
}

char* getparam (int argc, char *argv[], int *i)
{
  int n=*i;
  if (argv[n][2] != 0) {
    return &argv[n][2];
  }
  if ((n+1) < argc) {
    *i=n+1;
    return argv[n+1];
  }
  printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
  exit (0);
}

void usage (void)
{
  int i;
  
  printf ("\n  usage: DES_test -k <key> -i <file> -o <file>\n");
  printf ("\n  -k <key>    Key");
  printf ("\n  -i <file>   Input file");
  printf ("\n  -o <file>   Output file");
  printf ("\n  -e          Encrypt");
  printf ("\n  -d          Decrypt");
  printf ("\n  -x          Run tests");
  printf ("\n  -l <pwd>    Create Lanman hash\n");
  exit (0);
}

/*
uint32_t *tbls[]=
{ e_permtab
  p_permtab
  ip_permtab
  inv_ip_permtab
  pc1_permtab
  pc2_permtab
  splitin6bitword_permtab
  shiftkey_permtab }; */

/*
uint8_t e_permtab[]  = {
	 4,  6, 					// 4 bytes in 6 bytes out
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

uint8_t p_permtab[]  = {
	 4,  4,						// 32 bit -> 32 bit
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};

uint8_t ip_permtab[]  = {
	 8,  8,						// 64 bit -> 64 bit
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

uint8_t inv_ip_permtab[]  = {
	 8, 8,						// 64 bit -> 64 bit
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

uint8_t pc1_permtab[]  = {
	 8,  7, 					// 64 bit -> 56 bit
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

uint8_t pc2_permtab[]  = {
	 7,	 6, 					// 56 bit -> 48 bit
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

uint8_t splitin6bitword_permtab[]  = {
	 8,  8, 					// 64 bit -> 64 bit
	64, 64,  1,  6,  2,  3,  4,  5, 
	64, 64,  7, 12,  8,  9, 10, 11, 
	64, 64, 13, 18, 14, 15, 16, 17, 
	64, 64, 19, 24, 20, 21, 22, 23, 
	64, 64, 25, 30, 26, 27, 28, 29, 
	64, 64, 31, 36, 32, 33, 34, 35, 
	64, 64, 37, 42, 38, 39, 40, 41, 
	64, 64, 43, 48, 44, 45, 46, 47 
};

uint8_t shiftkey_permtab[]  = {
	 7,  7, 					// 56 bit -> 56 bit
	 2,  3,  4,  5,  6,  7,  8,  9,
	10, 11, 12, 13, 14, 15, 16, 17,
	18, 19, 20, 21, 22, 23, 24, 25, 
	26, 27, 28,  1, 
	30, 31, 32, 33, 34, 35, 36, 37, 
	38, 39, 40, 41, 42, 43, 44, 45, 
	46, 47, 48, 49, 50, 51, 52, 53, 
	54, 55, 56, 29
};

uint8_t shiftkeyinv_permtab[]  = {
	 7,  7,
	28,  1,  2,  3,  4,  5,  6,  7,
	 8,  9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27,
	56, 29, 30, 31, 32, 33, 34, 35, 
	36, 37, 38, 39, 40, 41, 42, 43, 
	44, 45, 46, 47, 48, 49, 50, 51, 
	52, 53, 54, 55
};
*/
void print_tbl (char *s, uint8_t *tbl, uint32_t len)
{
  uint32_t i;
  uint8_t *p=tbl;
  
  p++;
printf ("\n%s:\n  db  0x%02x,", s, *p++);
  
  for (i=0; i<len-2; i++) {
    if ((i % 8)==0) printf("\n  db  ");
    printf ("0x%02x, ", *p++ - 1);
  }
//printf ("};");
}

int main (int argc, char *argv[])
{
  char opt;
  int i, test=0, crypt=DES_ENCRYPT;
  char *in=NULL, *out=NULL, *pwd="password";
  uint8_t lm[32];
  uint32_t x=0x7EFC;
  
  /*print_tbl ("e_permtab",      e_permtab, sizeof(e_permtab));
  print_tbl ("p_permtab",      p_permtab, sizeof(p_permtab));
  print_tbl ("ip_permtab",     ip_permtab, sizeof(ip_permtab));
  print_tbl ("inv_ip_permtab", inv_ip_permtab, sizeof(inv_ip_permtab));
  print_tbl ("pc1_permtab",    pc1_permtab, sizeof(pc1_permtab));
  print_tbl ("pc2_permtab",    pc2_permtab, sizeof(pc2_permtab));
  print_tbl ("splitin6bitword_permtab", splitin6bitword_permtab, sizeof(splitin6bitword_permtab));
  print_tbl ("shiftkey_permtab", shiftkey_permtab, sizeof(shiftkey_permtab));
  
  return 0;*/
  
  // for each argument
  for (i=1; i<argc; i++)
  {
    // is this option?
    if (argv[i][0]=='-' || argv[i][1]=='/')
    {
      // get option value
      opt=argv[i][1];
      switch (opt)
      {
        case 'i':
          in=getparam (argc, argv, &i);
          break;
        case 'd':
          crypt=DES_DECRYPT;
          break;
        case 'e':
          crypt=DES_ENCRYPT;
          break;
        case 'o':
          out=getparam (argc, argv, &i);
          break;
        case 'k':
          pwd=getparam (argc, argv, &i);
          break;
        case 'x':
          test=1;
          break;
        case 'l': {
          pwd=getparam(argc, argv, &i);
          lanman (lm, pwd);
          printf ("\nMS Lanman = ");
          for (i=0; i<16; i++) {
            printf ("%02X", lm[i]);
          }
          return 0;
        }
        default:
          usage ();
          break;
      }
    }
  }
  
  if (test) {
    if (!run_tests()) {
      printf ("\n  [ self-test OK!\n");
    }
  } else if (in!=NULL && out!=NULL && pwd!=NULL) {
    DES_file (in, out, pwd, crypt);
  } else {
    usage ();
  }
  return 0;
}
