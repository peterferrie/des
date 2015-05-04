

// DES in C
// Odzhan

#include <string.h>

#include "des.h"

uint8_t sbox[256] = {
  /* S-box 1 */
  0xE4, 0xD1, 0x2F, 0xB8, 0x3A, 0x6C, 0x59, 0x07,
  0x0F, 0x74, 0xE2, 0xD1, 0xA6, 0xCB, 0x95, 0x38,
  0x41, 0xE8, 0xD6, 0x2B, 0xFC, 0x97, 0x3A, 0x50,
  0xFC, 0x82, 0x49, 0x17, 0x5B, 0x3E, 0xA0, 0x6D,
  /* S-box 2 */
  0xF1, 0x8E, 0x6B, 0x34, 0x97, 0x2D, 0xC0, 0x5A,
  0x3D, 0x47, 0xF2, 0x8E, 0xC0, 0x1A, 0x69, 0xB5,
  0x0E, 0x7B, 0xA4, 0xD1, 0x58, 0xC6, 0x93, 0x2F,
  0xD8, 0xA1, 0x3F, 0x42, 0xB6, 0x7C, 0x05, 0xE9,
  /* S-box 3 */
  0xA0, 0x9E, 0x63, 0xF5, 0x1D, 0xC7, 0xB4, 0x28,
  0xD7, 0x09, 0x34, 0x6A, 0x28, 0x5E, 0xCB, 0xF1,
  0xD6, 0x49, 0x8F, 0x30, 0xB1, 0x2C, 0x5A, 0xE7,
  0x1A, 0xD0, 0x69, 0x87, 0x4F, 0xE3, 0xB5, 0x2C,
  /* S-box 4 */
  0x7D, 0xE3, 0x06, 0x9A, 0x12, 0x85, 0xBC, 0x4F,
  0xD8, 0xB5, 0x6F, 0x03, 0x47, 0x2C, 0x1A, 0xE9,
  0xA6, 0x90, 0xCB, 0x7D, 0xF1, 0x3E, 0x52, 0x84,
  0x3F, 0x06, 0xA1, 0xD8, 0x94, 0x5B, 0xC7, 0x2E,
  /* S-box 5 */
  0x2C, 0x41, 0x7A, 0xB6, 0x85, 0x3F, 0xD0, 0xE9,
  0xEB, 0x2C, 0x47, 0xD1, 0x50, 0xFA, 0x39, 0x86,
  0x42, 0x1B, 0xAD, 0x78, 0xF9, 0xC5, 0x63, 0x0E,
  0xB8, 0xC7, 0x1E, 0x2D, 0x6F, 0x09, 0xA4, 0x53,
  /* S-box 6 */
  0xC1, 0xAF, 0x92, 0x68, 0x0D, 0x34, 0xE7, 0x5B,
  0xAF, 0x42, 0x7C, 0x95, 0x61, 0xDE, 0x0B, 0x38,
  0x9E, 0xF5, 0x28, 0xC3, 0x70, 0x4A, 0x1D, 0xB6,
  0x43, 0x2C, 0x95, 0xFA, 0xBE, 0x17, 0x60, 0x8D,
  /* S-box 7 */
  0x4B, 0x2E, 0xF0, 0x8D, 0x3C, 0x97, 0x5A, 0x61,
  0xD0, 0xB7, 0x49, 0x1A, 0xE3, 0x5C, 0x2F, 0x86,
  0x14, 0xBD, 0xC3, 0x7E, 0xAF, 0x68, 0x05, 0x92,
  0x6B, 0xD8, 0x14, 0xA7, 0x95, 0x0F, 0xE2, 0x3C,
  /* S-box 8 */
  0xD2, 0x84, 0x6F, 0xB1, 0xA9, 0x3E, 0x50, 0xC7,
  0x1F, 0xD8, 0xA3, 0x74, 0xC5, 0x6B, 0x0E, 0x92,
  0x7B, 0x41, 0x9C, 0xE2, 0x06, 0xAD, 0xF3, 0x58,
  0x21, 0xE7, 0x4A, 0x8D, 0xFC, 0x90, 0x35, 0x6B
};

uint8_t e_permtab[] = {
	 4,  6, 					/* 4 bytes in 6 bytes out*/
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

uint8_t p_permtab[] = {
	 4,  4,						/* 32 bit -> 32 bit */
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};

uint8_t ip_permtab[] = {
	 8,  8,						/* 64 bit -> 64 bit */
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

uint8_t inv_ip_permtab[] = {
	 8, 8,						/* 64 bit -> 64 bit */
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

uint8_t pc1_permtab[] = {
	 8,  7, 					/* 64 bit -> 56 bit*/
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

uint8_t pc2_permtab[] = {
	 7,	 6, 					/* 56 bit -> 48 bit */
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

uint8_t splitin6bitword_permtab[] = {
	 8,  8, 					/* 64 bit -> 64 bit */
	64, 64,  1,  6,  2,  3,  4,  5, 
	64, 64,  7, 12,  8,  9, 10, 11, 
	64, 64, 13, 18, 14, 15, 16, 17, 
	64, 64, 19, 24, 20, 21, 22, 23, 
	64, 64, 25, 30, 26, 27, 28, 29, 
	64, 64, 31, 36, 32, 33, 34, 35, 
	64, 64, 37, 42, 38, 39, 40, 41, 
	64, 64, 43, 48, 44, 45, 46, 47 
};

uint8_t shiftkey_permtab[] = {
	 7,  7, 					/* 56 bit -> 56 bit */
	 2,  3,  4,  5,  6,  7,  8,  9,
	10, 11, 12, 13, 14, 15, 16, 17,
	18, 19, 20, 21, 22, 23, 24, 25, 
	26, 27, 28,  1, 
	30, 31, 32, 33, 34, 35, 36, 37, 
	38, 39, 40, 41, 42, 43, 44, 45, 
	46, 47, 48, 49, 50, 51, 52, 53, 
	54, 55, 56, 29
};

uint8_t shiftkeyinv_permtab[] = {
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

void str2key (void *str, des_blk* key) {
  uint32_t x1, r1, *p1;
  des_blk *s=(des_blk*)str;
  int i, j;

  for (i=0; i<2; i++) {
    p1=(uint32_t*)&s->v8[i*3];
    x1=SWAP32(*p1);
    if (i==1) {
      x1=ROL32 (x1, 4);
    }
    r1=0;
    for (j=0; j<4; j++) {
      r1 = ROL32((r1 | (x1 & 0xFE000000)), 8);
      x1 <<= 7;
    }
    key->v32[i] = SWAP32(r1);
  }
}

/******************************************************************************/
void permute (uint8_t ptbl[], void *input, des_blk *out) {
	uint8_t ob;
	uint8_t byte, bit, x, t;
  uint8_t *p=ptbl, *in=(uint8_t*)input;
  
	ob = p[1];
	p  = &p[2];
  
	for (byte=0; byte<ob; ++byte) {
		t=0;
		for (bit=0; bit<8; ++bit) {
			x = *p++ - 1;
		  t <<= 1;
			if ((in[x / 8]) & (0x80 >> (x % 8)) ){
				t |= 0x01;
			}
		}
		out->v8[byte]=t;
	}
}

/******************************************************************************/
void shiftkey (des_blk *key_in, int type) {
	des_blk tmp_key;
  
	memcpy (tmp_key.v8, key_in->v8, 7);
  
  if (type==DES_ENCRYPT) {
    permute (shiftkey_permtab, &tmp_key, key_in);
  } else {
    permute (shiftkeyinv_permtab, &tmp_key, key_in);
  }    
}

/******************************************************************************/
void splitin6bitwords (des_blk *x) {
  des_blk t;
  
	t.v64 = x->v64 & 0x0000ffffffffffffLL;
  
	permute (splitin6bitword_permtab, &t, x);
}

/******************************************************************************/
uint8_t substitute (uint8_t a, uint8_t *sbp) {
	uint8_t x;
  
	x = sbp[a >> 1];
	x = (a & 1) ? x & 0x0F : x >> 4;
  
	return x;
}

/******************************************************************************/

void des_f (des_blk *data_in, des_blk *key) {
	uint8_t  i, x;
	uint32_t t=0, L, R;
	uint8_t *sbp;
  des_blk tmp_data, tmp_key, res;
	
  // load data
  L=data_in->v32[0];
  R=data_in->v32[1];
  
  // permute 1 half of data
  permute (e_permtab, &R, &tmp_data);
  
  // permute key
  permute (pc2_permtab, key, &tmp_key);
  
  // mix key with data
	for (i=0; i<7; i++)
		tmp_data.v8[i] ^= tmp_key.v8[i];
	
  // split data into 6bit words
	splitin6bitwords (&tmp_data);
	sbp=sbox;
  
	for(i=0; i<8; ++i) {
		x = substitute (tmp_data.v8[i], sbp);
		t <<= 4;
		t |= x;
		sbp += 32;
	}
	t=SWAP32(t);

	permute (p_permtab, &t, &res);
  
  // xor
  L ^= res.v32[0];
  
  // save swapped
  data_in->v32[1]=L;
  data_in->v32[0]=R;
}

// perform initial permutation on input
// perform permuted choice 1 on key
void start_enc (void *data_in, des_blk *data_out, void *key_in, des_blk *key_out)
{
  permute (ip_permtab, data_in, data_out);
	permute (pc1_permtab, key_in, key_out);
}

// perform final permutation
void end_enc (des_blk *data_out, des_blk *data_in)
{
  uint32_t L, R;
  
  L=data_in->v32[0];
  R=data_in->v32[1];
  
	R ^= L;
	L ^= R;
	R ^= L;
  
  data_in->v32[0]=L;
  data_in->v32[1]=R;
  
	permute (inv_ip_permtab, data_in, data_out);
}
/******************************************************************************/ 

void update_key (des_blk *key, uint8_t rnd_idx, int type)
{
  shiftkey (key, type);

  if (ROTTABLE & (1 << rnd_idx)) {
    shiftkey (key, type);
  }
}  

void des_enc (void *ct, void *pt, void *key) {
  des_blk tmp_data, tmp_key;
	uint8_t  i;
  
  start_enc (pt, &tmp_data, key, &tmp_key);
  
	for (i=0; i<16; i++) {
    update_key (&tmp_key, i, DES_ENCRYPT);
    des_f (&tmp_data, &tmp_key);
	}
  end_enc (ct, &tmp_data);
}

/******************************************************************************/

void des_dec (void *pt, void *ct, void *key) {
  des_blk tmp_data, tmp_key;
	uint8_t  i;
  
	start_enc (ct, &tmp_data, key, &tmp_key);
  
	for (i=15; i>=0; --i) {
    des_f (&tmp_data, &tmp_key);
    update_key (&tmp_key, i, DES_DECRYPT);
	}
  end_enc (pt, &tmp_data);
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
/******************************************************************************/

// xor dst blk by src
void blkxor (des_blk *dst, des_blk *src)
{
  uint8_t i;

  for (i=0; i<DES_BLK_LEN; i++) {
    dst->v8[i] ^= src->v8[i];
  }
}

// copy src blk to dst
void blkcpy (des_blk *dst, des_blk *src)
{
  uint8_t i;

  for (i=0; i<DES_BLK_LEN; i++) {
    dst->v8[i] = src->v8[i];
  }
}

// clear block
void blkclr (des_blk *blk)
{
  uint8_t i;

  for (i=0; i<DES_BLK_LEN; i++) {
    blk->v8[i] = 0;
  }
}

// perform encryption in CBC mode
void des_cbc_enc (void *data_out, void *data_in, 
  uint32_t len, des_blk *iv, void *key)
{
  des_blk t;
  des_blk *in=(des_blk*)data_in;
  des_blk *out=(des_blk*)data_out;
  int r;
  
  // encrypt 64-bit blocks
  do {
    // clear t
    blkclr (&t);
    // copy 1 block or whatever is remaining to t
    r=(len > DES_BLK_LEN) ? DES_BLK_LEN : len;
    memcpy (t.v8, in->v8, r);
    // xor iv with t
    blkxor (&t, iv);
    des_enc (out, &t, key);
    blkcpy (iv, out);
    len -= r;
    in++;
    out++;
  } while (r == DES_BLK_LEN);
}

// perform decryption in CBC mode
void des_cbc_dec (void *data_out, void *data_in, 
  uint32_t len, des_blk *iv, void *key)
{
  des_blk *in=(des_blk*)data_in;
  des_blk *out=(des_blk*)data_out;
  int r;
  
  // decrypt 64-bit blocks
  do {
    r=(len>DES_BLK_LEN) ? DES_BLK_LEN : len;
    // decrypt block
    des_dec (out, in, key);
    // xor with iv
    blkxor (out, iv);
    // copy cipher text into iv
    blkcpy (iv, in);
    len -= r;
    in++;
    out++;
  } while (r == DES_BLK_LEN);
}

