

; DES in x86 assembly
; 1,079 bytes
; Odzhan

  bits 32

struc pushad_t
  _edi resd 1
  _esi resd 1
  _ebp resd 1
  _esp resd 1
  _ebx resd 1
  _edx resd 1
  _ecx resd 1
  _eax resd 1
  .size:
endstruc
  
  %ifndef BIN
    global _des_str2keyx
    global _des_setkeyx
    global _des_encx
  %endif
  
; esi = permutation table
; ebx = input
; edi = output
_permutex:
permutex:
  pushad
  
  ;mov    esi, [esp+32+ 4] ; ptbl
  ;mov    ebx, [esp+32+ 8] ; input
  ;mov    edi, [esp+32+12] ; out
  
  xor    eax, eax
  push   edi
  stosd
  stosd
  pop    edi
  
  ; ob=ptable[1];
  lodsb
  xchg   eax, ecx
p_l1:
  ; t=0
  cdq
  push   ecx
  xor    ebp, ebp
p_l2:
  ; x = *p++ - 1;
  lodsb
  dec    eax
  ; t <<= 1;
  shl    dl, 1
  ; 0x80 >> (x % 8)
  mov    cl, al
  mov    ch, 80h
  and    cl, 7
  shr    ch, cl
  ; in[x/8];
  shr    al, 3
  xlatb
  ; if (in[x/8] & (0x80 >> (x % 8)))
  test   ch, al
  jz     p_l3
  or     dl, 1
p_l3:
  inc    ebp
  cmp    ebp, 8
  jnz    p_l2
  xchg   eax, edx
  ; out[byte]=t;
  stosb
  pop    ecx
  loop   p_l1
  popad
  ret
  
; eax = input
; esi = key
; return result in eax
_des_fx:
des_fx:
  pushfd
  pushad
  cld

  ;mov    eax, [esp+32+4+4] ; x
  ;mov    esi, [esp+32+8+4] ; key
  
  ; put x in ebx
  xchg   ebx, eax
  ; put key in eax
  xchg   eax, esi
  xor    ecx, ecx
  
  ; allocate 16 bytes
  sub    esp, 16
  lea    ebp, [esp+8] ; ebp has t1
  
  ; permute (e_permtab, x, &t0);
  mov    edi, esp
  mov    esi, e_permtab
  call   permutex
  
  ; put key in esi
  xchg   eax, esi
  mov    cl, 7
df_l1:
  lodsb
  xor    al, [edi]
  stosb
  loop   df_l1
  
  ; permute (splitin6bitword_permtab, &t0, &t1);
  mov    esi, splitin6bitword_permtab
  mov    ebx, esp
  mov    edi, ebp
  call   permutex
  
  mov    esi, ebp
  mov    ebx, sbox
  mov    cl, 8
  xor    edx, edx
  ;int3
df_l2:
  push   ecx
  lodsb
  mov    cl, al
  shr    al, 1
  xlatb
  aam    16
  test   cl, 1
  jnz    df_l3
  mov    al, ah
df_l3:
  shl    edx, 4
  or     dl, al
  add    ebx, 32
  pop    ecx
  loop   df_l2
  
  bswap  edx
  
  ; permute (p_permtab, &t, &t0);
  mov    esi, p_permtab
  mov    edi, esp
  mov    ebx, ebp
  mov    [ebx], edx
  call   permutex
  mov    eax, [edi]
  add    esp, 4*4
  mov    [esp+_eax], eax
  popad
  popfd
  ret
  
_des_setkeyx:
des_setkey:
  pushad
  mov    ebx, [esp+32+8]  ; input
  mov    ebp, [esp+32+4]  ; ctx
  
  ; alloc space for k1, k2
  sub    esp, 16
  
  mov    edx, permutex
  
  ; permute (pc1_permtab, input, &k1);
  mov    esi, pc1_permtab
  mov    edi, esp
  call   edx ; permutex
  xor    ecx, ecx
sk_l1:
  ; permute (shiftkey_permtab, &k1, &k2);
  mov    ebx, esp ; k1
  lea    edi, [ebx+8] ; k2
  mov    esi, shiftkey_permtab
  call   edx ; permutex
  push   1
  pop    eax
  shl    eax, cl
  test   eax, 07EFCh
  xchg   ebx, edi    ; k2 is k
  jz     sk_l2
  ;jz     sk_l2
  ; permute (shiftkey_permtab, &k2, &k1);
  call   edx ; permutex
  mov    ebx, edi ; now k2 is k
sk_l2:
  ; permute (pc2_permtab, k, &ctx->keys[rnd]);
  mov    esi, pc2_permtab
  mov    edi, ebp
  call   edx ; permutex
  ; memcpy (k1.v8, k->v8, DES_BLK_LEN);
  mov    esi, ebx
  mov    edi, ebp
  movsd
  movsd
  mov    ebp, edi
  ; rnd++
  inc    ecx
  cmp    ecx, 16
  jnz    sk_l1
  ; free stack
  add    esp, ecx
  popad
  ret
  
%define L ebx
%define R edx
  
_des_encx:
des_encx:
  pushad

  mov    eax, [esp+32+ 4] ; ctx
  mov    ebx, [esp+32+ 8] ; in
  mov    ebp, [esp+32+12] ; out
  mov    ecx, [esp+32+16] ; enc

  ; permute (ip_permtab, in, &t0);
  push   ecx
  push   ecx
  mov    edi, esp
  push   eax
  mov    esi, ip_permtab
  call   permutex
  
  mov    esi, edi
  lodsd
  xchg   eax, L
  lodsd
  xchg   eax, R
  pop    esi
  mov    edi, ebp
  
  test   ecx, ecx
  mov    cl, 16
  jz     de_l1
  ; if decrypt, advance key and set direction
  add    esi, 15*8
  std
de_l1:
  ; L ^= des_f (&R, key);
  push   R
  mov    eax, esp
  call   des_fx
  
  xor    L, eax
  pop    eax
  ; swap
  xchg   L, R
  ; key += ofs;
  lodsd
  lodsd
  loop   de_l1
  cld
  
  ; permute (inv_ip_permtab, &t0, out);
  mov    dword[esp], R
  mov    dword[esp+4], L
  mov    ebx, esp
  mov    esi, inv_ip_permtab
  call   permutex
  pop    eax
  pop    eax
  popad
  ret
  
_des_str2keyx:
des_str2keyx:
  pushad
  mov    esi, [esp+32+4] ; str
  mov    edi, [esp+32+8] ; key
  push   2
  pop    ecx
s2k_l1:
  lodsd
  dec    esi
  bswap  eax
  xor    ebp, ebp
  xor    edx, edx
  cmp    ecx, 1
  jnz    s2k_l2
  rol    eax, 4
s2k_l2:
  mov    ebx, eax
  and    ebx, 0FE000000h
  or     edx, ebx
  rol    edx, 8
  shl    eax, 7
  inc    ebp
  cmp    ebp, 4
  jnz    s2k_l2
  
  xchg   eax, edx
  bswap  eax
  stosd
  loop   s2k_l1
  popad
  ret
  
sbox:
  ; S-box 1
  db 0E4h, 0D1h, 02Fh, 0B8h, 03Ah, 06Ch, 059h, 007h
  db 00Fh, 074h, 0E2h, 0D1h, 0A6h, 0CBh, 095h, 038h
  db 041h, 0E8h, 0D6h, 02Bh, 0FCh, 097h, 03Ah, 050h
  db 0FCh, 082h, 049h, 017h, 05Bh, 03Eh, 0A0h, 06Dh
  ; S-box 2
  db 0F1h, 08Eh, 06Bh, 034h, 097h, 02Dh, 0C0h, 05Ah
  db 03Dh, 047h, 0F2h, 08Eh, 0C0h, 01Ah, 069h, 0B5h
  db 00Eh, 07Bh, 0A4h, 0D1h, 058h, 0C6h, 093h, 02Fh
  db 0D8h, 0A1h, 03Fh, 042h, 0B6h, 07Ch, 005h, 0E9h
  ; S-box 3
  db 0A0h, 09Eh, 063h, 0F5h, 01Dh, 0C7h, 0B4h, 028h
  db 0D7h, 009h, 034h, 06Ah, 028h, 05Eh, 0CBh, 0F1h
  db 0D6h, 049h, 08Fh, 030h, 0B1h, 02Ch, 05Ah, 0E7h
  db 01Ah, 0D0h, 069h, 087h, 04Fh, 0E3h, 0B5h, 02Ch
  ; S-box 4 
  db 07Dh, 0E3h, 006h, 09Ah, 012h, 085h, 0BCh, 04Fh
  db 0D8h, 0B5h, 06Fh, 003h, 047h, 02Ch, 01Ah, 0E9h
  db 0A6h, 090h, 0CBh, 07Dh, 0F1h, 03Eh, 052h, 084h
  db 03Fh, 006h, 0A1h, 0D8h, 094h, 05Bh, 0C7h, 02Eh
  ; S-box 5
  db 02Ch, 041h, 07Ah, 0B6h, 085h, 03Fh, 0D0h, 0E9h
  db 0EBh, 02Ch, 047h, 0D1h, 050h, 0FAh, 039h, 086h
  db 042h, 01Bh, 0ADh, 078h, 0F9h, 0C5h, 063h, 00Eh
  db 0B8h, 0C7h, 01Eh, 02Dh, 06Fh, 009h, 0A4h, 053h
  ; S-box 6
  db 0C1h, 0AFh, 092h, 068h, 00Dh, 034h, 0E7h, 05Bh
  db 0AFh, 042h, 07Ch, 095h, 061h, 0DEh, 00Bh, 038h
  db 09Eh, 0F5h, 028h, 0C3h, 070h, 04Ah, 01Dh, 0B6h
  db 043h, 02Ch, 095h, 0FAh, 0BEh, 017h, 060h, 08Dh
  ; S-box 7
  db 04Bh, 02Eh, 0F0h, 08Dh, 03Ch, 097h, 05Ah, 061h
  db 0D0h, 0B7h, 049h, 01Ah, 0E3h, 05Ch, 02Fh, 086h
  db 014h, 0BDh, 0C3h, 07Eh, 0AFh, 068h, 005h, 092h
  db 06Bh, 0D8h, 014h, 0A7h, 095h, 00Fh, 0E2h, 03Ch
  ; S-box 8
  db 0D2h, 084h, 06Fh, 0B1h, 0A9h, 03Eh, 050h, 0C7h
  db 01Fh, 0D8h, 0A3h, 074h, 0C5h, 06Bh, 00Eh, 092h
  db 07Bh, 041h, 09Ch, 0E2h, 006h, 0ADh, 0F3h, 058h
  db 021h, 0E7h, 04Ah, 08Dh, 0FCh, 090h, 035h, 06Bh

e_permtab: 
  db 0x06, ; 4 bytes in 6 bytes out
  db 0x02, 0x03, 0x04, 0x05, 0x04, 0x05, 0x06, 0x07
  db 0x08, 0x09, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
  db 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x10, 0x11
  db 0x12, 0x13, 0x14, 0x15, 0x14, 0x15

p_permtab: 
  db 0x04, ; 32 bit -> 32 bit
  db 0x02, 0x03, 0x04, 0x05, 0x04, 0x05, 0x06, 0x07
  db 0x08, 0x09, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
  db 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x10, 0x11
  db 0x12, 0x13, 0x14, 0x15, 0x14, 0x15, 0x16

ip_permtab: 
  db 0x08, ; 64 bit -> 64 bit
  db 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02
  db 0x3c, 0x34, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04
  db 0x3e, 0x36, 0x2e, 0x26, 0x1e, 0x16, 0x0e, 0x06
  db 0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08
  db 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01
  db 0x3b, 0x33, 0x2b, 0x23, 0x1b, 0x13, 0x0b, 0x03
  db 0x3d, 0x35, 0x2d, 0x25, 0x1d, 0x15, 0x0d, 0x05
  db 0x3f, 0x37, 0x2f, 0x27, 0x1f, 0x17, 0x0f, 0x07

inv_ip_permtab: 
  db 0x08, ; 64 bit -> 64 bit
  db 0x28, 0x08, 0x30, 0x10, 0x38, 0x18, 0x40, 0x20
  db 0x27, 0x07, 0x2f, 0x0f, 0x37, 0x17, 0x3f, 0x1f
  db 0x26, 0x06, 0x2e, 0x0e, 0x36, 0x16, 0x3e, 0x1e
  db 0x25, 0x05, 0x2d, 0x0d, 0x35, 0x15, 0x3d, 0x1d
  db 0x24, 0x04, 0x2c, 0x0c, 0x34, 0x14, 0x3c, 0x1c
  db 0x23, 0x03, 0x2b, 0x0b, 0x33, 0x13, 0x3b, 0x1b
  db 0x22, 0x02, 0x2a, 0x0a, 0x32, 0x12, 0x3a, 0x1a
  db 0x21, 0x01, 0x29, 0x09, 0x31, 0x11, 0x39, 0x19

pc1_permtab: 
  db 0x07, ; 64 bit -> 56 bit
  db 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01
  db 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02
  db 0x3b, 0x33, 0x2b, 0x23, 0x1b, 0x13, 0x0b, 0x03
  db 0x3c, 0x34, 0x2c, 0x24, 0x3f, 0x37, 0x2f, 0x27
  db 0x1f, 0x17, 0x0f, 0x07, 0x3e, 0x36, 0x2e, 0x26
  db 0x1e, 0x16, 0x0e, 0x06, 0x3d, 0x35, 0x2d, 0x25
  db 0x1d, 0x15, 0x0d, 0x05, 0x1c, 0x14, 0x0c, 0x04

pc2_permtab: 
  db 0x06, ; 56 bit -> 48 bit
  db 0x0e, 0x11, 0x0b, 0x18, 0x01, 0x05, 0x03, 0x1c
  db 0x0f, 0x06, 0x15, 0x0a, 0x17, 0x13, 0x0c, 0x04
  db 0x1a, 0x08, 0x10, 0x07, 0x1b, 0x14, 0x0d, 0x02
  db 0x29, 0x34, 0x1f, 0x25, 0x2f, 0x37, 0x1e, 0x28
  db 0x33, 0x2d, 0x21, 0x30, 0x2c, 0x31, 0x27, 0x38
  db 0x22, 0x35, 0x2e, 0x2a, 0x32, 0x24, 0x1d, 0x20

splitin6bitword_permtab:
  db 0x08, ; 64 bit -> 64 bit
  db 0x40, 0x40, 0x01, 0x06, 0x02, 0x03, 0x04, 0x05
  db 0x40, 0x40, 0x07, 0x0c, 0x08, 0x09, 0x0a, 0x0b
  db 0x40, 0x40, 0x0d, 0x12, 0x0e, 0x0f, 0x10, 0x11
  db 0x40, 0x40, 0x13, 0x18, 0x14, 0x15, 0x16, 0x17
  db 0x40, 0x40, 0x19, 0x1e, 0x1a, 0x1b, 0x1c, 0x1d
  db 0x40, 0x40, 0x1f, 0x24, 0x20, 0x21, 0x22, 0x23
  db 0x40, 0x40, 0x25, 0x2a, 0x26, 0x27, 0x28, 0x29
  db 0x40, 0x40, 0x2b, 0x30, 0x2c, 0x2d, 0x2e, 0x2f

shiftkey_permtab:
  db 0x07, ; 56 bit -> 56 bit
  db 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
  db 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
  db 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
  db 0x1a, 0x1b, 0x1c, 0x01, 0x1e, 0x1f, 0x20, 0x21
  db 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29
  db 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31
  db 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x1d
  