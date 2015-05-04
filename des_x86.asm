

; DES in x86 assembly
; Odzhan

.686
.model flat

;option epilogue :none
;option prologue :none
option casemap  :none

.code

; esi = permutation table
; ebx = data_in
; edi = data_out
permutex proc
  pushad
  
  ; ob=ptable[1];
  movzx  ecx, byte ptr[esi+1]
  jecxz  exit_permute
  
  xor    eax, eax
  add    esi, 2
byte_loop:
  ; t=0
  xor    edx, edx
  mov    ebp, -8
  push   ecx
bit_loop:
  ; x = *p++ - 1;
  lodsb
  ; just sub 1 from all permutation values
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
  jz     chk_len
  or     dl, 1
chk_len:
  inc    ebp
  jnz    bit_loop
  xchg   eax, edx
  ; out[byte]=t;
  stosb
  pop    ecx
  loop   byte_loop
exit_permute:
  popad
  ret
permutex endp

; ebx = data
splitin6bitwordsx proc
  local  t[2]:dword
  
  pushad
  
  ; a &= 0x0000ffffffffffffLL;
  and    dword ptr[ebx+0], 0FFFFFFFFh
  and    dword ptr[ebx+4], 00000FFFFh
  ; permute((uint8_t*)splitin6bitword_permtab, 
  ;     (uint8_t*)&a, (uint8_t*)&r);
  lea    edi, [t]
  lea    esi, [splitin6bitword_permtab]
  call   permutex
  
  ; save result
  mov    esi, edi
  mov    edi, ebx
  movsd
  movsd
  
  popad
  ret
splitin6bitwordsx endp

substitutex proc
  push   edx
  push   ebx
  ; t = a
  mov    dl, al
  ; a >> 1
  shr    al, 1
  movzx  ebx, al
  ; x = sbp[ a >> 1 ]
  xlatb
  ; x & 0x0F
  and    al, 15
  ; x >> 4
  shr    bl, 4
  ; (a & 1)
  test   dl, 1
  cmove  eax, ebx
  pop    ebx
  pop    edx
  ret
substitutex endp

; in:  esi = key_in
; out: esi = shifted key
shiftkeyx proc
  local tmp_key[8]:byte
  
  pushad
  lea   edi, [tmp_key]
  ; memcpy (tmp_key, key_in, 7);
  push  esi
  push  7
  pop   ecx
  rep   movsb
  
  ; permute (shiftkey_permtab, tmp_key, key_in);
  pop    edi
  lea    ebx, [tmp_key]
  lea    esi, [shiftkey_permtab]
  call   permutex
  popad
  ret
shiftkeyx endp

; update the key bits
; esi = key_in
; ecx = rnd_idx
update_keyx proc
  pushad
  ; shiftkey (k);
  call   shiftkeyx
  
  ; if (0x7EFC & (1 << rnd_idx))
  mov    eax, 07EFCh
  push   1
  pop    ebx
  shl    ebx, cl
  test   ebx, eax
  je     exit_update
  ; shiftkey (k);
  call   shiftkeyx
exit_update:
  popad
  ret
update_keyx endp

start_encx proc stdcall data_in:dword, data_out:dword, key_in:dword, key_out:dword
  pushad
  ; perform initial permutation on input
  ; permute (ip_permtab, data_in, data_out);
  mov    ebx, [data_in]
  mov    edi, [data_out]
  lea    esi, [ip_permtab]
  call   permutex
  
  ; perform permuted choice 1 on key
	; permute (pc1_permtab, key_in, key_out);
  mov    ebx, [key_in]
  mov    edi, [key_out]
  lea    esi, [pc1_permtab]
  call   permutex
  popad
  ret    4*4
start_encx endp

; esi = data_in
; edi = data_out
end_encx proc
  pushad
  mov    ebx, esi
  mov    eax, [ebx+0]
  mov    edx, [ebx+4]
  ; R ^= L;
  xor    edx, eax
  ; L ^= R;
  xor    eax, edx
  ; R ^= L;
  xor    edx, eax
  mov    [ebx+0], eax
  mov    [ebx+4], edx
  ; permute((uint8_t*)inv_ip_permtab, tmp_data, (uint8_t*)data_out);
  lea    esi, [inv_ip_permtab]
  call   permutex
  popad
  ret
end_encx endp

; eax = key_in
; ebx = R
des_fx proc
  local tmp_data[2]:dword
  local f_cnt   :dword
  local t       :dword
  local result  :dword
  
  pushad
  ; permute((uint8_t*)e_permtab, (uint8_t*)&r, (uint8_t*)&tmp_data);
  lea    edi, [tmp_data]
  lea    esi, [e_permtab]
  call   permutex
  
  ; for (i=0; i<7; ++i)
  ;   ((uint8_t*)&data)[i] ^= kr[i];
  push   7
  pop    ecx
  xchg   eax, esi
  push   edi
xor_kr:
  lodsb
  xor    [edi], al
  scasb
  loop   xor_kr
  
  ; data = splitin6bitwords(data);
  pop    ebx
  call   splitin6bitwordsx
  ; i=0
  mov    dword ptr[f_cnt], -8
  ; t=0
  xor    edx, edx
  lea    ebx, [sbox]
  lea    esi, [tmp_data]
f_loop:
  movzx  eax, byte ptr[esi]              ; _data[i]
  inc    esi
  call   substitutex
  ; t <<= 4;
  shl    edx, 4
  ; t  |= 1;
  or     edx, eax
  ; sbp += 32;
  add    ebx, 32
  inc    dword ptr[f_cnt]
  jnz    f_loop
  
  bswap  edx
  mov    [t], edx
  
  ; permute((uint8_t*)p_permtab,(uint8_t*)&t, (uint8_t*)&ret);
  lea    edi, [result]
  lea    ebx, [t]
  lea    esi, [p_permtab]
  call   permutex
  
  mov    eax, [result]
  mov    [esp+28], eax
  popad
  ret
des_fx endp

des_rndx proc
  local tmp_key[8]:byte
  
  pushad
  push   esi
  
  lea    edi, [tmp_key]
  lea    esi, [pc2_permtab]
  ; permute (pc2_permtab, key, tmp_key);
  call   permutex
  
  ; L ^= des_f (R, kr);
  pop    esi
  lodsd
  xchg   eax, ebx
  lodsd
  xchg   eax, ebx
  
  lea    edx, [tmp_key]
  push   edx
  push   ebx
  call   des_fx

  ; swap (L, R);
  xchg   eax, ebx
  popad
  ret
des_rndx endp

des_encx proc C ct:dword, pt:dword, key:dword
  local tmp_data[8] :byte
  local tmp_key[8]  :byte
  
  pushad
  
  ; start_enc (pt, tmp_data, key, tmp_key);
  lea    eax, [tmp_key]
  push   eax
  push   [key]
  lea    eax, [tmp_data]
  push   eax
  push   [pt]
  call   start_encx
  
  ; for (i=0; i<16; i++)
  xor    ecx, ecx
enc_loop:
  ; update_key (tmp_key, i);
  lea    esi, [tmp_key]
  call   update_keyx
  
  ; des_rnd (&tmp_data, tmp_key);
  lea    ebx, [tmp_key]
  lea    esi, [tmp_data]
  call   des_rndx
  
  inc    ecx
  cmp    ecx, 16
  jnz    enc_loop
  
  ; end_enc (ct, &tmp_data);
  mov    edi, [ct]
  call   end_encx
  popad
  ret
des_encx endp

; derived from code originally by Svend Olaf Mikkelson
str2keyx proc C
  pushad
  mov    esi, [esp+32+4] ; str
  mov    edi, [esp+32+8] ; key
  or     ebp, -1
cvt_word:
  lodsd
  dec    esi
  bswap  eax
  inc    ebp
  jz     skip_rot
  rol    eax, 4
skip_rot:
  ; convert 4 bytes
  push   4
  pop    ecx
  xor    edx, edx
cvt_byte:
  mov    ebx, eax
  and    ebx, 0FE000000h
  or     edx, ebx
  rol    edx, 8
  shl    eax, 7
  loop   cvt_byte
  ; save
  xchg   eax, edx
  bswap  eax
  stosd
  cmp    ebp, ecx
  je     cvt_word
  ; exit
  popad
  ret
str2keyx endp

sbox label dword
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

e_permtab label dword
  db  4,  6          ; 4 bytes in 6 bytes out
  db 32,  1,  2,  3,  4,  5
  db  4,  5,  6,  7,  8,  9
  db  8,  9, 10, 11, 12, 13
  db 12, 13, 14, 15, 16, 17
  db 16, 17, 18, 19, 20, 21
  db 20, 21, 22, 23, 24, 25
  db 24, 25, 26, 27, 28, 29
  db 28, 29, 30, 31, 32,  1

p_permtab label dword
  db  4,  4           ; 32 bit -> 32 bit
  db 16,  7, 20, 21
  db 29, 12, 28, 17
  db  1, 15, 23, 26
  db  5, 18, 31, 10
  db  2,  8, 24, 14
  db 32, 27,  3,  9
  db 19, 13, 30,  6
  db 22, 11,  4, 25

ip_permtab label dword
  db  8,  8           ; 64 bit -> 64 bit
  db 58, 50, 42, 34, 26, 18, 10, 2
  db 60, 52, 44, 36, 28, 20, 12, 4
  db 62, 54, 46, 38, 30, 22, 14, 6
  db 64, 56, 48, 40, 32, 24, 16, 8
  db 57, 49, 41, 33, 25, 17,  9, 1
  db 59, 51, 43, 35, 27, 19, 11, 3
  db 61, 53, 45, 37, 29, 21, 13, 5
  db 63, 55, 47, 39, 31, 23, 15, 7

inv_ip_permtab label dword
  db  8, 8            ; 64 bit -> 64 bit
  db 40, 8, 48, 16, 56, 24, 64, 32
  db 39, 7, 47, 15, 55, 23, 63, 31
  db 38, 6, 46, 14, 54, 22, 62, 30
  db 37, 5, 45, 13, 53, 21, 61, 29
  db 36, 4, 44, 12, 52, 20, 60, 28
  db 35, 3, 43, 11, 51, 19, 59, 27
  db 34, 2, 42, 10, 50, 18, 58, 26
  db 33, 1, 41,  9, 49, 17, 57, 25

pc1_permtab label dword
  db  8,  7           ; 64 bit -> 56 bit
  db 57, 49, 41, 33, 25, 17,  9
  db  1, 58, 50, 42, 34, 26, 18
  db 10,  2, 59, 51, 43, 35, 27
  db 19, 11,  3, 60, 52, 44, 36
  db 63, 55, 47, 39, 31, 23, 15
  db  7, 62, 54, 46, 38, 30, 22
  db 14,  6, 61, 53, 45, 37, 29
  db 21, 13,  5, 28, 20, 12,  4
  
pc2_permtab label dword
  db  7,  6           ; 56 bit -> 48 bit
  db 14, 17, 11, 24,  1,  5
  db  3, 28, 15,  6, 21, 10
  db 23, 19, 12,  4, 26,  8
  db 16,  7, 27, 20, 13,  2
  db 41, 52, 31, 37, 47, 55
  db 30, 40, 51, 45, 33, 48
  db 44, 49, 39, 56, 34, 53
  db 46, 42, 50, 36, 29, 32

splitin6bitword_permtab label dword
  db  8,  8           ; 64 bit -> 64 bit
  db 64, 64,  1,  6,  2,  3,  4,  5 
  db 64, 64,  7, 12,  8,  9, 10, 11 
  db 64, 64, 13, 18, 14, 15, 16, 17 
  db 64, 64, 19, 24, 20, 21, 22, 23 
  db 64, 64, 25, 30, 26, 27, 28, 29 
  db 64, 64, 31, 36, 32, 33, 34, 35 
  db 64, 64, 37, 42, 38, 39, 40, 41 
  db 64, 64, 43, 48, 44, 45, 46, 47 

shiftkey_permtab label dword
  db  7,  7           ; 56 bit -> 56 bit
  db  2,  3,  4,  5,  6,  7,  8,  9
  db 10, 11, 12, 13, 14, 15, 16, 17
  db 18, 19, 20, 21, 22, 23, 24, 25 
  db 26, 27, 28,  1 
  db 30, 31, 32, 33, 34, 35, 36, 37 
  db 38, 39, 40, 41, 42, 43, 44, 45 
  db 46, 47, 48, 49, 50, 51, 52, 53 
  db 54, 55, 56, 29

shiftkeyinv_permtab label dword
  db  7,  7          ; 56 bit -> 56 bit
  db 28,  1,  2,  3,  4,  5,  6,  7
  db  8,  9, 10, 11, 12, 13, 14, 15
  db 16, 17, 18, 19, 20, 21, 22, 23
  db 24, 25, 26, 27
  db 56, 29, 30, 31, 32, 33, 34, 35 
  db 36, 37, 38, 39, 40, 41, 42, 43 
  db 44, 45, 46, 47, 48, 49, 50, 51 
  db 52, 53, 54, 55
  
  end