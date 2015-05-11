@echo off
cl /nologo /O2 des_test.c des.c des_cbc.c
echo running x86
openssl dgst -md5 des_test.c
des_test -k "password" -i des_test.c -o test.enc -e
openssl dgst -md5 test.enc
des_test -k "password" -i test.enc -o test.dec -d
openssl dgst -md5 test.dec