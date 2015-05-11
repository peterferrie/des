@echo off
cl /nologo /O2 des_test.c des.c des_cbc.c
del *.obj *.err