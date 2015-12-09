@echo off
cl /nologo /O2 /Os /Fa /GS- des_test.c des.c des_cbc.c
jwasm -bin des.asm
del *.obj *.err