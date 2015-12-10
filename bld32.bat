@echo off
yasm -fwin32 dx.asm -odx.obj
yasm -fbin -DBIN dx.asm -odx.bin
cl /nologo /O2 /Os /Fa /GS- des_test.c des.c des_cbc.c
move des_test.exe c_test.exe
cl /DUSE_ASM /nologo /O2 /Os /Fa /GS- des_test.c des_cbc.c dx.obj
move des_test.exe asm_test.exe
del *.obj *.err