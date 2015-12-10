@echo off
yasm -fwin32 dx.asm -odx.obj
cl /nologo /O2 /Os /Fa /GS- des_test.c des.c des_cbc.c dx.obj
del *.obj *.err