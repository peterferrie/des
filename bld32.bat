@echo off
ml /coff /Cp /c /nologo des_x86.asm
cl /nologo /O1 des_test.c des_x86.obj des.c
del *.obj *.err