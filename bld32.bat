@echo off
ml /coff /Cp /c /nologo src\x86\rc4.asm
ml /coff /Cp /c /nologo src\x86\rc4x.asm
ml /coff /Cp /c /nologo src\x86\rc4_setkey.asm
lib /nologo /out:lib\x86\rc4.lib rc4.obj rc4x.obj rc4_setkey.obj
cl /nologo /O1 rc4_test.c lib\x86\rc4.lib
move rc4_test.exe bin\x86\
del *.obj *.err