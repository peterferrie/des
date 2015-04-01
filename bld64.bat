@echo off
ml64 /Cp /c /nologo src\x64\rc4.asm
ml64 /Cp /c /nologo src\x64\rc4x.asm
ml64 /Cp /c /nologo src\x64\rc4_setkey.asm
lib /nologo /out:lib\x64\rc4.lib rc4.obj rc4x.obj rc4_setkey.obj
cl /nologo /O1 rc4_test.c lib\x64\rc4.lib
move rc4_test.exe bin\x64\
del *.obj *.err