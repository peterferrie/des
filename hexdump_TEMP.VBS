:' VBSCRIPT STARTS HERE - DO NOT EDIT!
:'
:'  The MIT License:
:'
:'  Copyright (c) 2010 Kevin Devine
:'
:'  Permission is hereby granted,  free of charge,  to any person obtaining a copy
:'  of this software and associated documentation files (the "Software"),  to deal
:'  in the Software without restriction,  including without limitation the rights
:'  to use,  copy,  modify,  merge,  publish,  distribute,  sublicense,  and/or sell
:'  copies of the Software,  and to permit persons to whom the Software is
:'  furnished to do so,  subject to the following conditions:
:'
:'  The above copyright notice and this permission notice shall be included in
:'  all copies or substantial portions of the Software.
:'
:'  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND,  EXPRESS OR
:'  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
:'  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
:'  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
:'  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  ARISING FROM,
:'  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
:'  THE SOFTWARE.
:'
:
:
:If (WScript.Arguments.Count <> 1) Then
:  WScript.StdOut.WriteLine("Hexdump v0.1 - Copyright (c) 2010 Kevin Devine")
:  WScript.StdOut.WriteLine("Usage: hexdump <file>")
:  WScript.Quit
:Else
:  Dim fso  : Set fso = CreateObject("Scripting.FileSystemObject")
:  Dim file : file = WScript.Arguments(0)
:
:  If (fso.FileExists(file)) Then
:    WScript.StdOut.Write vbNewLine
:    Call HexDump(file)
:  Else
:    WScript.StdOut.WriteLine "Cannot find : " & file
:  End If
:
:  Set fso = Nothing
:  WScript.Quit
:End If
:
:Function HexDump(ByVal file)
:
:  Dim fso    : Set fso    = CreateObject("Scripting.FileSystemObject")
:  Dim stream : Set stream = fso.GetFile(file).OpenAsTextStream(1, False)
:  
:  Dim pos    : pos    = 0
:  Dim hexstr : hexstr = ""
:  Dim ascstr : ascstr = ""
:
:  Do Until stream.AtEndOfStream
:    Dim c : c = stream.Read(1)
:
:    pos = pos + 1
:
:    If (Asc(c) > 31 And Asc(c) < 127) Then
:      ascstr = ascstr & c
:    Else
:      ascstr = ascstr & "."
:    End If
:
:    Dim hexbyte : hexbyte = Hex(Asc(c))
:
:    If (Len(hexbyte) < 2) Then
:      hexbyte = ("0" & hexbyte)
:    End If
:
:    hexstr = hexstr & hexbyte & " "
:
:    If ((pos Mod 16 = 0) Or stream.AtEndOfStream) Then
:      Dim hexpos : hexpos = Hex(pos - 16)
:
:      If (Len(hexpos) < 8) Then
:        hexpos = (String(8 - Len(hexpos), "0") & hexpos)
:      End If
:
:      Dim padding : padding = (48 - Len(hexstr))
:      Wscript.StdOut.WriteLine hexpos & " " & hexstr & Space(padding) & vbTab & ascstr
:
:      hexstr = ""
:      ascstr = ""
:      
:      If (stream.AtEndOfStream) Then
:        Exit Do
:      End If
:    End If
:  Loop
:
:  stream.Close
:
:  Set stream = Nothing
:  Set fso    = Nothing
:
:End Function
