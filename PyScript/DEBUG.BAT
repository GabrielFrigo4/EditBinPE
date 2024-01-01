@ECHO OFF
cls
set "deb=debug/debug"
gcc %deb%.c -o %deb%.exe 
call "C:\Program Files\Utils\Script\gpupe" %deb%.exe %deb%1.exe
call gpupe %deb%.exe %deb%2.exe
pause