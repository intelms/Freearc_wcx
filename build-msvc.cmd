@echo off
rem ---------------------------------------------------------------------------
rem  Builds the FreeArc WCX plugin for Total Commander with Visual Studio 2017
rem  (MSVC 14.x) - the MinGW equivalent is build.cmd.
rem
rem    build-msvc.cmd            build both x86 and x64
rem    build-msvc.cmd x86        build 32-bit only
rem    build-msvc.cmd x64        build 64-bit only
rem
rem  Differences to the MinGW build:
rem    * vcvarsall.bat is NOT used (it shells out to reg.exe, which some hosts
rem      block).  INCLUDE/LIB/PATH are set from the toolset and SDK directories
rem      found below; VCDIR / SDKROOT / SDKVER may be preset to override them.
rem      When they are not preset, the toolset is looked for under Program Files
rem      and then as an unpacked layout on any drive (see :probe_vc/:probe_sdk),
rem      so the build also works on a machine without Visual Studio installed.
rem    * bzip2dll_msvc32.def / bzip2dll_msvc64.def replace bzip2dll.def, because
rem      MSVC's linker wants the decorated names (_OpenArchive@4) on x86, while
rem      MinGW's --kill-at stripped them.
rem    * msvc-compat\utime.h satisfies FreeArc's POSIX <utime.h> include.
rem    * -include fa_check.h  ->  /FI bzip2dll\fa_check.h
rem    * -fno-exceptions      ->  /EHsc is used instead: the plugin never throws
rem      and FreeArc's CHECK() is redirected to longjmp, so no unwind tables are
rem      executed.  C_CLS.cpp needs exceptions on GCC, and /EHsc covers it.
rem    * freearc_wcx.cpp contains the decompression logic itself (SolidWorker).
rem      Unarc/unarcdll.cpp is compiled with /DFA_MERGED_PLUGIN and linked
rem      into the same PE, so there is no companion unarc_x86.dll /
rem      unarc_x64.dll and no LoadLibrary.  Arc.exe is still required for
rem      PackFiles / DeleteFiles.
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion
set "BZ=%~dp0"
if "%BZ:~-1%"=="\" set "BZ=%BZ:~0,-1%"
set "FA=%BZ%\..\FreeArc-master"
for %%I in ("%FA%") do set "FA=%%~fI"

set "WHAT=%~1"
if "%WHAT%"=="" set "WHAT=both"

if not exist "%FA%\Compression\Common.cpp" (
  echo ERROR: FreeArc sources not found in "%FA%"
  exit /b 1
)
if not exist "%FA%\Unarc\unarcdll.cpp" (
  echo ERROR: Unarc\unarcdll.cpp not found - the driver is linked statically
  exit /b 1
)

rem ---------------------------------------------------------------- toolset ---
if not defined VCDIR (
  for /d %%D in ("C:\Program Files (x86)\Microsoft Visual Studio\2017\*") do (
    if exist "%%D\VC\Tools\MSVC" (
      for /d %%E in ("%%D\VC\Tools\MSVC\*") do set "VCDIR=%%E"
    )
  )
)
if not defined VCDIR (
  for /d %%D in ("C:\Program Files\Microsoft Visual Studio\2017\*") do (
    if exist "%%D\VC\Tools\MSVC" (
      for /d %%E in ("%%D\VC\Tools\MSVC\*") do set "VCDIR=%%E"
    )
  )
)
rem  Offline layouts are routinely unpacked onto a data drive instead of being
rem  installed (this is how the build works on machines without Visual Studio:
rem  the toolset payload.vsix files are extracted somewhere and VCDIR points at
rem  ...\VC\Tools\MSVC\14.xx.xxxxx).  Probe the usual shapes on every drive.
if not defined VCDIR call :probe_vc
if not defined VCDIR (
  echo ERROR: Visual Studio 2017 C++ toolset not found.  Set VCDIR to the
  echo        ...\VC\Tools\MSVC\14.xx.xxxxx directory and run again.
  exit /b 1
)
if not defined SDKROOT if exist "C:\Program Files (x86)\Windows Kits\10\Include" set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
if not defined SDKROOT call :probe_sdk
if not defined SDKROOT (
  echo ERROR: Windows 10 SDK not found.  Set SDKROOT to the ...\Windows Kits\10
  echo        directory and run again.
  exit /b 1
)
if not defined SDKVER (
  for /d %%D in ("%SDKROOT%\Include\10.0.*") do set "SDKVER=%%~nxD"
)
if not exist "%SDKROOT%\Include\%SDKVER%\um\windows.h" (
  echo ERROR: Windows 10 SDK not found below "%SDKROOT%".  Set SDKROOT/SDKVER.
  exit /b 1
)
echo Toolset : %VCDIR%
echo SDK     : %SDKROOT%\Include\%SDKVER%

rem The x64 host compiler needs mspdbcore.dll, which only lives in Common7\IDE
rem (vcvarsall normally puts it on PATH; we do not call vcvarsall).
for %%I in ("%VCDIR%\..\..\..\..") do set "VSROOT=%%~fI"
if exist "%VSROOT%\Common7\IDE\mspdbcore.dll" set "IDE=%VSROOT%\Common7\IDE"

rem  FREEARC_UNARC_DLL and FA_MERGED_PLUGIN apply to every unit now
rem  (FaJmpOnOwnerThread in Common.cpp, non-exit() path in tta.cpp, COMDAT
rem  header implementations).  CHECK itself comes from /FI fa_check.h.
set "DEFS=/DFREEARC_WIN /DFREEARC_INTEL_BYTE_ORDER /DWIN32 /D_WINDOWS /D_UNICODE /DUNICODE /DFREEARC_DECOMPRESS_ONLY /D_NO_EXCEPTIONS /DUNARC /DFREEARC_UNARC_DLL /DFA_MERGED_PLUGIN /D_CRT_SECURE_NO_WARNINGS"
set INCS=/I"%FA%" /I"%FA%\Compression" /I"%FA%\Compression\_Encryption\headers" /I"%FA%\Unarc" /I"%BZ%\msvc-compat"
rem  /GL + /LTCG: whole-program optimisation.  It inlines across the 22 units
rem  (the plugin, the driver and the 20 library units are all one PE here), which
rem  is where the decoder's hot loops gain their last few percent, and drops the
rem  code of the unused helpers (the driver implements both "a" and "x").  /Gy
rem  makes every function its own COMDAT so that dead-stripping can work.
set "CFLAGS=/nologo /c /O2 /GL /Gy /MT /EHsc /W3 /wd4996 /utf-8"
set "LIBS=ole32.lib oleaut32.lib uuid.lib shell32.lib user32.lib gdi32.lib advapi32.lib"

if not exist "%BZ%\plugin" mkdir "%BZ%\plugin"

if /i "%WHAT%"=="both"  set "ARCHS=x86 x64"
if /i "%WHAT%"=="x86"   set "ARCHS=x86"
if /i "%WHAT%"=="x64"   set "ARCHS=x64"

for %%A in (%ARCHS%) do call :build %%A
if errorlevel 1 goto :fail
echo === Done! ===
dir /b "%BZ%\plugin"
exit /b 0

rem ---------------------------------------------------------------------------
:build
set "ARCH=%~1"
if /i "%ARCH%"=="x86" (
  set "HOSTBIN=x86"
  set "SDKARCH=x86"
  set "OUTNAME=bzip2dll.wcx"
  set "MULTINAME=Freearc.wcx"
  set "DEFFILE=bzip2dll_msvc32.def"
  set "OBJ=%BZ%\out_msvc\x86"
) else (
  set "HOSTBIN=x64"
  set "SDKARCH=x64"
  set "OUTNAME=bzip2dll.wcx64"
  set "MULTINAME=Freearc.wcx64"
  set "DEFFILE=bzip2dll_msvc64.def"
  set "OBJ=%BZ%\out_msvc\x64"
)
rem The cross tools sometimes ship without cvtres.exe, which link.exe spawns to
rem convert the .res file; the native toolset directory always has one, so put
rem it at the end of PATH (the cross directory still wins for cl/link/rc).
set "TOOLBIN=%VCDIR%\bin\Hostx86\%HOSTBIN%"
set "EXTRA_BIN="
if not exist "%TOOLBIN%\cvtres.exe" if exist "%VCDIR%\bin\Hostx64\x64\cvtres.exe" set "EXTRA_BIN=%VCDIR%\bin\Hostx64\x64"
if not exist "%TOOLBIN%\cvtres.exe" if not defined EXTRA_BIN if exist "%VCDIR%\bin\Hostx86\x86\cvtres.exe" set "EXTRA_BIN=%VCDIR%\bin\Hostx86\x86"
set "PATH=%TOOLBIN%;%EXTRA_BIN%;%SDKROOT%\bin\%SDKVER%\%SDKARCH%;%IDE%;C:\Windows\system32;C:\Windows"
set "INCLUDE=%VCDIR%\include;%SDKROOT%\Include\%SDKVER%\ucrt;%SDKROOT%\Include\%SDKVER%\shared;%SDKROOT%\Include\%SDKVER%\um;%SDKROOT%\Include\%SDKVER%\winrt;%SDKROOT%\Include\%SDKVER%\cppwinrt"
set "LIB=%VCDIR%\lib\%HOSTBIN%;%SDKROOT%\Lib\%SDKVER%\ucrt\%HOSTBIN%;%SDKROOT%\Lib\%SDKVER%\um\%HOSTBIN%"
if not exist "%OBJ%" mkdir "%OBJ%"

echo.
echo === Building %ARCH% FreeArc WCX plugin with MSVC ===

rc.exe /nologo /I"%BZ%" /fo"%OBJ%\bzip2dll.res" "%BZ%\bzip2dll.rc"
if errorlevel 1 exit /b 1

set "OBJS="
for %%F in ("%FA%\Environment.cpp" "%FA%\Compression\Common.cpp" "%FA%\Compression\CompressionLibrary.cpp" "%FA%\Compression\External\C_External.cpp" "%FA%\Compression\4x4\C_4x4.cpp" "%FA%\Compression\DisPack\C_DisPack.cpp" "%FA%\Compression\LZMA2\C_BCJ.cpp" "%FA%\Compression\LZMA2\C_LZMA.cpp" "%FA%\Compression\Dict\C_Dict.cpp" "%FA%\Compression\Delta\C_Delta.cpp" "%FA%\Compression\REP\C_REP.cpp" "%FA%\Compression\LZP\C_LZP.cpp" "%FA%\Compression\PPMD\C_PPMD.cpp" "%FA%\Compression\MM\C_MM.cpp" "%FA%\Compression\MM\C_TTA.cpp" "%FA%\Compression\Tornado\C_Tornado.cpp" "%FA%\Compression\GRZip\C_GRZip.cpp" "%FA%\Compression\LZ4\C_LZ4.cpp" "%FA%\Compression\_Encryption\C_Encryption.cpp" "%FA%\Compression\CLS\C_CLS.cpp") do (
  rem 7zAES\CpuArch.c calls the MSVC intrinsic __cpuid() but never includes
  rem <intrin.h> - on GCC it takes the inline-asm path instead.  Only the
  rem AES/encryption unit needs the forced include.
  set "EXTRA="
  if /i "%%~nF"=="C_Encryption" set "EXTRA=/FIintrin.h"
  cl.exe %CFLAGS% %DEFS% %INCS% !EXTRA! /FI"%BZ%\fa_check.h" "%%~fF" /Fo"%OBJ%\%%~nF.obj"
  if errorlevel 1 exit /b 1
  set "OBJS=!OBJS! "%OBJ%\%%~nF.obj""
)
cl.exe %CFLAGS% %DEFS% %INCS% /DFA_OWNS_HEADER_IMPL /FI"%BZ%\fa_check.h" "%BZ%\freearc_wcx.cpp" /Fo"%OBJ%\bzip2dll.obj"
if errorlevel 1 exit /b 1
set "OBJS=!OBJS! "%OBJ%\bzip2dll.obj""

rem  The unarc driver, statically linked into this module.
cl.exe %CFLAGS% %DEFS% %INCS% /DFREEARC_LIBRARY /DUNARC_DECRYPTION /FI"%BZ%\fa_check.h" "%FA%\Unarc\unarcdll.cpp" /Fo"%OBJ%\unarcdll.obj"
if errorlevel 1 exit /b 1
set "OBJS=!OBJS! "%OBJ%\unarcdll.obj""

link.exe /nologo /DLL /LTCG /OPT:REF /OPT:ICF /DEF:"%BZ%\%DEFFILE%" /OUT:"%BZ%\plugin\%OUTNAME%" /IMPLIB:"%OBJ%\bzip2dll.lib" /PDB:"%OBJ%\bzip2dll.pdb" !OBJS! "%OBJ%\bzip2dll.res" %LIBS%
if errorlevel 1 exit /b 1

rem Same second copy build.cmd makes, so both build paths produce the same
rem set of files for Total Commander.
copy /Y "%BZ%\plugin\%OUTNAME%" "%BZ%\plugin\%MULTINAME%" >nul

echo --- %OUTNAME% built ---
exit /b 0

:fail
echo.
echo *** BUILD FAILED ***
exit /b 1

rem ---------------------------------------------------------------------------
rem  Toolchain discovery for unpacked (non-installed) layouts.  Nothing here is
rem  specific to one machine: it only looks for the directory shapes a VS
rem  "layout" or an extracted toolset has, on whichever drive it was left on.
:probe_vc
for %%L in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if not defined VCDIR if exist "%%L:\Windows" (
    for %%R in ("%%L:\VSP" "%%L:\vs2017" "%%L:\VCTools" "%%L:\VisualStudio") do (
      if not defined VCDIR if exist "%%~R\VC\Tools\MSVC" (
        for /d %%E in ("%%~R\VC\Tools\MSVC\*") do set "VCDIR=%%E"
      )
    )
  )
)
exit /b 0

:probe_sdk
for %%L in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  if not defined SDKROOT if exist "%%L:\Windows Kits\10\Include" set "SDKROOT=%%L:\Windows Kits\10"
)
exit /b 0

