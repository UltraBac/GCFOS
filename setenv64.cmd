cd /d "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC"
call vcvarsall amd64
set DBG_C_FLAGS=/wd4996 /Zm120 /Zi /D_BIND_TO_CURRENT_MFC_VERSION=1 /D_BIND_TO_CURRENT_CRT_VERSION=1 /D_BIND_TO_CURRENT_ATL_VERSION=1 /D_IPP_NO_DEFAULT_LIB  
set REL_C_FLAGS=/wd4996 /Zm120 /Zi /D_BIND_TO_CURRENT_MFC_VERSION=1 /D_BIND_TO_CURRENT_CRT_VERSION=1 /D_BIND_TO_CURRENT_ATL_VERSION=1 /D_IPP_NO_DEFAULT_LIB  
set ADV_LINK_OPTS=/machine:AMD64 /LARGEADDRESSAWARE /SAFESEH:NO 
set dev=%~dp0
set dev=%dev:~0,-1%
cd /d %dev%
set DISP_PLATFORM=a64
set DISTPLATFORM=a64
set INTELLIBS=ippcoremt.lib;ippsmt.lib;ippvmmt.lib;ippdcmt.lib
set IPP_INCLUDE=C:\Program Files (x86)\Intel\Composer XE 2015\ipp\include
set IPP_LIB=C:\Program Files (x86)\Intel\Composer XE 2015\ipp\lib\intel64
set IPP_ROOT=C:\Program Files (x86)\Intel\Composer XE 2015\ipp
set PLATFORM=a64
set PLATFORM2=amd64
set sdkbindir=amd64
set UBPLATFORM=a64
set UB_MIDL_FLAGS=/x64
set INCLUDE=%IPP_INCLUDE%;%DEV%\GCFOS_Client;%INCLUDE%
set LIB=%IPP_LIB%;%LIB%
set GCFOS_ROOT=%dev%
start devenv.exe /useenv

