/*
This file forms part of the GCFOS project

Copyright(C) 2014-2016 UltraBac Software, Paul Bunn

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.


This software was developed by Paul Bunn (paul.bunn <at> icloud.com)
Commercial licenses are availble from UltraBac, please contact
sales@ultrabac.com


*/


// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma warning(disable:4127) // conditional expression is constant
#pragma warning(disable:4100) // unreferenced formal parameter

#include <stdint.h>

#ifdef _WIN32
#include "targetver.h"
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define _CRT_RAND_S
#define STRICT

#include <basetsd.h>
#include <tchar.h>
#include <atlstr.h>
#include <winsock2.h>   // for Winsock API
#include <windows.h>    // for Win32 APIs and types
#include <ws2tcpip.h>   // for IPv6 support
#include <wspiapi.h>    // for IPv6 support
#include <strsafe.h>    // for safe versions of string functions
#include <crtdbg.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <process.h>
#include <MSWSock.h>
typedef SSIZE_T ssize_t;
typedef HANDLE EVENTHANDLE;
typedef HANDLE FILEHANDLE;
#define CloseEvent CloseHandle
#define _wcsncpy wcsncpy_s
#define _wcslen wcslen
#else
// LINUX definitions
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <wchar.h>
#include <ctype.h>
#include <queue>
#include <sstream>
#include <algorithm>
#include "pevents.h"
#include "WinTypes.h"

typedef pthread_mutex_t CRITICAL_SECTION;
typedef neosmart::neosmart_event_t EVENTHANDLE;

#define _T(_x) _x
#define TEXT(_x) _x
#define __cdecl
#define CStringA(_x) _x

typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
	DWORD nFileSizeLow;
	DWORD nFileSizeHigh;
	FILETIME ftLastWriteTime;
} WIN32_FILE_ATTRIBUTE_DATA, *PWIN32_FILE_ATTRIBUTE_DATA;
#define GetFileExInfoStandard 0x1

#define ERROR_FILE_NOT_FOUND ENOENT
#define ERROR_INVALID_PARAMETER EINVAL
#define ERROR_ALREADY_EXISTS EEXIST
#define ERROR_USER_MAPPED_FILE EAGAIN // Not sure this is the correct error (error in LMDB may only occur on windows)

typedef int32_t SOCKET;
const SOCKET SOCKET_ERROR = -1;
const SOCKET INVALID_SOCKET = -1;
#define closesocket close
#define WSAECONNRESET ECONNRESET

#define HKEY_CLASSES_ROOT                   (( HKEY )((LONG)0x80000000) )
#define HKEY_CURRENT_USER                   (( HKEY )((LONG)0x80000001) )
#define HKEY_LOCAL_MACHINE                  (( HKEY )((LONG)0x80000002) )
#define HKEY_USERS                          (( HKEY )((LONG)0x80000003) )
#define KEY_READ (0x1) // not the same value on win32
#define KEY_WRITE (0x2) // not the same value on win32
#define REG_DWORD (0x4) // not the same value on win32
#define REG_SZ (0x5) // not the same value on win32

const LSTATUS ERROR_SUCCESS = 0;
#define FIELD_OFFSET(type, field)    ((long)(uintptr_t)&(((type *)0)->field))
#define RTL_FIELD_SIZE(type, field) (sizeof(((type *)0)->field))
#define RTL_SIZEOF_THROUGH_FIELD(type, field) (FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field))

#define MEM_COMMIT 0 // no equivalent on linux
#define MEM_RESERVE 0 // no equivalent on linux
#define PAGE_READWRITE 0 // no equivalent on linux
#define MEM_RELEASE 0 // no equivalent on linux
#define MEM_FREE 0 // no equivalent on linux
#define FILE_FLAG_BACKUP_SEMANTICS 0x200
#define FILE_FLAG_SEQUENTIAL_SCAN 0x100
#define GENERIC_READ 0x400
#define GENERIC_WRITE 0x800
#define OPEN_EXISTING 0x1000
#define CREATE_ALWAYS 0x1001
#define CREATE_NEW 0x1002
#define FILE_SHARE_READ 0x2000
#define FILE_SHARE_WRITE 0x4000
#endif//_WIN32


#include <stack>
#include <stdio.h>      // for printing to stdout.
#include <assert.h>

#include "ipp.h"
#include "ippdc.h"
#include "ippcp.h"

#define _SECOND ((UINT64) 10000000)
#define _MINUTE (60 * _SECOND)
#define _HOUR   (60 * _MINUTE)
#define _DAY    (24 * _HOUR)

#ifdef _DEBUG
#define DEBUGLOG(__x) GcfosClientDebug __x
#else
#define DEBUGLOG(x)
#endif// _DEBUG

#include "lmdb.h"
#include "GCFOS_Client.h"
#include "Helper.h"
#include "gcfosdb.h"
#include "GCFOS_Client_Private.h"
#include "GCFOS_Client_Only.h"
#include "Common.h"

   
       
   
     
   
 
 
 
             
    
 
     

