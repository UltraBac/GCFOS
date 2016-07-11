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
#pragma once
#pragma warning(disable:4127) // conditional expression is constant
#pragma warning(disable:4100) // unreferenced formal parameter
#pragma warning(disable:4189) // local variable initialized but unused
#pragma warning(disable:4793) // function compiled as native
#pragma warning(disable:4564) // [xxx] defines unsupported default parameter '[yyy]' (amazon S3)
#pragma warning(disable:4714) // Interlocked commands are generating these warnings (http://msdn.microsoft.com/en-us/library/a98sb923.aspx) does not seem to apply

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S
#define STRICT
#define WIN32_LEAN_AND_MEAN

#define DEBUGLOG(__x) DEBUGLOG_L(3, __x)
#define DEBUGLOG_L(__l, __x) { if(g_debugLvl >= __l) { printf __x; } }

#include <basetsd.h>
#include <stdint.h>
typedef SSIZE_T ssize_t;
#include "btree_set.h"

#include <stdio.h>
#include <tchar.h>
#include <winsock2.h>   // for Winsock API
#include <windows.h>    // for Win32 APIs and types
#include <ws2tcpip.h>   // for IPv6 support
#include <wspiapi.h>    // for IPv6 support
#include <stdio.h>      // for printing to stdout.
#include <process.h>
#include <MSWSock.h>
#include <assert.h>
#include <crtdbg.h>
#include <string>
#include <time.h>
#ifdef __cplusplus_cli
#include <vcclr.h>
#endif//__cplusplus_cli
#include <atlstr.h>
#include <vector>

#include "ipp.h"
#include "ippcp.h"

#include <iostream>
#include <fstream>
#include <istream>
#include <cstring>
#include <strsafe.h>    // for safe versions of string functions

#include <atlenc.h>

#include "helper.h"
#include "lmdb.h"
#include "gcfosdb.h"
#include "gcfos_client.h"
#include "Common.h"