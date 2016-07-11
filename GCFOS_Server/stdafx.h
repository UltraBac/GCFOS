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
#define GCFOS_SERVER_PROJECT

#include "targetver.h"

#include <basetsd.h>
#include <stdint.h>
typedef SSIZE_T ssize_t;

#include <btree_set.h>
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
#include <vcclr.h>
#include <atlstr.h>
#include <stack>
#include <forward_list>
#include <set>
#include <iostream>
#include <fstream>
#include <istream>
#include <cstring>
#include <strsafe.h>    // for safe versions of string functions

#include "ipp.h"
#include "ippcp.h"

#pragma warning(push ,2)
#include "lmdb.h"
// #include "db_cxx.h" -- BDB, no longer used
#pragma warning(pop)


#include <atlenc.h>
#include "Locker.h"
#include "GCFOS_Client.h"
#include "Common.h"
#include "GCFOS_Client_Private.h"
#include "S3Repository.h"
#include "FileRepository.h"
#include "AzureRepository.h"
#include "OpenStackRepository.h"
#include "gcfosdb.h"
#include "Misc.h"
#include "Blocks.h"



   
       
   
     
   
 
 
 
             
    
 
     

