// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#pragma warning(disable:4127) // disable bitching about "while(true)"
#pragma warning(disable:4100) // disable bitching about unreferenced parameters

#define STRICT
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _CRT_RAND_S

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <deque>
#include <process.h>
#include <iostream>
#include <fstream>
#include <queue>
#include <ctime>
#include <winsock2.h>   // for Winsock API
#include <MSWSock.h>

#include "ipp.h"
#include "ippcp.h"

#include "Misc.h"

#ifdef _DEBUG
#define DEBUGLOG(__x) printf __x
#else
#define DEBUGLOG(x)
#endif// _DEBUG


// TODO: reference additional headers your program requires here
