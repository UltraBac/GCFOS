#include "stdafx.h"
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

// sendBlock merely uses send() to send all bytes requested which
// may require repeated calls to send()

GCFOS_CLIENT_LOCALONLY int sendBlock(SOCKET s, const char *buf, int len, int flags /* = 0*/)
{
	int totalsent = 0;
	int sent;
	int databytesready = 0;
	DWORD dwLen;

	while(len)
		{
		WSAIoctl(s, FIONREAD, NULL, 0, &databytesready, sizeof(databytesready), &dwLen, NULL, NULL);
		if(dwLen == sizeof(databytesready) && databytesready > 0)
			return totalsent; // this will likely prompt an error
		sent = send(s, buf, len, flags);
		if(sent == SOCKET_ERROR)
			return SOCKET_ERROR;
		totalsent += sent;
		len -= sent;
		buf += sent;
		}
	return totalsent;
}

GCFOS_CLIENT_LOCALONLY int recvBlock(SOCKET s, char *buf, int len, int flags /* = 0*/)
{
	int received = 0;
	int totalrecd = 0;
	while(len > 0)
		{
		received = recv(s, buf, len, flags);
		if(received == SOCKET_ERROR || received == 0)
			return SOCKET_ERROR;
		totalrecd += received;
		len -= received;
		buf+= received;
		}
	return totalrecd;
}

void gcfosclient_tohex_A(LPBYTE p, size_t len, char* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = p + len - 1;
		}
	else
		{
		in = p;
		}

	while(len--)
		{
		sprintf_s(out, 3, "%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}

void gcfosclient_tobin_A(LPSTR in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}
}

// Unicode versions

#ifdef _UNICODE
void gcfosclient_tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = (LPBYTE)p + len - 1;
		}
	else
		{
		in = (LPBYTE)p;
		}

	while(len--)
		{
		swprintf_s(out, 3, L"%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}
   
void gcfosclient_tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (BYTE)(*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (BYTE)(*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}

}
#endif//_UNICODE

#ifdef _DEBUG
static bool GcfosClientDebug_console = false;
#endif
void GCFOS_Client::SetConsoleLogging(bool bLog)
	{
#ifdef _DEBUG
	GcfosClientDebug_console = bLog;
#endif
	}

#ifdef _DEBUG

void GcfosClientDebug(LPCSTR fmt, ...)
	{
	static bool init = false;
	static CRITICAL_SECTION cs;
	char outstr[1024];
	va_list args;

	if(init == false)
		{
		InitializeCriticalSection(&cs);
		init = true;
		}
	EnterCriticalSection(&cs);
	va_start(args, fmt);
	vsprintf_s(outstr, sizeof(outstr), fmt, args);
	OutputDebugStringA(outstr);
	va_end(args);
	if(GcfosClientDebug_console)
		{
		printf(outstr);
		}
	LeaveCriticalSection(&cs);
	}

#endif//_DEBUG

#ifndef _WIN32
void InitializeCriticalSection(pthread_mutex_t *m)
{
	pthread_mutex_init(m, NULL);
}

void EnterCriticalSection(pthread_mutex_t *m)
{
	pthread_mutex_lock(m);
}

void LeaveCriticalSection(pthread_mutex_t *m)
{
	pthread_mutex_unlock(m);
}

int _tcscpy_s(char * _Dst, int _DstSize, const char * _Src)
{
	snprintf(_Dst, _DstSize, _Src);
}

WCHAR* _wcsncpy(WCHAR* Dst, WCHAR const * Src, size_t len)
{
	WCHAR* Out = Dst;
	while(len > 0)
		{
		*Out++ = *Src++;
		len--;
		}
	*Out = 0;
	return Dst;
}

SOCKET WSASocket(int af, int type, int protocol, void * lpProtocolInfo, unsigned int g, DWORD dwFlags)
{
	return socket(af,type,protocol);
}

int WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPVOID lpOverlapped, LPVOID lpCompletionRoutine)
// this function is really just to provide the simple FIONREAD functionality, not used currently for anything else
{
	int retval;

	retval = ioctl(s, dwIoControlCode, lpvOutBuffer);
	if(retval == 0)
		{
		*lpcbBytesReturned = cbOutBuffer;
		}
	return retval;
}

void SetLastError(int32_t newerr)
{
	errno = newerr;
}
int32_t GetLastError()
{
	return errno;
}

void time_t_to_FILETIME(time_t const t, LPFILETIME ft)
{
	/*
	A FILETIME is the number of 100-nanosecond intervals since January 1, 1601.
	A time_t is the number of 1-second intervals since January 1, 1970.	uint64_t u64ft;
	*/
	uint64_t u64ft;

	u64ft = (t * 10000000ULL) + 11644473600ULL;
	ft->dwHighDateTime = (DWORD)(u64ft >> 32ULL);
	ft->dwLowDateTime = (DWORD)(u64ft);
	return;
}

LONG CompareFileTime(FILETIME const *ft1, FILETIME const *ft2)
{
	int64_t f1,f2, r;
	f1 = ((int64_t)ft1->dwHighDateTime << 32ULL) | ft1->dwLowDateTime;
	f2 = ((int64_t)ft2->dwHighDateTime << 32ULL) | ft2->dwLowDateTime;
	r = f1 - f2;
	if(r < 0)
		{
		return -1;
		}
	else if(r > 0)
		{
		return 1;
		}
	else
		{
		return 0; 
		}
}

bool GetFileAttributesEx(LPCSTR filename, DWORD level, PWIN32_FILE_ATTRIBUTE_DATA info)
{
	struct stat64 stat_info;

	memset(info, 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));

	if(level != GetFileExInfoStandard)
		{
		return false;
		}
	if(stat64(filename, &stat_info) != 0)
		{
		return false;
		}

	info->nFileSizeHigh = (DWORD)(stat_info.st_size >> 32ULL);
	info->nFileSizeLow = (DWORD)(stat_info.st_size);
	time_t_to_FILETIME(stat_info.st_mtime, &info->ftLastWriteTime);
	return true;
	}

int32_t WSAGetLastError()
{
	return GetLastError();
}

uint32_t GetComputerName(char *name, LPDWORD dwLen)
{
	struct utsname uname_info;
	*dwLen = 0;
	DWORD len = 0;
	if(uname(&uname_info) != 0)
		{
		return errno;
		}

	while(len <= MAX_COMPUTERNAME_LENGTH)
		{
		if(uname_info.nodename[len] == 0)
			{
			break;
			}
		name[len] = uname_info.nodename[len];
		len++;
		}
	// GCFOS_COMPUTER_NAME_LENGTH is MAX_COMPUTERNAME_LENGTH+1, so the following is acceptable
	name[len] = 0; // ensure name is terminated (even if truncated)
}

uint32_t GetComputerNameW(WCHAR *name, LPDWORD dwLen)
{
	struct utsname uname_info;
	*dwLen = 0;
	DWORD len = 0;
	if(uname(&uname_info) != 0)
		{
		return errno;
		}

	while(len <= MAX_COMPUTERNAME_LENGTH)
		{
		if(uname_info.nodename[len] == 0)
			{
			break;
			}
		name[len] = uname_info.nodename[len];
		len++;
		}
	// GCFOS_COMPUTER_NAME_LENGTH is MAX_COMPUTERNAME_LENGTH+1, so the following is acceptable
	name[len] = 0; // ensure name is terminated (even if truncated)
}

char* _tcscat_s(LPSTR dest, DWORD maxlen, LPCSTR src)
{
	return strncat(dest, src, maxlen);
}

size_t _wcslen(LPWSTR str)
{
	LPWSTR newstr = str;

	while(*newstr != 0)
		{
		newstr++;
		}
	return newstr - str;
	}

LSTATUS RegCreateKeyEx(HKEY hKey, LPCSTR pszKeyPath, DWORD dwResvd, LPSTR lpClass, DWORD dwOptions, DWORD dwAccess, LPVOID secattr, HKEY *result, LPDWORD dwDisposition)
{
	return RegOpenKeyEx(hKey,pszKeyPath,dwResvd,dwAccess,result);
}

typedef struct _HKEY_OPAQUE_DATA {
	std::string path;
} HKEY_OPAQUE_DATA, *PHKEY_OPAQUE_DATA;

LSTATUS RegOpenKeyEx(HKEY hKey, LPCSTR pszKeyPath, DWORD dwResvd, DWORD dwAccess, HKEY *result)
{
	std::stringstream tmppath;
	PHKEY_OPAQUE_DATA regdata;

	regdata = new HKEY_OPAQUE_DATA;

	if(getenv ("HOME"))
		{
		tmppath << getenv("HOME") << "/.config";
		}
	else
		{
		tmppath <<  "/etc/.config";
		}
	// make sure our "registry" path exists
	mkdir(tmppath.str().c_str(), 0777);
	tmppath << "/gcfos_client";
	mkdir(tmppath.str().c_str(), 0777);
	tmppath << "/" << pszKeyPath << "/";
	regdata->path = tmppath.str();
	std::replace(regdata->path.begin(), regdata->path.end(), '\\', '_'); 
	std::replace(regdata->path.begin(), regdata->path.end(), ' ', '_'); 

	mkdir(regdata->path.c_str(), 0777);
	*result = (HKEY *)regdata;

	return ERROR_SUCCESS;
}

LSTATUS RegSetValueEx(HKEY hKey, LPCSTR pszValueName, DWORD dwResvd, DWORD dwType, const BYTE *Data, DWORD cbData)
{
	PHKEY_OPAQUE_DATA regdata = (PHKEY_OPAQUE_DATA)hKey;
	FILE *hRegFile;
	int ret;
	std::stringstream regfilepath;
	size_t byteswritten;

	regfilepath << regdata->path << pszValueName;
	hRegFile = fopen(regfilepath.str().c_str(), "wb+");
	if(hRegFile != NULL)
		{
		byteswritten = fwrite(Data, 1, cbData, hRegFile);
		if(byteswritten > 0)
			{
			fclose(hRegFile);
			return ERROR_SUCCESS; 
			}
		ret = errno;
		fclose(hRegFile);
		return ret;
		}
	return ENOENT;
}

// this "wide" version auto-translates wide-char strings to a narrow value for storage
// (there is no equivalent "Query", only the narrow values can be read)
LSTATUS RegSetValueExW(HKEY hKey, LPCSTR pszValueName, DWORD dwResvd, DWORD dwType, const BYTE *Data, DWORD cbData)
{
	PHKEY_OPAQUE_DATA regdata = (PHKEY_OPAQUE_DATA)hKey;
	FILE *hRegFile;
	int ret;
	std::stringstream regfilepath;
	size_t byteswritten;
	
	LPBYTE valuetowrite = (LPBYTE)malloc(cbData);
	DWORD i;
	for (i = 0; i < cbData; i++)
		{
		valuetowrite[i] = Data[2 * i];
		if(valuetowrite[i] == 0)
			{
			break;
			}
		}
	cbData /= 2;

	regfilepath << regdata->path << pszValueName;
	hRegFile = fopen(regfilepath.str().c_str(), "wb+");
	if(hRegFile != NULL)
		{
		byteswritten = fwrite(valuetowrite, 1, cbData, hRegFile);
		if(byteswritten > 0)
			{
			fclose(hRegFile);
			free(valuetowrite);
			return ERROR_SUCCESS; 
			}
		ret = errno;
		fclose(hRegFile);
		free(valuetowrite);
		return ret;
		}
	free(valuetowrite);
	return ENOENT;
}

LSTATUS RegQueryValueEx(HKEY hKey, LPCSTR pszValueName, LPDWORD dwResvd, LPDWORD dwType, LPBYTE Data, LPDWORD cbData)
{
	PHKEY_OPAQUE_DATA regdata = (PHKEY_OPAQUE_DATA)hKey;
	FILE *hRegFile;
	int ret;
	std::stringstream regfilepath;
	size_t bytesread;

	regfilepath << regdata->path << pszValueName;
	hRegFile = fopen(regfilepath.str().c_str(), "rb");
	memset(Data, 0, *cbData); // this ensures any REG_SZ's are null-terminated
	if(hRegFile != NULL)
		{
		bytesread = fread(Data, 1, *cbData, hRegFile);
		if(bytesread > 0)
			{
			fclose(hRegFile);
			*cbData = (DWORD)bytesread;
			return ERROR_SUCCESS; 
			}
		ret = errno;
		fclose(hRegFile);
		return ret;
		}
	return ENOENT;
}

LSTATUS RegDeleteValue(HKEY hKey, LPCSTR pszValueName)
{
	PHKEY_OPAQUE_DATA regdata = (PHKEY_OPAQUE_DATA)hKey;
	std::stringstream regfilepath;

	regfilepath << regdata->path << pszValueName;
	if(remove(regfilepath.str().c_str()) == 0)
		return ERROR_SUCCESS;
	else
		return errno;
}

LSTATUS RegCloseKey(HKEY hKey)
{
	PHKEY_OPAQUE_DATA regdata = (PHKEY_OPAQUE_DATA)hKey;

	delete regdata;
	return ERROR_SUCCESS;
}

void QueryPerformanceFrequency(LARGE_INTEGER *li)
{
	li->QuadPart = 0;
}

void QueryPerformanceCounter(LARGE_INTEGER *li)
{
	int64_t value;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	value = ts.tv_sec * 1000000000LL + ts.tv_nsec;
	li->QuadPart = value;
}

void rand_s(PUINT32 val)
{
	*val = lrand48();
}

void* VirtualAlloc(LPVOID ignored, DWORD dwSize, DWORD options, DWORD security)
{
	return malloc(dwSize);
}

void VirtualFree(LPVOID mem, DWORD dwSize, DWORD options)
{
	free(mem);
}

FILEHANDLE CreateFile(LPCSTR filename, DWORD dwAccess, DWORD dwShareMode, LPVOID Security, DWORD dwCreationDisp, DWORD dwFlags, HANDLE hTemplate)
{
	FILE *hFile = NULL;

	switch (dwCreationDisp)
		{
		case CREATE_ALWAYS:
			hFile = fopen(filename, "w+b"); // file overwritten
			break;
		case CREATE_NEW:
			hFile = fopen(filename, "r+b"); // file must exist
			break;
		default:
			hFile = fopen(filename, "rb"); // open for read, existing file
			break;
		}
	if(hFile == NULL)
		{
		return INVALID_HANDLE_VALUE;
		}
	return hFile;
	}

bool ReadFile(FILEHANDLE hFile, LPVOID buffer, DWORD dwRequested, LPDWORD dwRead, LPVOID o)
{
	assert(o == NULL);

	*dwRead = fread(buffer, 1, dwRequested, hFile);
	if(*dwRead < 0)
		{
		return false;
		}
	return true;
}

bool WriteFile(FILEHANDLE hFile, LPVOID buffer, DWORD dwLen, LPDWORD dwWritten, LPVOID o)
{
	assert(o == NULL);
	*dwWritten = fwrite(buffer, 1, dwLen, hFile);
	if(*dwWritten != dwLen)
		{
		return false;
		}
	return true;
}

void CloseHandle(FILEHANDLE hFile)
{
	fclose(hFile);
}

void CloseEvent(EVENTHANDLE hEvent)
{
	neosmart::DestroyEvent(hEvent);
}

BOOL CreateDirectoryA(LPCSTR path, LPVOID IgnoredSecurityAttr)
{
	if(mkdir(path, 777) == 0)
		{
		return TRUE;
		}
	return FALSE;
}

HANDLE CreateIoCompletionPort(HANDLE FileHandle, HANDLE PreviousHandle, ULONG_PTR Key, DWORD ConcurrentThreads)
{
	// This is not a full implementation of an IOCP -- just one for a simple work queue

	PMyIOCP iocp = new MyIOCP;
	pthread_mutex_init(&iocp->qlock, NULL);
	pthread_cond_init(&iocp->qcond, NULL);
	return (HANDLE)iocp;
}

BOOL GetQueuedCompletionStatus(HANDLE Port, LPDWORD pdwBytes, PULONG_PTR Key, LPOVERLAPPED *o, DWORD dwMilliseconds)
{
	PMyIOCP iocp = (PMyIOCP)Port;

	pthread_mutex_lock(&iocp->qlock);
    while (iocp->q.empty())
		{
		pthread_cond_wait(&iocp->qcond, &iocp->qlock);
		}
    *o = (LPOVERLAPPED)iocp->q.front();
    iocp->q.pop();
	pthread_mutex_unlock(&iocp->qlock);
	return TRUE;
}

BOOL PostQueuedCompletionStatus(HANDLE Port, DWORD dwBytes, ULONG_PTR Key, LPOVERLAPPED o)
{
	PMyIOCP iocp = (PMyIOCP)Port;

	pthread_mutex_lock(&iocp->qlock);
	iocp->q.push((void *)o);
	pthread_mutex_unlock(&iocp->qlock);
	pthread_cond_broadcast(&iocp->qcond);
	return TRUE;
}

EVENTHANDLE CreateEvent(PVOID SecAttr, BOOL bManualReset, BOOL bInitialState, LPTSTR name)
{
	EVENTHANDLE evt = neosmart::CreateEvent(bManualReset, bInitialState);

	return evt;
}

BOOL WaitForSingleObject(EVENTHANDLE hEvent, DWORD dwMilliseconds)
{
	// Only waits for EVENTHANDLEs (not file handles, pipes, or any other handles)
//	neosmart::WaitForEvent(hEvent, dwMilliseconds);
	while(neosmart::WaitForEvent(hEvent, 100) == WAIT_TIMEOUT)
		{
		printf("timeout\n");
		}
	return TRUE; 
}

DWORD WaitForMultipleObjects(DWORD nCount, EVENTHANDLE *handles, BOOL bWaitAll, DWORD dwMilliseconds)
{
	// Assumes list of EVENTHANDLEs
	// Always returns 0 (not an index)
	neosmart::WaitForMultipleEvents(handles, nCount, bWaitAll, dwMilliseconds);
	return 0;
}

uintptr_t _beginthread(void (*start_address )( void * ), unsigned stack_size, void *arglist)
{
	int s;
	pthread_t id;
	pthread_attr_t attrs;
	pthread_attr_init(&attrs);
	pthread_attr_setdetachstate(&attrs, PTHREAD_CREATE_DETACHED);
	// the casting is necessary because linux expects a return value (void *)
	// whereas win32 expects no return value (void)
	s = pthread_create(&id, &attrs, (void *(*)(void*))start_address, arglist);
	return 0;
}
#endif//_WIN32
       
   
     
   
 
 
 
             
    
 
     

