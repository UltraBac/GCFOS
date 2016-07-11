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

int sendBlock(SOCKET s, const char *buf, int len, int flags = 0);
int recvBlock(SOCKET s, char *buf, int len, int flags = 0);

class Locker {
private:
	CRITICAL_SECTION	m_csWrite;
	CRITICAL_SECTION	m_csReaders;
	LONG volatile		m_ReaderCount;
	HANDLE				m_heWrite;

public:
	Locker() {
		m_ReaderCount = 0;
		InitializeCriticalSection(&m_csReaders);
		InitializeCriticalSection(&m_csWrite);
		m_heWrite = CreateEvent(NULL, TRUE, TRUE, NULL);
		}

	~Locker() {
		CloseHandle(m_heWrite);
		DeleteCriticalSection(&m_csReaders);
		DeleteCriticalSection(&m_csWrite);
		}

	void Read() {
		EnterCriticalSection(&m_csWrite);
		EnterCriticalSection(&m_csReaders);
		m_ReaderCount++;
		ResetEvent(m_heWrite);
		LeaveCriticalSection(&m_csReaders);
		LeaveCriticalSection(&m_csWrite);
		}

	void ReadEnd() {
		EnterCriticalSection(&m_csReaders);
		m_ReaderCount--;
		if(m_ReaderCount <= 0)
			{
			// Indicate that there are no readers now
			m_ReaderCount = 0;
			SetEvent(m_heWrite);
			}
		LeaveCriticalSection(&m_csReaders);
		}

	void Write() {
		EnterCriticalSection(&m_csWrite);
		while(true)
			{
			EnterCriticalSection(&m_csReaders);
			if(m_ReaderCount > 0)
				{
				LeaveCriticalSection(&m_csReaders);
				WaitForSingleObject(m_heWrite, INFINITE);
				continue;
				}
			else
				{
				break;
				}
			}
		}

	void WriteEnd() {
		LeaveCriticalSection(&m_csReaders);
		LeaveCriticalSection(&m_csWrite);
		}
};

#ifndef _UNICODE
#define tobin gcfosclient_tobin_A
#define tohex gcfosclient_tohex_A
#else
#define tobin gcfosclient_tobin_W
#define tohex gcfosclient_tohex_W
void GCFOS_CLIENT_API gcfosclient_tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse = false);
void GCFOS_CLIENT_API gcfosclient_tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse = false);
#endif

void GCFOS_CLIENT_API gcfosclient_tohex_A(LPBYTE p, size_t len, char* out, bool reverse = false);
void GCFOS_CLIENT_API gcfosclient_tobin_A(LPSTR in, size_t len, LPBYTE p, bool reverse = false);

#ifdef _DEBUG
void GcfosClientDebug(LPCSTR fmt, ...);
#endif//_DEBUG
#ifndef _WIN32
typedef struct _MyIOCP {
	pthread_mutex_t qlock;  
	pthread_cond_t qcond;
	std::queue<void *> q;
} MyIOCP, *PMyIOCP;

void InitializeCriticalSection(pthread_mutex_t *m);
void EnterCriticalSection(pthread_mutex_t *m);
void LeaveCriticalSection(pthread_mutex_t *m);
int _tcscpy_s(char * _Dst, int _DstSize, const char * _Src);
WCHAR* _wcsncpy(WCHAR* Dst, WCHAR const* Src, size_t len);
SOCKET WSASocket(int af, int type, int protocol, void * lpProtocolInfo, unsigned int g, DWORD dwFlags);
int WSAIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbBytesReturned, LPVOID lpOverlapped, LPVOID lpCompletionRoutine);
void SetLastError(int32_t newerr);
int32_t GetLastError();
LONG CompareFileTime(FILETIME const *ft1, FILETIME const *ft2);
bool GetFileAttributesEx(LPCSTR filename, DWORD level, PWIN32_FILE_ATTRIBUTE_DATA info);
int32_t WSAGetLastError();
uint32_t GetComputerName(char *name, LPDWORD dwLen);
uint32_t GetComputerNameW(WCHAR *name, LPDWORD dwLen);
char* _tcscat_s(LPSTR dest, DWORD maxlen, LPCSTR src);
size_t _wcslen(LPWSTR str);
LSTATUS RegCreateKeyEx(HKEY hKey, LPCSTR pszKeyPath, DWORD dwResvd, LPSTR lpClass, DWORD dwOptions, DWORD dwAccess, LPVOID secattr, HKEY *result, LPDWORD dwDisposition);
LSTATUS RegOpenKeyEx(HKEY hKey, LPCSTR pszKeyPath, DWORD dwResvd, DWORD dwAccess, HKEY *result);
LSTATUS RegSetValueExW(HKEY hKey, LPCSTR pszValueName, DWORD dwResvd, DWORD dwType, const BYTE *Data, DWORD cbData);
LSTATUS RegSetValueEx(HKEY hKey, LPCSTR pszValueName, DWORD dwResvd, DWORD dwType, const BYTE *Data, DWORD cbData);
LSTATUS RegQueryValueEx(HKEY hKey, LPCSTR pszValueName, LPDWORD dwResvd, LPDWORD dwType, LPBYTE Data, LPDWORD cbData);
LSTATUS RegDeleteValue(HKEY hKey, LPCSTR pszValueName);
LSTATUS RegCloseKey(HKEY hKey);
void QueryPerformanceFrequency(LARGE_INTEGER *li);
void QueryPerformanceCounter(LARGE_INTEGER *li);
void rand_s(PUINT32 val);
void* VirtualAlloc(LPVOID ignored, DWORD dwSize, DWORD options, DWORD security);
void VirtualFree(LPVOID mem, DWORD dwSize, DWORD options);
FILEHANDLE CreateFile(LPCSTR filename, DWORD dwAccess, DWORD dwShareMode, LPVOID Security, DWORD dwCreationDisp, DWORD dwFlags, HANDLE hTemplate);
bool ReadFile(FILEHANDLE hFile, LPVOID buffer, DWORD dwRequested, LPDWORD dwRead, LPVOID o);
bool WriteFile(FILEHANDLE hFile, LPVOID buffer, DWORD dwLen, LPDWORD dwWritten, LPVOID o);
void CloseHandle(FILEHANDLE hFile);
void CloseEvent(EVENTHANDLE hEvent);
BOOL CreateDirectoryA(LPCSTR path, LPVOID IgnoredSecurityAttr);
HANDLE CreateIoCompletionPort(HANDLE FileHandle, HANDLE PreviousHandle, ULONG_PTR Key, DWORD ConcurrentThreads);
BOOL GetQueuedCompletionStatus(HANDLE Port, LPDWORD pdwBytes, PULONG_PTR Key, LPOVERLAPPED *o, DWORD dwMilliseconds);
BOOL PostQueuedCompletionStatus(HANDLE Port, DWORD dwBytes, ULONG_PTR Key, LPOVERLAPPED o);
EVENTHANDLE CreateEvent(PVOID SecAttr, BOOL bManualReset, BOOL bInitialState, LPTSTR name);
BOOL WaitForSingleObject(EVENTHANDLE hEvent, DWORD dwMilliseconds);
DWORD WaitForMultipleObjects(DWORD nCount, EVENTHANDLE *handles, BOOL bWaitAll, DWORD dwMilliseconds);
uintptr_t _beginthread(void (*start_address )( void * ), unsigned stack_size, void *arglist);

#endif//_WIN32
