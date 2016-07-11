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

// GenSHA1.cpp : Defines the entry point for the console application.
//

#if 0
restore example (cmdline) (note: no 0x prefix, always in hex for size and validation key)
-r -h 00cc199c12becee994ce62af6479bc85b400d285 -s 00013400 -p c:\logs\restore.dat -v 00008a8b (c:\windows\system32\drivers\winusb.sys)

delete one hash from server:
-d cc021bcb0b84a5e34c5aeed6df43c10ed4c15d35 -s 0029c1e3

#endif

#include "stdafx.h"

#include "GCFOS_Client.h"

//#define GENSHA1_CACHE_PATH NULL
#define GENSHA1_CACHE_PATH _T("c:\\Program Files\\UltraBac Software\\UltraBac\\x64\\GCFOSCache\\") // where to store SHA1 cache files db
#define GENSHA1_LOG_PATH _T("c:\\Program Files\\UltraBac Software\\UltraBac\\x64\\GCFOSCache\\") // where to store logfiles 
#define GENSHA1_COMPANY_NAME "UltraBac Software"

GCFOS_Client *client;

TCHAR				localpath[MAX_PATH] = _T("");
BYTE				SHA1[GCFOS_SHA1_LEN];
DWORD				Size;
BYTE				ValidationKey[GCFOS_VALIDATION_KEY_LEN];
bool				bSize = false, bSHA1 = false, bVal = false, bPath = false;
bool				bForceDonate = false;
HANDLE				hsFiles;
HANDLE				heTerminate;
HANDLE				heReleased;
bool				bVerify = false;
bool				bDedupeFiles = false;
CRITICAL_SECTION	csFiles;
CRITICAL_SECTION	csLog;
std::wofstream		hSHALog;
std::wofstream		hSHAResident;
std::wofstream		hSHALimbo;
std::wofstream		hSHAErrors;
std::wstring		sSHALog;
__int64				totalBytesRead = 0;
UINT32				entry;
UINT32				curentry;
UINT32				processed;
UINT32				totalresident = 0;
UINT64				totalresidentsize = 0;
UINT32				totallimbo = 0;
UINT64				totallimbosize = 0;
UINT32				totalsent = 0;
UINT64				totalsentbytes = 0;
UINT32				totalignored = 0;
UINT32				FilesSentOnlyToBlocks = 0;
UINT64				totalUnique = 0;

bool				deletemode = false;

enum OPERATION { ENUMERATE, RESTORE, DEL } op = ENUMERATE;

LARGE_INTEGER		liCounterFreq;
LONGLONG volatile	TotalUnitsSpentInClient = 0;

#define GENSHA1_THREADS 1

#define GENSHA1_CONNECTIONS 1

GCFOS_Client		*GCFOS[GENSHA1_CONNECTIONS];

#if GENSHA1_CONNECTIONS==1
#define GCFOS_IDX(_x) (0)
#else
#define GCFOS_IDX(_x) (_x)
#if GENSHA1_CONNECTIONS != GENSHA1_THREADS
#error GENSHA1_CONNECTIONS must either be 1 or equal to SHA1_THREADS
#endif
#endif

struct threadstate {
	OVERLAPPED			o;
	LPBYTE				buffer;
	HANDLE				hFile;
	HANDLE				hThread;
};

struct WORK_QUEUE {
	LPTSTR	filename;
	UINT64  filesize;
	FILETIME ft;
	};

std::queue<WORK_QUEUE> workq;


threadstate state[GENSHA1_THREADS];


UINT EnumerateFiles(LPCTSTR p)
{
	UINT		c = 0;
	HANDLE		hFind;//, hFile;
	size_t		pathlen = _tcslen(p);
	LPTSTR		np;
	WIN32_FIND_DATA w32fd;

	if(GENSHA1_CACHE_PATH && _tcsicmp(p, GENSHA1_CACHE_PATH) == 0)
		return 0; // don't enumerate our cache files

	np = new TCHAR[pathlen + 4];
	_stprintf(np, _T("%s*.*"), p);

	hFind = FindFirstFile(np, &w32fd);
	delete [] np;

	if(INVALID_HANDLE_VALUE == hFind)
		{
		return 0;
		}

	do
		{
		if(w32fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			{
			_tprintf(_T("Skipping %s%s\n"), p, w32fd.cFileName);
			continue;
			}

		if(w32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
			if(_tcscmp(w32fd.cFileName, _T(".")) == 0 || _tcscmp(w32fd.cFileName, _T("..")) == 0)
				continue; // skip these pseudo-dirs

			np = new TCHAR[pathlen + _tcslen(w32fd.cFileName) + 2];
			_stprintf(np, _T("%s%s\\"), p, w32fd.cFileName);
			c += EnumerateFiles(np);
			delete[] np;
			continue;
			}

		if(_tcsnicmp(w32fd.cFileName, _T("GENSHA1_"), 8) == 0)
			{
			// this is one of "our" files, skip it
			continue;
			}

		c++;

		WORK_QUEUE	q_item;

		q_item.filename = new TCHAR[pathlen + _tcslen(w32fd.cFileName) + 1];
		_stprintf(q_item.filename, _T("%s%s"), p, w32fd.cFileName);

		if(w32fd.nFileSizeHigh || w32fd.nFileSizeLow < GCFOS_FILE_MINIMUM_SIZE)
			{
			if(w32fd.nFileSizeHigh || w32fd.nFileSizeLow > GCFOS_MINIMUM_BLOCK_SIZE)
				{
				InterlockedIncrement(&FilesSentOnlyToBlocks);
				}
			else
				{
				InterlockedIncrement(&totalignored);
				delete q_item.filename;
				continue; // skip files bigger than 4GB or smaller than 32KB
				}
			}

		EnterCriticalSection(&csFiles);

		q_item.filesize = w32fd.nFileSizeLow + ((UINT64)w32fd.nFileSizeHigh << 32LL);
		memcpy(&q_item.ft, &w32fd.ftLastWriteTime, sizeof(FILETIME));
		workq.push(q_item);

		entry++;
		LeaveCriticalSection(&csFiles);
		while(!ReleaseSemaphore(hsFiles, 1, NULL))
			WaitForSingleObject(heReleased, INFINITE);

		} while(FindNextFile(hFind, &w32fd));

	FindClose(hFind);

	return c;

}
bool SendDataBlocksToGCFOS(LPCTSTR filename, int i, INT64 filesize)
	{
	LPBYTE			hashes;
	UINT32			hash_size;
	bool			retval;
	HANDLE			hFile;

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		return false;

	hash_size = GCFOS[GCFOS_IDX(i)]->GetHashDataLengthForFileSize(filesize);
	hashes = (LPBYTE)malloc(hash_size);

	if(GCFOS[GCFOS_IDX(i)]->GetBlockHashesForFile(hFile, filename, hashes, hash_size) > 0)
		retval = true;
	else
		retval = false;
	free(hashes);
	CloseHandle(hFile);
	return retval;

#if 0
	HANDLE			hFile;
	BYTE			buffer[GCFOS_BLOCK_SIZE * GCFOS_BLOCKS_PER_QUERY];
	BYTE			buffer2[GCFOS_BLOCK_SIZE * GCFOS_BLOCKS_PER_QUERY];
	DWORD			dwLen;
	BYTE			hashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	UINT16			blocks, blocks2;
	UINT32			hashsize;
	UINT32			xfer;
	bool			bDiff = false;

	if(!state[i].GCFOS[0]->BlockStoreEnabled())
		return false;

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		hSHAErrors << filename << L" error " << GetLastError() << std::endl;
		return false;
		}

	while(true)
		{
		if(!ReadFile(hFile, &buffer, sizeof(buffer), &dwLen, NULL))
			break;
		blocks = (UINT16)(dwLen / GCFOS_BLOCK_SIZE); // round down to nearest whole block (this might result in no blocks to send)
		if(dwLen % GCFOS_BLOCK_SIZE > GCFOS_MINIMUM_BLOCK_SIZE)
			{
			xfer = dwLen;
			blocks++;
			}
		else
			{
			xfer = blocks * GCFOS_BLOCK_SIZE;
			}
		if(xfer == 0)
			break;
		if(state[i].GCFOS[0]->StoreBlocks(buffer, xfer, hashes, &hashsize) == false)
			{
			CloseHandle(hFile);
			return false;
			}

		if(bVerify)
			{
			if(blocks < GCFOS_BLOCKS_PER_QUERY)
				{
				memset(hashes + (GCFOS_BLOCK_HASH_LEN * blocks), 0, GCFOS_BLOCK_HASH_LEN);
				}
			if(state[i].GCFOS[0]->RetrieveBlocks(hashes, &blocks2, buffer2) == false
			|| memcmp(buffer, buffer2, xfer) != 0)
				bDiff = true;
			}
		}
	CloseHandle(hFile);
	if(bDiff == true)
		{
		printf("%S is different\n", filename);
		}
	return true;
#endif
	}

void GenerateSHA1HashForFile(UINT myentry, UINT i, WORK_QUEUE &item)
{
	Ipp8u			SHA1Bytes[GCFOS_SHA1_LEN];
	WCHAR			hexsha[GCFOS_SHA1_LEN * 2 + 1];
	WCHAR			hexval[9];
	WCHAR			hexsize[9];
	GCFOS_SRV_RESPONSE qr;
	BYTE			ValKey[GCFOS_VALIDATION_KEY_LEN];
	LARGE_INTEGER	liStart, liEnd;
	UINT32			FileSize32;
	
	EnterCriticalSection(&csLog);
	totalBytesRead += item.filesize;
	LeaveCriticalSection(&csLog);

	FileSize32 = (UINT32)item.filesize;

	if(deletemode)
		{
		if(item.filesize >= GCFOS_FILE_MAX_SIZE
		|| item.filesize < GCFOS_FILE_MINIMUM_SIZE)
			{
			return;
			}
	
		_tprintf(_T("Deleting %s\n"), item.filename);
		GCFOS[GCFOS_IDX(i)]->DeleteObject(SHA1Bytes, FileSize32, 0);
		return;
		}

	if(!bDedupeFiles && GCFOS[GCFOS_IDX(i)]->BlockStoreEnabled())
		{
		if(!SendDataBlocksToGCFOS(item.filename, i, item.filesize) == false)
			{
			hSHAErrors << "Send blocks failed for " << item.filename;
			}

		}

	if(item.filesize >= GCFOS_FILE_MAX_SIZE
	|| item.filesize < GCFOS_FILE_MINIMUM_SIZE)
		{
		if(GCFOS[GCFOS_IDX(i)]->BlockStoreEnabled()
		&& SendDataBlocksToGCFOS(item.filename, i, item.filesize) == false)
			{
			hSHAErrors << "Send blocks failed for " << item.filename;
			}
		return;
		}

	if(!GCFOS[GCFOS_IDX(i)]->GetHash(item.filename, item.filename, (LPBYTE)&SHA1Bytes, &item.ft, &FileSize32, ValKey))
		{
		hSHAErrors << item.filename << L"(" << GetLastError() << L")" << std::endl;
		return;
		}

	tohex(SHA1Bytes, GCFOS_SHA1_LEN, hexsha);
	tohex((LPBYTE)&FileSize32, sizeof(UINT32), hexsize, true);
	tohex(ValKey, GCFOS_VALIDATION_KEY_LEN, hexval);

	QueryPerformanceCounter(&liStart);
	qr = GCFOS[GCFOS_IDX(i)]->Query(SHA1Bytes, FileSize32);
	QueryPerformanceCounter(&liEnd);

	InterlockedExchangeAdd64(&TotalUnitsSpentInClient, (LONGLONG)(liEnd.QuadPart - liStart.QuadPart));

	switch(qr)
		{
		case GCFOS_SRV_RESP_WANTED:
			_tprintf(_T("sending %s\n"), item.filename);
			// Donate file to server 
			GCFOS[GCFOS_IDX(i)]->ContributeFile(item.filename, SHA1Bytes, FileSize32);
			hSHALog << item.filename << L" " << hexsha << " " << hexsize << " " << hexval << std::endl;
			totalsent++;
			totalsentbytes += FileSize32;
			break;

		case GCFOS_SRV_RESP_WANT_FILENAME:
			_tprintf(_T("Providing filename for %s\n"), item.filename);
			GCFOS[GCFOS_IDX(i)]->ProvideFileName(item.filename, SHA1Bytes, FileSize32);
			break;

		case GCFOS_SRV_RESP_RESIDENT:
			totalresident++;
			totalresidentsize += FileSize32;
			hSHAResident << item.filename << L" " << hexsha << " " << hexsize << " " << hexval;
			if((FileSize32 & 0xfff) > 0 && (FileSize32 & 0xfff) < 0x100)
				hSHAResident << " (S)";
			hSHAResident << std::endl;
			break;

		case GCFOS_SRV_RESP_UNIQUE:
			totalUnique++;
			break;

		case GCFOS_SRV_RESP_LIMBO:
			totallimbo++;
			totallimbosize += FileSize32;
			hSHALimbo << item.filename << L" " << hexsha << std::endl;
			if(GCFOS[GCFOS_IDX(i)]->BlockStoreEnabled()
			&& SendDataBlocksToGCFOS(item.filename, i, item.filesize) == false)
				{
				hSHAErrors << "Send blocks failed for " << item.filename;
				}
			if(bForceDonate)
				{
				// FORCE donate file
				_tprintf(_T("Force sending %s\n"), item.filename);
				tohex(SHA1Bytes, GCFOS_SHA1_LEN, hexsha);
				// Donate file to server
				GCFOS[GCFOS_IDX(i)]->ContributeFile(item.filename, SHA1Bytes, FileSize32, GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_FORCE);
				hSHALog << item.filename << L"," << hexsha << " " << hexsize << " " << hexval << std::endl;
				}
			break;

		default:
			_tprintf(_T("Invalid response when querying for %s (%u)\n"), item.filename, qr);
			exit(-1);
		}
}

unsigned int __stdcall processQueue(void* param)
{
	UINT			i = (UINT)(UINT64)param;
	UINT			myentry;
	WORK_QUEUE		item;
	HANDLE			Wait[2] = { hsFiles, heTerminate };		

	while(true)
		{
		if(WaitForMultipleObjects(2, Wait, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
			break;
		EnterCriticalSection(&csFiles);
		item = workq.front();
		workq.pop();
		myentry = curentry;
		curentry++;
		if((entry - curentry)  < 3)
			{
			SetEvent(heReleased);
			}
		LeaveCriticalSection(&csFiles);
		GenerateSHA1HashForFile(myentry, i, item);
		EnterCriticalSection(&csFiles);
		processed++;
		LeaveCriticalSection(&csFiles);
		}
	GCFOS[GCFOS_IDX(i)]->GetHash(NULL, NULL, NULL, NULL, NULL, NULL);
	_endthreadex(0);
	return 0; // not reached
}

int RecoverFile()
{
	GCFOS[0] = new GCFOS_Client();
	_tprintf(_T("Connecting\n"));
	if(GCFOS[0]->Connect(GENSHA1_CACHE_PATH, _T(GENSHA1_COMPANY_NAME), false, false) == false)
		{
		DEBUGLOG(("Unable to connect to GCFOS server\n"));
		return 0;
		}
	_tprintf(_T("Authenticating\n"));
	if(GCFOS[0]->Auth() != GCFOS_SRV_RESP_AUTH)
		{
		DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
		return 0;
		}

	if(!DeleteFile(localpath))
		{
		if(GetLastError() != ERROR_FILE_NOT_FOUND)
			{
			_tprintf(TEXT("Unable to delete %s, error %d\n"), localpath, GetLastError());
			return -1;
			}
		}
#if 0
	UINT32 chunksize = 3000;
	LPBYTE buffer = (LPBYTE)malloc(chunksize);
	UINT32 offset = 0;
	UINT32 remaining = Size;
	UINT32 thisread;
	DWORD dwWritten;
	HANDLE hFile = CreateFile(localpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE)
		{
		_tprintf(TEXT("Unable to create %s, error %d\n"), localpath, GetLastError());
		return -1;
		}

	while(remaining > 0)
		{
		if(remaining < chunksize)
			thisread = remaining;
		else
			thisread = chunksize;
		if(!GCFOS[0]->RetrieveFilePortion(SHA1, Size, ValidationKey, offset, buffer, thisread))
			{
			_tprintf(TEXT("Unable to retrieve chunk\n"));
			return -1;
			}
		if(!WriteFile(hFile, buffer, thisread, &dwWritten, NULL))
			{
			_tprintf(TEXT("Unable to write to %s, error %d\n"), localpath, GetLastError());
			return -1;
			}
		offset += thisread;
		remaining -= thisread;
		}
	CloseHandle(hFile);

#else
	_tprintf(_T("Retrieving\n"));
	if(GCFOS[0]->RetrieveWholeFile(SHA1, Size, localpath, ValidationKey) == true)
		_tprintf(_T("Successfully retrieved "));
	else
		_tprintf(_T("Failed to retrieve "));
#endif

	_tprintf(_T("%s\n"), localpath);
	GCFOS[0]->Close();

	return 0;
}

int DeleteObject()
{
	GCFOS_SRV_RESPONSE		result;

	GCFOS[0] = new GCFOS_Client();
	_tprintf(_T("Connecting\n"));
	if(GCFOS[0]->Connect(GENSHA1_CACHE_PATH, _T(GENSHA1_COMPANY_NAME), false, false) == false)
		{
		DEBUGLOG(("Unable to connect to GCFOS server\n"));
		return 0;
		}
	_tprintf(_T("Authenticating\n"));
	if(GCFOS[0]->Auth() != GCFOS_SRV_RESP_AUTH)
		{
		DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
		return 0;
		}

	result = GCFOS[0]->DeleteObject(SHA1, Size, GCFOS_REQUEST_DELETE_FILE_BUT_WANTED);

	if(result == GCFOS_SRV_RESP_OK)
		{
		_tprintf(_T("Delete Successful\n"));
		}
	else
		{
		_tprintf(_T("Delete failed %u\n"), result);
		}

	GCFOS[0]->Close();
	return 0;
}

void printusage()
	{
	_tprintf(TEXT("GENSHA1 -p[path]\n"));
	_tprintf(TEXT("   -r Recover file\n"));
	_tprintf(TEXT("   -f Force donation (where possible)\n"));
	_tprintf(TEXT("   -d Delete entry from server\n"));
	_tprintf(TEXT("   -v[key] Specify Validation Key\n"));
	_tprintf(TEXT("   -s[size] Specify size of file[hex]\n"));
	_tprintf(TEXT("   -h[hash] Specify Validation Key[hex]\n"));
	_tprintf(TEXT("   -c check/compare data against block-store\n"));
	_tprintf(TEXT("   -l enable local block-store cache\n"));
	_tprintf(TEXT("   -eb erase local block-store cache\n"));
	_tprintf(TEXT("   -eh erase local hash cache\n"));
	_tprintf(TEXT("   -er erase local resident cache\n"));
	_tprintf(TEXT("   -eu erase local unique db\n"));
	_tprintf(TEXT("\n"));
	}


int _tmain(int argc, _TCHAR* argv[])
{
	TOKEN_PRIVILEGES	tp;
	LUID				luid;
	HANDLE				hToken;
	UINT				i, fc;
	bool				alldone;
	DWORD				startTime, endTime;
	GCFOS_CLIENT_SESSIONINFO sessinfo;
	time_t				time_now = time(NULL);
	CHAR				szDateTimeStr[100];
	bool				b_EnableLocalBlockCache = false;

	_ASSERTE(nGCFOS_Client_Ver == 1);

	TCHAR				*PrivsReqd[] =
		{
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_SECURITY_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		NULL
		};

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ))
		{
		for(i = 0; PrivsReqd[i]; i++)
			{
			LookupPrivilegeValue( NULL, PrivsReqd[i], &luid );
			tp.PrivilegeCount           = 1;
			tp.Privileges[0].Luid       = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			// The and clause must be at the end (order sensitive).
			AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL);
			}
		}

	std::strftime(szDateTimeStr, 100, "%c", localtime(&time_now));

	if(argc < 2)
		{
		printusage();
		_tprintf(_T("Insufficient parameters given\n"));
		return 0;
		}

	for(i = 1; i < (UINT)argc; i++)
		{
		switch(argv[i][0])
			{
			case '-':
			case '/':
				switch(_totlower(argv[i][1]))
					{
					case 'p':
						if(argv[i][2] == 0 && (UINT)argc >= i)
							{
							_tcscpy_s(localpath, MAX_PATH, argv[i+1]);
							i++; // skip the next parameter in loop
							}
						else
							{
							_tcscpy_s(localpath, MAX_PATH, argv[i]+2);
							}
						bPath = true;
						break;
					case 'r':
						op = RESTORE;
						break;
					case 'd':
						op = DEL;
						break;
					case 'h':
						if(argv[i][2] == 0 && (UINT)argc >= i)
							{
							if(_tcslen(argv[i+1]) == GCFOS_SHA1_LEN * 2)
								{
								tobin_W(argv[i+1], GCFOS_SHA1_LEN * 2, SHA1);
								bSHA1 = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == GCFOS_SHA1_LEN * 2)
								{
								tobin_W(argv[i]+2, GCFOS_SHA1_LEN * 2, SHA1);
								bSHA1 = true;
								}
							}
						if(!bSHA1)
							{
							printusage();
							return 0;
							}
							
						break;
					case 's':
						if(argv[i][2] == 0 && (UINT)argc >= i)
							{
							if(_tcslen(argv[i+1]) == sizeof(DWORD) * 2)
								{
								tobin_W(argv[i+1], sizeof(DWORD) * 2, (LPBYTE)(VOID*)&Size, true);
								bSize = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == sizeof(DWORD) * 2)
								{
								tobin_W(argv[i]+2, sizeof(DWORD) * 2, (LPBYTE)(VOID*)&Size, true);
								bSize = true;
								}
							}
						if(!bSize)
							{
							printusage();
							return 0;
							}
						break;
					case 'v':
						if(argv[i][2] == 0 && (UINT)argc >= i)
							{
							if(_tcslen(argv[i+1]) == 2 * GCFOS_VALIDATION_KEY_LEN)
								{
								tobin_W(argv[i+1], 2 * GCFOS_VALIDATION_KEY_LEN, (LPBYTE)(VOID*)&ValidationKey);
								bVal = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == 2 * GCFOS_VALIDATION_KEY_LEN)
								{
								tobin_W(argv[i]+2, 2 * GCFOS_VALIDATION_KEY_LEN, (LPBYTE)(VOID*)&ValidationKey);
								bVal = true;
								}
							}
						if(!bVal)
							{
							printusage();
							return 0;
							}
						break;

					case'f':
						bForceDonate = true;
						break;

					case 'c':
						bVerify = true;
						break;

					case 'l':
						b_EnableLocalBlockCache = true;
						_tprintf(TEXT("Local block cache enabled\n"));
						break;

					case 'e':
						{
						GCFOS_LOCAL_ERASE_TYPE	type;

						client = new GCFOS_Client();
						switch(_totlower(argv[i][2]))
							{
							case 'b':
								type = GCFOS_LOCAL_ERASE_TYPE_BLOCKS;
								break;
							case 'h':
								type = GCFOS_LOCAL_ERASE_TYPE_HASH;
								break;
							case 'r':
								type = GCFOS_LOCAL_ERASE_TYPE_RESIDENT;
								break;
							case 'u':
								type = GCFOS_LOCAL_ERASE_TYPE_UNIQUE;
								break;
							default:
								_tprintf(TEXT("Invalid erase type specified\n"));
								return 0;
							}
						
						if(client->EraseLocalCache(GENSHA1_CACHE_PATH, _T(GENSHA1_COMPANY_NAME), type))
							{
							_tprintf(TEXT("Erase successful\n"));
							}
						else
							{
							_tprintf(TEXT("Erase failed\n"));
							}
						return 0;
						}

					default:
						_tprintf(TEXT("Ignoring prarameter %s\n"), argv[i]);
						break; // ignore this parameter
					}
				break;

			}
		}

	GCFOS_Client::SetConsoleLogging(true);

	if(op == RESTORE || op == ENUMERATE)
		{
		if(localpath[0] == 0)
			{
			printusage();
			_tprintf(TEXT("Please give fully qualified path on command line with '-p' parameter\n"));
			return 0;
			}
		}

	if(op == RESTORE)
		{
		if(bPath == false)
			{
			printusage();
			_tprintf(TEXT("Please specify filename in path for restore operation\n"));
			return 0;
			}
		if(bSize == false)
			{
			printusage();
			_tprintf(TEXT("Please specify size in hex for restore operation\n"));
			return 0;
			}
		if(bVal == false)
			{
			printusage();
			_tprintf(TEXT("Please specify validation key in hex for restore operation\n"));
			return 0;
			}
		if(bSHA1 == false)
			{
			printusage();
			_tprintf(TEXT("Please specify SHA1-hash in hex for restore operation\n"));
			return 0;
			}
		return RecoverFile();
		}

	if(bPath && op != RESTORE && localpath[_tcslen(localpath) - 1] != '\\')
		{
		_tcscat(localpath, _T("\\"));
		}

	if(op == DEL)
		{
		if(bPath)
			{
			deletemode = true;
			}
		else
			{
			// delete just one named object
			return DeleteObject();
			}
		}

	QueryPerformanceFrequency(&liCounterFreq);
	CreateDirectory(GENSHA1_CACHE_PATH, NULL);
	sSHALog = GENSHA1_LOG_PATH L"GENSHA1_Log.txt";
	hSHALog.open(sSHALog, std::ofstream::app);
	
	entry = curentry = processed = 0;

	if(!hSHALog.is_open()) 
		{
		_tprintf(_T("Unable to create SHA log file, error %u\n"), GetLastError());
		return 0;
		}
	else
		{
		_tprintf(_T("Opened log %s\n"), sSHALog.c_str());
		}

	sSHALog = GENSHA1_LOG_PATH L"GENSHA1_Resident.txt";
	hSHAResident.open(sSHALog, std::ofstream::out); //(erase current contents)
	
	sSHALog = GENSHA1_LOG_PATH L"GENSHA1_Limbo.txt";
	hSHALimbo.open(sSHALog, std::ofstream::out); //(erase current contents)

	sSHALog = GENSHA1_LOG_PATH L"GENSHA1_Errors.txt";
	hSHAErrors.open(sSHALog, std::ofstream::out); //(erase current contents)

	startTime = GetTickCount();

	hSHALog << szDateTimeStr << std::endl;
	hSHAResident << szDateTimeStr << std::endl;
	hSHAErrors << szDateTimeStr << std::endl;
	hSHALimbo << szDateTimeStr << std::endl;


	InitializeCriticalSection(&csFiles);
	InitializeCriticalSection(&csLog);
	hsFiles = CreateSemaphore(NULL, 0, 20, NULL);
	heTerminate = CreateEvent(NULL, TRUE, FALSE, NULL);
	heReleased = CreateEvent(NULL, FALSE, FALSE, NULL);

	for(i = 0; i < GENSHA1_THREADS; i++)
		{
		state[i].buffer = (LPBYTE)VirtualAlloc(NULL, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		ZeroMemory(&state[i].o, sizeof(OVERLAPPED));
		state[i].o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		state[i].hThread = (HANDLE)_beginthreadex(NULL, 0, processQueue, (void*)(UINT64)i, 0, NULL);
		}

	for(i = 0; i < GENSHA1_CONNECTIONS; i++)
		{
		GCFOS[GCFOS_IDX(i)] = new GCFOS_Client();
		if(GCFOS[GCFOS_IDX(i)]->Connect(GENSHA1_CACHE_PATH, _T(GENSHA1_COMPANY_NAME), b_EnableLocalBlockCache, b_EnableLocalBlockCache) == false)
			{
			DEBUGLOG(("Unable to connect to GCFOS server\n"));
			return 0;
			}
		if(GCFOS[GCFOS_IDX(i)]->Auth() != GCFOS_SRV_RESP_AUTH)
			{
			GCFOS[GCFOS_IDX(i)]->Close();
			delete GCFOS[GCFOS_IDX(i)];
			DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
			return 0;
			}
		bDedupeFiles = GCFOS[GCFOS_IDX(i)]->FileStoreEnabled();

		if(i == GCFOS_IDX(i))
			break;
		}

	startTime = GetTickCount();


#if 0
	GCFOS_SRV_RESPONSE qr;
	Ipp8u			SHA1Bytes[GCFOS_SHA1_LEN];
	BYTE			ValKey[GCFOS_VALIDATION_KEY_LEN];
	WIN32_FILE_ATTRIBUTE_DATA attr;
	LPCTSTR			filename;

	filename = L"C:\\Windows\\System32\\DriverStore\\FileRepository\\net1qx64.inf_amd64_neutral_85d10fa4c777b7be\\net1qx64.PNF";
	GetFileAttributesEx(filename, GetFileExInfoStandard, &attr);
	GCFOS[0]->GetHash(filename, filename, (LPBYTE)&SHA1Bytes, &attr.ftLastWriteTime, (PUINT32)&attr.nFileSizeLow, ValKey);
	qr = GCFOS[0]->Query(SHA1Bytes, attr.nFileSizeLow);
	
	filename = L"C:\\Windows\\System32\\DriverStore\\FileRepository\\nete1e3e.inf_amd64_neutral_f77725472d91b1d1\\nete1e3e.PNF";
	GetFileAttributesEx(filename, GetFileExInfoStandard, &attr);
	GCFOS[0]->GetHash(filename, filename, (LPBYTE)&SHA1Bytes, &attr.ftLastWriteTime, (PUINT32)&attr.nFileSizeLow, ValKey);
	qr = GCFOS[0]->Query(SHA1Bytes, attr.nFileSizeLow);
	exit(0);
#endif

	if(bVerify)
		{
		if(!GCFOS[0]->BlockStoreEnabled())
			{
			printf("Block store is not enabled on GCFOS server\n");
			goto cleanup;
			}
		printf("Verify enabled\n");
#if 0
		// this should only be done if you're paranoid that the local cache is corrupt
		if(GCFOS[0]->ValidateLocalBlockCache())
			{
			printf("Verify of local block cache successful\n");
			return 0;
			}
		else
			{
			printf("Verify of local block cache failed\n");
			return 0;
			}
#endif//0
		}

	fc = EnumerateFiles(localpath);

	for(alldone = false; !alldone; )
		{
		EnterCriticalSection(&csFiles);
		if(processed == entry)
			alldone = true;
		LeaveCriticalSection(&csFiles);
		Sleep(1);
		}

	SetEvent(heTerminate);

	endTime = GetTickCount();

	for(i = 0; i < GENSHA1_CONNECTIONS; i++)
		{
		GCFOS[GCFOS_IDX(i)]->GetSessionInfo(&sessinfo);
		_tprintf(_T("Session %u: Locally resident entries = %I64u (hits=%I64u), Locally unique = %I64u\n"), i, sessinfo.Resident, sessinfo.locallyResidentHits, sessinfo.Unique);
		_tprintf(_T("  Added = %I64u, SHA1 cache hits = %I64u, SHA1 cache misses: %I64u\n"), sessinfo.locallyAdded, sessinfo.SHA1Hits, sessinfo.SHA1Misses);
		_tprintf(_T("  Queries: %I64u, Query time = %f, Average = %f ms\n"), sessinfo.ServerQueries, sessinfo.TotalQueryTime, (sessinfo.TotalQueryTime * 1000.0f) / (double)sessinfo.ServerQueries);
		_tprintf(_T("  Server queries = %I64u\n"), sessinfo.ServerQueries);
		_tprintf(_T("  Block cache hits = %I64u (%I64u MB)\n"), sessinfo.BlocksHitCache, ((sessinfo.BlocksHitCache * (UINT64)GCFOS_BLOCK_SIZE) >> 20LL));
		_tprintf(_T("  Block queries = %I64u\n"), sessinfo.BlocksQueried);
		_tprintf(_T("  Block stores = %I64u (%0.2f %% hit)\n"), sessinfo.BlocksStored, (sessinfo.BlocksQueried > 0 ? (double)((sessinfo.BlocksQueried - sessinfo.BlocksStored)/(double)sessinfo.BlocksQueried)*100.0f : 0.0f));
		GCFOS[GCFOS_IDX(i)]->Close();
		}

	for(i = 0; i < GENSHA1_THREADS; i++)
		{
		WaitForSingleObject(state[i].hThread, INFINITE);
		VirtualFree(state[i].buffer, 0, MEM_RELEASE);
		CloseHandle(state[i].o.hEvent);
		}

	_tprintf(_T("Enumerated %u files (%I64u MB) in %0.2f secs (%.2f MB/sec)\n"), fc, (totalBytesRead >> 20LL),
		(double)(endTime - startTime)/1000.0f, 
		(double)((double)(totalBytesRead >> 20LL) / ((double)(endTime - startTime)/1000.0f)));
	_tprintf(_T("Total time spent in GCFOS_Client = %0.2f\n"), (double)TotalUnitsSpentInClient / (double)liCounterFreq.QuadPart);
	_tprintf(_T("Total ignored = %u\n"), totalignored);
	_tprintf(_T("Total files sent only to block store = %u\n"), FilesSentOnlyToBlocks);
	_tprintf(_T("Total resident = %u (size = %I64u MB)\n"), totalresident, (totalresidentsize >> 20));
	_tprintf(_T("Total limbo = %u (size = %I64u MB)\n"), totallimbo, (totallimbosize >> 20));
	_tprintf(_T("Total sent = %u (size = %I64u MB)\n"), totalsent, (totalsentbytes >> 20));
	_tprintf(_T("Total client-unique = %I64u\n"), totalUnique);
	if(sessinfo.BlocksQueried > 0)
		{
		_tprintf(_T("Total block query time = %0.1f (%0.2f ms avg)\n"), sessinfo.TotalBlockQueryTime, (1000.0f * sessinfo.TotalBlockQueryTime) / (double)(sessinfo.BlocksQueried));
		}
	if(sessinfo.BlocksStored > 0)
		{
		_tprintf(_T("Total block store time = %0.1f (%0.2f MB/s, %0.2f ms avg)\n"), sessinfo.TotalBlockStoreTime, 
			(double)(sessinfo.BlocksStored * GCFOS_BLOCK_SIZE) / sessinfo.TotalBlockStoreTime / 1048576.0f, (1000.0f * sessinfo.TotalBlockStoreTime) / (double)(sessinfo.BlocksStored));
		}

#if 0
	for(itr = set_hashes.begin(); itr != set_hashes.end(); itr++)
		{
		for(int k=0;k<20;k++)
			{
			hSHALog.fill('0'); // don’t print n
			hSHALog.width(2); // instead of 0n
			hSHALog << hex << itr->bytes[k];
			}
		hSHALog << /*"," << itr->filename << */ "," << dec << itr->filesize << "," << itr->count << endl;
		}
#endif
cleanup:
	hSHALog.close();
	hSHAResident.close();
	hSHALimbo.close();
	hSHAErrors.close();

	return i;
}

