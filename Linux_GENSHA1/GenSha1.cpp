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

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <string.h>
#include <string.h>
#include <wchar.h>
#include <queue>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

#include "WinTypes.h"
#include "GCFOS_Client.h"
#include "Misc.h"

#ifdef _DEBUG
#define DEBUGLOG(__x) printf __x
#else
#define DEBUGLOG(x)
#endif// _DEBUG

#define GENSHA1_CONNECTIONS 1
#define SHA1_THREADS 1

#define GENSHA1_COMPANY_NAME _T("UltraBac Software")

#define hSHALog std::cout;
#define hSHAResident std::cout;
#define hSHALimbo std::cout;
#define hSHAErrors std::cout;

struct threadstate {
	char *				buffer;
	GCFOS_Client		*GCFOS[GENSHA1_CONNECTIONS];
	pthread_t			ThreadId;
	};

struct WORK_QUEUE {
	char*	filename;
	unsigned long long filesize;
	FILETIME ft;
	};

char g_GCFOS_ClientCachePath[250];

std::queue<WORK_QUEUE> workq;

threadstate state[SHA1_THREADS];

void GenerateSHA1HashForFile(UINT myentry, UINT i, WORK_QUEUE &item);
LONGLONG totalBytesRead, deletemode,totalresidentsize, totalUnique, totallimbo, totallimbosize, totalsent, totalsentbytes, totalresident;
bool bForceDonatei, bDedupeFiles, bForceDonate,bVerify;
bool b_EnableLocalBlockCache;
bool				bSize = false, bSHA1 = false, bVal = false, bPath = false;

TCHAR				localpath[MAX_PATH] = _T("");
BYTE				SHA1[GCFOS_SHA1_LEN];
DWORD				Size;
BYTE				ValidationKey[GCFOS_VALIDATION_KEY_LEN];

enum OPERATION { ENUMERATE, RESTORE, DEL } op = ENUMERATE;


int EnumerateFiles(TCHAR *szDirectory)
	{
	TCHAR *np;
	size_t		pathlen = _tcslen(szDirectory);

	struct stat stDirInfo;
	struct dirent * stFiles;
	DIR *stDirIn;
	TCHAR szFullName[MAXPATHLEN];
	struct stat stFileInfo;
	int mode;
	int c = 0;
	WORK_QUEUE item;

	if(_tcsicmp(szDirectory, g_GCFOS_ClientCachePath) == 0)
		return 0; // don't enumerate our cache files

	if (lstat(szDirectory, &stDirInfo) < 0)
		{
		perror (szDirectory);
		return 0;

		}

	if ((stDirIn = opendir( szDirectory)) == NULL)
		{
		perror( szDirectory );
		return 0;
		}


	while(( stFiles = readdir(stDirIn)) != NULL)
		{
		sprintf(szFullName, "%s/%s", szDirectory, stFiles->d_name );

		if (lstat(szFullName, &stFileInfo) < 0)
			perror ( szFullName );

		if ( S_ISLNK( stFileInfo.st_mode ))
			{
			printf("is link\n");
			continue;
			}

		/* is the file a directory? */
		if (S_ISDIR(stFileInfo.st_mode))
			{
			if(_tcscmp(stFiles->d_name, _T(".")) == 0 || _tcscmp(stFiles->d_name, _T("..")) == 0)
				continue; // skip these pseudo-dirs

			np = new TCHAR[pathlen + _tcslen(stFiles->d_name) + 2];
			sprintf(np, _T("%s/%s"), szDirectory, stFiles->d_name);

			printf("Enum: %s\n", np);
			c += EnumerateFiles(np);
			delete[] np;
			continue;
			}

		if(_tcsnicmp(stFiles->d_name, _T("GENSHA1_"), 8) == 0)
			{
			// this is one of "our" files, skip it
			continue;
			}

		item.filename = szFullName;
		time_t_to_FILETIME(stFileInfo.st_mtime, &item.ft);
		item.filesize = stFileInfo.st_size;

		GenerateSHA1HashForFile(0, 0, item);
		c++;
		//printf( "Filename: %s\n", szFullName );
		} 

	closedir(stDirIn);
	return c;
	}

bool SendDataBlocksToGCFOS(LPCTSTR filename, int i, INT64 filesize)
	{
	LPBYTE 			hashes;
	UINT32			hash_size;
	bool			retval;
	FILE*			hFile;
	int64_t			rc;

	hFile = fopen(filename, "r");
	hash_size = state[i].GCFOS[0]->GetHashDataLengthForFileSize(filesize);
	hashes = (unsigned char *	)malloc(hash_size);

	rc = state[i].GCFOS[0]->GetBlockHashesForFile(hFile, filename, hashes, hash_size);
	if(rc > 0)
		retval = true; 
	else
		retval = false;

	free(hashes);
	fclose(hFile);
	return retval;
	}

void GenerateSHA1HashForFile(UINT myentry, UINT i, WORK_QUEUE &item)
	{
	BYTE			SHA1Bytes[GCFOS_SHA1_LEN];
	CHAR			hexsha[GCFOS_SHA1_LEN * 2 + 1];
	CHAR			hexval[9];
	CHAR			hexsize[9];
	GCFOS_SRV_RESPONSE qr;
	BYTE			ValKey[GCFOS_VALIDATION_KEY_LEN];
	UINT32			FileSize32;
	totalBytesRead += item.filesize;

	FileSize32 = (UINT32)item.filesize;

	if(deletemode)
		{
		if(item.filesize >= GCFOS_FILE_MAX_SIZE
			|| item.filesize < GCFOS_FILE_MINIMUM_SIZE)
			{
			return;
			}

		_tprintf(_T("Deleting %s\n"), item.filename);
		state[i].GCFOS[0]->DeleteObject(SHA1Bytes, FileSize32, 0);
		return;
		}

	if(!bDedupeFiles && state[0].GCFOS[0]->BlockStoreEnabled())
		{
		if(!SendDataBlocksToGCFOS((char *)item.filename, i, item.filesize) == false)
			{
			printf("Send blocks failed for %s\n", item.filename);
			}
		}

	if(item.filesize >= GCFOS_FILE_MAX_SIZE
		|| item.filesize < GCFOS_FILE_MINIMUM_SIZE)
		{
		if(state[0].GCFOS[0]->BlockStoreEnabled()
			&& SendDataBlocksToGCFOS(item.filename, i, item.filesize) == false)
			{
			printf("Send blocks failed for %s", item.filename);
			}
		return;
		}

	if(!state[i].GCFOS[0]->GetHash(item.filename, item.filename, SHA1Bytes, &item.ft, &FileSize32, ValKey))
		{
		printf("Error GetHash: %s\n", item.filename);
		return;
		}

	tohex(SHA1Bytes, GCFOS_SHA1_LEN, hexsha);
	tohex((uint8_t*)&FileSize32, sizeof(UINT32), hexsize, true);
	tohex(ValKey, GCFOS_VALIDATION_KEY_LEN, hexval);

	if(GENSHA1_CONNECTIONS > 1)
		qr = state[i].GCFOS[rand() % GENSHA1_CONNECTIONS]->Query(SHA1Bytes, FileSize32);
	else
		qr = state[i].GCFOS[0]->Query(SHA1Bytes, FileSize32);

	switch(qr)
		{
		case GCFOS_SRV_RESP_WANTED:
			_tprintf(_T("sending %s\n"), item.filename);
			// Donate file to server 
			state[i].GCFOS[0]->ContributeFile(item.filename, SHA1Bytes, FileSize32);
			printf("Contribute %s", item.filename);
			totalsent++;
			totalsentbytes += FileSize32;
			break;

		case GCFOS_SRV_RESP_WANT_FILENAME:
			_tprintf(_T("Providing filename for %s\n"), item.filename);
			state[i].GCFOS[0]->ProvideFileName(item.filename, SHA1Bytes, FileSize32);
			break;

		case GCFOS_SRV_RESP_RESIDENT:
			totalresident++;
			totalresidentsize += FileSize32;
			printf("Resident %s\n", item.filename);
			break;

		case GCFOS_SRV_RESP_UNIQUE:
			totalUnique++;
			break;

		case GCFOS_SRV_RESP_LIMBO:
			totallimbo++;
			totallimbosize += FileSize32;
			if(state[0].GCFOS[0]->BlockStoreEnabled()
				&& SendDataBlocksToGCFOS(item.filename, i, item.filesize) == false)
				{
				printf("Send blocks failed for %s\n", item.filename);
				}
			if(bForceDonate)
				{
				// FORCE donate file
				_tprintf(_T("Force sending %s\n"), item.filename);
				tohex(SHA1Bytes, GCFOS_SHA1_LEN, hexsha);
				// Donate file to server
				state[i].GCFOS[0]->ContributeFile(item.filename, SHA1Bytes, FileSize32, GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_FORCE);
				printf("Force donate %s\n", item.filename);
				}
			break;

		default:
			_tprintf(_T("Invalid response when querying for %s (%u)\n"), item.filename, qr);
			exit(-1);
		}

	}

int RecoverFile()
{
	state[0].GCFOS[0] = new GCFOS_Client();
	_tprintf(_T("Connecting\n"));
	if(state[0].GCFOS[0]->Connect(g_GCFOS_ClientCachePath, GENSHA1_COMPANY_NAME, false, false) == false)
		{
		DEBUGLOG(("Unable to connect to GCFOS server\n"));
		return 0;
		}
	_tprintf(_T("Authenticating\n"));
	if(state[0].GCFOS[0]->Auth() != GCFOS_SRV_RESP_AUTH)
		{
		DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
		return 0;
		}

	if(remove(localpath))
		{
		_tprintf(TEXT("Unable to delete %s, error %d\n"), localpath, errno);
		return -1;
		}

	_tprintf(_T("Retrieving\n"));
	if(state[0].GCFOS[0]->RetrieveWholeFile(SHA1, Size, localpath, ValidationKey) == true)
		_tprintf(_T("Successfully retrieved "));
	else
		_tprintf(_T("Failed to retrieve "));

	_tprintf(_T("%s\n"), localpath);
	state[0].GCFOS[0]->Close();

	return 0;
}

int DeleteObject()
{
	GCFOS_SRV_RESPONSE		result;

	state[0].GCFOS[0] = new GCFOS_Client();
	_tprintf(_T("Connecting\n"));
	if(state[0].GCFOS[0]->Connect(g_GCFOS_ClientCachePath, GENSHA1_COMPANY_NAME, false, false) == false)
		{
		DEBUGLOG(("Unable to connect to GCFOS server\n"));
		return 0;
		}
	_tprintf(_T("Authenticating\n"));
	if(state[0].GCFOS[0]->Auth() != GCFOS_SRV_RESP_AUTH)
		{
		DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
		return 0;
		}

	result = state[0].GCFOS[0]->DeleteObject(SHA1, Size, GCFOS_REQUEST_DELETE_FILE_BUT_WANTED);

	if(result == GCFOS_SRV_RESP_OK)
		{
		_tprintf(_T("Delete Successful\n"));
		}
	else
		{
		_tprintf(_T("Delete failed %u\n"), result);
		}

	state[0].GCFOS[0]->Close();
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

int main (int argc, char * argv[])
	{
	int i = 0;
	TCHAR szDirectory[MAXPATHLEN];

	if(argc < 2)
		{
		printusage();
		_tprintf(_T("Insufficient parameters given\n"));
		return 0;
		}

	strcpy(g_GCFOS_ClientCachePath, getenv("HOME"));
	strcat(g_GCFOS_ClientCachePath, "/gcfos_cache");
	mkdir(g_GCFOS_ClientCachePath, 0777);

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
							_tcscpy(localpath, argv[i+1]);
							i++; // skip the next parameter in loop
							}
						else
							{
							_tcscpy(localpath, argv[i]+2);
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
								tobin_A(argv[i+1], GCFOS_SHA1_LEN * 2, (LPBYTE)SHA1);
								bSHA1 = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == GCFOS_SHA1_LEN * 2)
								{
								tobin_A(argv[i]+2, GCFOS_SHA1_LEN * 2, SHA1);
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
								tobin_A((LPSTR)argv[i+1], sizeof(DWORD) * 2, (LPBYTE)&Size, true);
								bSize = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == sizeof(DWORD) * 2)
								{
								tobin_A(argv[i]+2, sizeof(DWORD) * 2, (LPBYTE)&Size, true);
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
							if(_tcslen((LPSTR)argv[i+1]) == 2 * GCFOS_VALIDATION_KEY_LEN)
								{
								tobin_A(argv[i+1], 2 * GCFOS_VALIDATION_KEY_LEN, (LPBYTE)&ValidationKey);
								bVal = true;
								i++; // skip the next parameter in loop
								}
							}
						else
							{
							if(_tcslen(argv[i]+2) == 2 * GCFOS_VALIDATION_KEY_LEN)
								{
								tobin_A((LPSTR)argv[i]+2, 2 * GCFOS_VALIDATION_KEY_LEN, (LPBYTE)&ValidationKey);
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
						GCFOS_Client			client;

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
						
						if(client.EraseLocalCache(g_GCFOS_ClientCachePath, GENSHA1_COMPANY_NAME, type))
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

	for(i = 0; i < SHA1_THREADS; i++)
		{
		for(int j = 0; j < GENSHA1_CONNECTIONS; j++)
			{
			state[i].GCFOS[j] = new GCFOS_Client();
			if(state[i].GCFOS[j]->Connect(g_GCFOS_ClientCachePath, GENSHA1_COMPANY_NAME, b_EnableLocalBlockCache, b_EnableLocalBlockCache) == false)
				{
				DEBUGLOG(("Unable to connect to GCFOS server\n"));
				return 0;
				}
			if(state[i].GCFOS[j]->Auth() != GCFOS_SRV_RESP_AUTH)
				{
				state[i].GCFOS[j]->Close();
				delete state[i].GCFOS[j];
				DEBUGLOG(("Unable to connect to authorize with GCFOS server\n"));
				return 0;
				}
			bDedupeFiles = state[i].GCFOS[j]->FileStoreEnabled();
			}
		state[i].buffer = (char *)malloc(0x10000);
		}

	int c = EnumerateFiles(localpath);
	printf("Total Files Enumerated:%d\n", c);

	return 0;

	}

//------------------------------------------------- Thread Stuff --------------------------------------------------------
void *processQueue(void *param)
	{
	pthread_exit(0);
	return NULL;	
	}

void CreateWorkerThreads()
	{
	int i, ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	for(i = 0; i < SHA1_THREADS; i++)
		{
		ret = pthread_create(&state[i].ThreadId, &attr, processQueue, (void *)NULL);
		}

	for (i = 0; i < SHA1_THREADS; i++)
		pthread_join(state[i].ThreadId, NULL);
	}
