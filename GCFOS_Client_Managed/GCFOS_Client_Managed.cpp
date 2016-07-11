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
#include "stdafx.h"

#include <GCFOS_Client.h>
#include "GCFOS_Client_Managed.h"
#using <system.dll>
#include <vcclr.h>

GCFOS_Client_Managed::GCFOS_Client_Managed()
	{
	LastError = gcnew System::String("");
	BlockStoreEnabled = false;
	FileStoreEnabled = false;
	LocalBlockCacheEnabled = false;
	Connected = false;

	g = new GCFOS_Client();
	}

GCFOS_Client_Managed::~GCFOS_Client_Managed()
	{
	g->Close();
	delete g;
	}

bool GCFOS_Client_Managed::Connect(System::String ^cachePath, System::String ^CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache, System::String ^Server, GCFOS_CLIENTID ClientId, array<const System::Byte> ^Secret)
	{
	pin_ptr<const WCHAR> pCachePath = PtrToStringChars(cachePath);
	pin_ptr<const WCHAR> pCompanyName = PtrToStringChars(CompanyName);
	pin_ptr<const WCHAR> pServer = PtrToStringChars(Server);
	pin_ptr<const System::Byte> pSecret = &Secret[0];

	if(g->Connect(pCachePath, pCompanyName, EnableLocalBlockCache, EnableExtendedBlockCache, pServer, ClientId, pSecret))
		{
		Connected = true;
		BlockStoreEnabled = g->BlockStoreEnabled();
		FileStoreEnabled = g->FileStoreEnabled();
		return true;
		}
	else
		{
		return false;
		}
	}

bool GCFOS_Client_Managed::Connect(System::String ^cachePath, System::String ^CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache)
	{
	pin_ptr<const WCHAR> pCachePath = PtrToStringChars(cachePath);
	pin_ptr<const WCHAR> pCompanyName = PtrToStringChars(CompanyName);
	if(g->Connect(pCachePath, pCompanyName, EnableLocalBlockCache, EnableExtendedBlockCache))
		{
		Connected = true;
		BlockStoreEnabled = g->BlockStoreEnabled();
		FileStoreEnabled = g->FileStoreEnabled();
		return true;
		}
	else
		{
		return false;
		}
	}

GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE GCFOS_Client_Managed::Query(array<const System::Byte> ^SHA1, System::UInt32 size)
	{
	GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE rc;

	ClearLastError();

	if(SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE::GCFOS_SRV_RESP_PARAMETER_ERROR;
		}

	pin_ptr<const System::Byte> pHash = &SHA1[0];
	rc = (GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE)g->Query(pHash, size);
	SetLastError(rc);
	return rc;
	}

void GCFOS_Client_Managed::Close()
	{
	g->Close();
	Connected = false;
	}

GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE GCFOS_Client_Managed::Auth()
	{
	GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE rc;

	rc = (GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE) g->Auth();
	SetLastError(rc);
	return rc;
	}

bool GCFOS_Client_Managed::ContributeFile(System::String ^filename, array<const System::Byte> ^SHA1, System::UInt32 size, System::Byte flags)
	{
	ClearLastError();

	if(SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	pin_ptr<const System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);
	return g->ContributeFile(pPath, pSHA1, size, flags);
	}

bool GCFOS_Client_Managed::ContributeFileByHandle(Microsoft::Win32::SafeHandles::SafeFileHandle ^filehandle, array<const System::Byte> ^SHA1, System::UInt32 size, System::String ^filename, System::Byte flags)
	{
	bool retval;
	ClearLastError();
	bool RefSuccess = true;

	if(SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	pin_ptr<const System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);
	filehandle->DangerousAddRef(RefSuccess);
	retval = g->ContributeFileByHandle((HANDLE)filehandle->DangerousGetHandle(), pSHA1, size, pPath, flags);
	if(RefSuccess)
		{
		filehandle->DangerousRelease();
		}
	return retval;
	}

bool GCFOS_Client_Managed::GetHash(System::String ^filename, System::String ^filepathForOpen, array<System::Byte> ^SHA1, array<System::Byte> ^ValidationKey)
	{
	pin_ptr<System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<System::Byte> pKey = &ValidationKey[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);
	pin_ptr<const WCHAR> pPathForOpen = PtrToStringChars(filepathForOpen);

	ClearLastError();

	if(ValidationKey->Length != GCFOS_VALIDATION_KEY_LEN
	|| SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	return g->GetHash(pPath, pPathForOpen, pSHA1, NULL, NULL, pKey);
	}

bool GCFOS_Client_Managed::GetHash(System::String ^filename, System::String ^filepathForOpen, array<System::Byte> ^SHA1, System::DateTime ^dt, System::UInt32 ^filesize, array<System::Byte> ^ValidationKey)
	{
	UINT32				u32FileSize = *filesize;
	UINT64				u64ft = dt->ToFileTimeUtc();

	pin_ptr<System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<System::Byte> pKey = &ValidationKey[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);
	pin_ptr<const WCHAR> pPathForOpen = PtrToStringChars(filepathForOpen);

	ClearLastError();

	if(ValidationKey->Length != GCFOS_VALIDATION_KEY_LEN
	|| SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	return g->GetHash(pPath, pPathForOpen, pSHA1, (LPFILETIME)&u64ft, &u32FileSize, pKey);
	}

bool GCFOS_Client_Managed::GetHashForHandle(System::String ^filename, Microsoft::Win32::SafeHandles::SafeFileHandle ^filehandle, array<System::Byte> ^SHA1, System::DateTime ^dt, System::UInt32 ^filesize, array<System::Byte> ^ValidationKey)
	{
	bool retval;
	bool RefSuccess = true;
	UINT32 u32FileSize;
	FILETIME ft;
	UINT64 u64ft;

	pin_ptr<System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<System::Byte> pKey = &ValidationKey[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);

	ClearLastError();

	if(ValidationKey->Length != GCFOS_VALIDATION_KEY_LEN
	|| SHA1->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	try {
		u32FileSize = *filesize;
		u64ft = dt->ToFileTimeUtc();
		memcpy(&ft, &u64ft, sizeof(FILETIME));
		}
	catch(...)
		{
		LastError = "ParameterException";
		return false;
		}

	filehandle->DangerousAddRef(RefSuccess);
	
	retval = g->GetHashForHandle(pPath, (HANDLE)filehandle->DangerousGetHandle(), pSHA1, ft, u32FileSize, pKey);

	if(RefSuccess)
		{
		filehandle->DangerousRelease();
		}
	return retval;
	}

bool GCFOS_Client_Managed::RetrieveWholeFile(array<const System::Byte> ^SHA1, System::UInt32 size, System::String ^filename, array<System::Byte> ^ValidationKey)
	{
	ClearLastError();

	if(ValidationKey->Length != GCFOS_VALIDATION_KEY_LEN
	|| SHA1->Length != GCFOS_SHA1_LEN)
		return false;

	pin_ptr<const System::Byte> pSHA1 = &SHA1[0];
	pin_ptr<System::Byte> pKey = &ValidationKey[0];
	pin_ptr<const WCHAR> pPath = PtrToStringChars(filename);

	return g->RetrieveWholeFile(pSHA1, size, pPath, pKey);
	}

GCFOS_MANAGED_CLIENT::GCFOS_CLIENT_SESSIONINFO^ GCFOS_Client_Managed::GetSessionInfo()
	{
	GCFOS_MANAGED_CLIENT::GCFOS_CLIENT_SESSIONINFO ^info_m;
	GCFOS_CLIENT_SESSIONINFO info;

	g->GetSessionInfo(&info);
	info_m = gcnew GCFOS_MANAGED_CLIENT::GCFOS_CLIENT_SESSIONINFO(&info);
	return info_m;
	}

System::UInt32 GCFOS_Client_Managed::GetClientID()
	{
	return g->GetClientID();
	}

bool GCFOS_Client_Managed::EraseLocalCache(System::String ^CachePath, System::String ^CompanyName, GCFOS_MANAGED_CLIENT::GCFOS_LOCAL_ERASE_TYPE type)
	{
	pin_ptr<const WCHAR> pCachePath = PtrToStringChars(CachePath);
	pin_ptr<const WCHAR> pCompanyName = PtrToStringChars(CompanyName);

	return g->EraseLocalCache(pCachePath, pCompanyName, (GCFOS_LOCAL_ERASE_TYPE)type);
	}

bool GCFOS_Client_Managed::StoreBlocks(array<const System::Byte> ^BlockData, array<System::Byte> ^ References, System::UInt32 %outsize)
	{
	UINT32			uOutsize;
	bool			retval;

	ClearLastError();
	INT32 OutsizeNeeded = ((BlockData->Length + GCFOS_BLOCK_SIZE - 1) / GCFOS_BLOCK_SIZE) * GCFOS_BLOCK_HASH_LEN;

	if(BlockData->Length > GCFOS_MAX_BLOCK_SIZE
	|| References->Length < OutsizeNeeded)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	pin_ptr<const System::Byte> pBlockData = &BlockData[0];
	pin_ptr<System::Byte> pReferences = &References[0];

	retval = g->StoreBlocks(pBlockData, BlockData->Length, pReferences, &uOutsize);
	outsize = uOutsize;
	return retval;
	}

bool GCFOS_Client_Managed::RetrieveBlocks(array<const System::Byte> ^Hashes, System::UInt16 %Count, array<System::Byte> ^Blocks)
	{
	bool			retval;
	UINT16			uCount;

	ClearLastError();
	INT32 OutsizeNeeded = ((Hashes->Length / GCFOS_BLOCK_HASH_LEN) * GCFOS_BLOCK_SIZE);

	if(Hashes->Length < (GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY)
	|| Blocks->Length < OutsizeNeeded)
		{
		LastError = "InvalidParameterLength";
		return false;
		}

	pin_ptr<System::Byte> pBlockData = &Blocks[0];
	pin_ptr<const System::Byte> pHashes = &Hashes[0];

	retval = g->RetrieveBlocks(pHashes, &uCount, pBlockData);
	Count = uCount;
	return retval;
	}

array<System::Byte> ^ GCFOS_Client_Managed::SendBlocksInFile(System::IO::FileInfo ^inputfile, System::Int64 %filesize)
	{
	array<System::Byte> ^hashes = nullptr;
	LPBYTE					pHashdata;
	UINT32					hashdata_size = g->GetHashDataLengthForFileSize(filesize);
	HANDLE					hFile;
	CString					fullname(inputfile->FullName);

	hFile = CreateFile(fullname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		LastError = "Failed to open '" + inputfile->FullName + "', error " + GetLastError();
		return nullptr;
		}

	pHashdata = (LPBYTE)malloc(hashdata_size);

	filesize = g->GetBlockHashesForFile(hFile, fullname, pHashdata, hashdata_size);
	if(filesize > 0 && hashdata_size > 0)
		{
		hashes = gcnew array<System::Byte>(hashdata_size);
		System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(pHashdata), hashes, 0, hashdata_size);
		}
	else
		{
		LastError = "GetBlockHashesForFile failed:" + filesize;
		}
	CloseHandle(hFile);
	free(pHashdata);
	return hashes;

#if 0
	HANDLE			hFile;
	array<System::Byte> ^hashes;
	LPBYTE			buffer;
	UINT32			SizeOfHashes;
	LARGE_INTEGER	SizeOfFile;
	DWORD			dwRead;
	BYTE			localhashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	UINT32			local_hashsize;
	UINT32			stragglersize;
	int				startindex;

	ClearLastError();
	hFile = CreateFile(CString(filename), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		LastError = "ErrorOpeningFile:" + GetLastError();
		return nullptr;
		}

	if(!GetFileSizeEx(hFile, &SizeOfFile))
		{
		LastError = "ErrorGettingFileSize:" + GetLastError();
		return nullptr;
		}

	SizeOfHashes = (UINT32)(SizeOfFile.QuadPart / (UINT64)GCFOS_BLOCK_SIZE) * GCFOS_BLOCK_HASH_LEN;
	if(SizeOfFile.LowPart % GCFOS_BLOCK_SIZE > 0)
		{
		if(SizeOfFile.LowPart % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			SizeOfHashes += (SizeOfFile.LowPart % GCFOS_BLOCK_SIZE);
			}
		else
			{
			SizeOfHashes += GCFOS_BLOCK_HASH_LEN;
			}
		}

	hashes = gcnew array<System::Byte>(SizeOfHashes);
	if(hashes == nullptr)
		{
		LastError = "OutOfMemory";
		return nullptr;
		}

	buffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(buffer == NULL)
		{
		LastError = "OutOfMemory";
		delete hashes;
		return nullptr;
		}

	startindex = 0;
	while(true)
		{
		if(ReadFile(hFile, buffer, GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE, &dwRead, NULL))
			{
			if(dwRead == 0)
				break; // file all read
			if(dwRead % GCFOS_BLOCK_SIZE > 0
			&& dwRead % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
				{
				stragglersize = (dwRead % GCFOS_BLOCK_SIZE);
				if(g->StoreBlocks(buffer, dwRead - stragglersize, localhashes, &local_hashsize))
					{
					// copy "straggler block" to end of hash chain
					System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(localhashes), hashes, startindex, local_hashsize);
					startindex += local_hashsize;
					System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(buffer + dwRead - stragglersize), hashes, startindex, stragglersize);
					startindex += stragglersize;
					}
				else
					{
					LastError = "StoreBlocksFailed";
					delete hashes;
					hashes = nullptr;
					break;
					}
				}
			else
				{
				if(g->StoreBlocks(buffer, dwRead, localhashes, &local_hashsize))
					{
					System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(localhashes), hashes, startindex, local_hashsize);
					startindex += local_hashsize;
					}
				else
					{
					LastError = "StoreBlocksFailed";
					delete hashes;
					hashes = nullptr;
					break;
					}
				}
			}
		else
			{
			LastError = "FileReadError" + GetLastError();
			delete hashes;
			hashes = nullptr;
			break;
			}
		}
	CloseHandle(hFile);
	VirtualFree(buffer, NULL, MEM_RELEASE);
	return hashes;
#endif//0
	}

bool GCFOS_Client_Managed::BuildFileFromHashes(array<const System::Byte> ^hashes, System::IO::FileInfo ^outputfile, System::Int64 const filesize)
	{
	HANDLE			hFile;
	UINT32			SizeOfHashes;
	UINT32			BlocksRemain;
	UINT32			HashBytesProcessed;
	LPBYTE			buffer;
	UINT16			Blks;
	bool			retval = true;
	BYTE			localhashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	int				startindex;
	DWORD			dwWritten;
	INT64			BytesRemain = filesize;

	ClearLastError();
	hFile = CreateFile(CString(outputfile->FullName), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		LastError = "CreateFileError:" + GetLastError();
		return false;
		}

	BlocksRemain = (UINT32)(filesize / (UINT64)GCFOS_BLOCK_SIZE);

	SizeOfHashes = BlocksRemain * GCFOS_BLOCK_HASH_LEN;
	if(filesize % GCFOS_BLOCK_SIZE > 0)
		{
		if(filesize % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			SizeOfHashes += (filesize % GCFOS_BLOCK_SIZE);
			}
		else
			{
			SizeOfHashes += GCFOS_BLOCK_HASH_LEN;
			BlocksRemain++;
			}
		}

	buffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(buffer == NULL)
		{
		LastError = "OutOfMemory";
		CloseHandle(hFile);
		return false;
		}

	startindex = 0;
	HashBytesProcessed = 0;
	pin_ptr<const System::Byte> pHashes = &hashes[0];

	while(BlocksRemain > 0)
		{
		Blks = (UINT16)min(BlocksRemain, GCFOS_BLOCKS_PER_QUERY);
		memcpy(localhashes, pHashes, Blks * GCFOS_BLOCK_HASH_LEN);
		pHashes += (Blks * GCFOS_BLOCK_HASH_LEN);
		HashBytesProcessed += (Blks * GCFOS_BLOCK_HASH_LEN);
		if(BlocksRemain < GCFOS_BLOCKS_PER_QUERY)
			{
			memset(localhashes + (Blks * GCFOS_BLOCK_HASH_LEN), 0, GCFOS_BLOCK_HASH_LEN);
			}
		if(g->RetrieveBlocks(localhashes, &Blks, buffer))
			{
			if(!WriteFile(hFile, buffer, (DWORD)min((Blks * GCFOS_BLOCK_SIZE), BytesRemain), &dwWritten, NULL))
				{
				LastError = "WriteFileFailed:" + GetLastError();
				retval = false;
				break;
				}
			}
		else
			{
			LastError = "RetrieveBlocksFailed";
			retval = false;
			break;
			}
		BlocksRemain -= Blks;
		BytesRemain -= dwWritten;
		}
	if(retval == true && HashBytesProcessed < (UINT32)hashes->Length && BytesRemain > 0)
		{
		// write the remaining straggler data
		if(!WriteFile(hFile, pHashes, (DWORD)(hashes->Length - HashBytesProcessed), &dwWritten, NULL))
			{
			LastError = "WriteFileFailed:" + GetLastError();
			retval = false;
			}
		}

	VirtualFree(buffer, NULL, MEM_RELEASE);
	CloseHandle(hFile);
	return retval;
	}

void GCFOS_Client_Managed::SetLastError(GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE Response)
	{
	switch(Response)
		{
		case GCFOS_SRV_RESP_NOTAUTH:
			LastError = "NotAuth";
			break;
		case GCFOS_SRV_RESP_AUTH:
			LastError = "AlreadyAuthenticated";
			break;
		case GCFOS_SRV_RESP_ERROR:
			LastError = "Error";
			break;
		case GCFOS_SRV_RESP_RESIDENT:
			LastError = "Resident";
			break;
		case GCFOS_SRV_RESP_WANTED:
			LastError = "Wanted";
			break;
		case GCFOS_SRV_RESP_UNIQUE:
			LastError = "Unique";
			break;
		case GCFOS_SRV_RESP_LIMBO:
			LastError = "Limbo";
			break;
		case GCFOS_SRV_RESP_SERVER_BUSY:
			LastError = "ServerBusy";
			break;
		case GCFOS_SRV_RESP_NOT_CONNECTED:
			LastError = "NotConnected";
			break;
		case GCFOS_SRV_RESP_OK:
			LastError = "OK";
			break;
		case GCFOS_SRV_RESP_WANT_FILENAME:
			LastError = "FilenameWanted";
			break;
		case GCFOS_SRV_RESP_INVALID_VALIDATION_KEY:
			LastError = "InvalidValidationKey";
			break;
		case GCFOS_SRV_RESP_NOT_CONFIGURED:
			LastError = "NotConfigured";
			break;
		case GCFOS_SRV_RESP_TOO_BIG:
			LastError = "TooBig";
			break;
		case GCFOS_SRV_RESP_HASHES_AVAILABLE:
			LastError = "HashesAvailable";
			break;
		case GCFOS_SRV_RESP_CLIENT_ERROR:
			LastError = "ClientError";
			break;
		default:
			LastError = "Unknown";
			break;
		}
	}

GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE GCFOS_Client_Managed::DeleteObject(array<const System::Byte> ^hash, System::UInt32 size, System::Byte flags)
	{
	ClearLastError();

	if(hash->Length != GCFOS_SHA1_LEN)
		{
		LastError = "InvalidParameterLength";
		return GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE::GCFOS_SRV_RESP_CLIENT_ERROR;
		}

	pin_ptr<const System::Byte> pSHA1 = &hash[0];
	return (GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE)g->DeleteObject(pSHA1, size, flags);
	}

