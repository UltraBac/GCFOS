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

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the GCFOS_CLIENT_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// GCFOS_CLIENT_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.


// Only the public methods/definitions should be defined here.
// For internal definitions and structures use GCFOS_Client_Private.h
#ifndef _GCFOS_CLIENT_H_
#define _GCFOS_CLIENT_H_

#ifdef _WIN32
#define GCFOS_CLIENT_LOCALONLY
#if GCFOS_CLIENT_EXPORTS
#define GCFOS_CLIENT_API __declspec(dllexport)
#else
#define GCFOS_CLIENT_API __declspec(dllimport)
#endif//GCFOS_CLIENT_EXPORTS
#else
#define GCFOS_CLIENT_API __attribute__ ((visibility ("default")))
#define GCFOS_CLIENT_LOCALONLY __attribute__ ((visibility ("hidden")))
#endif

#define GCFOS_CLIENT_REG_SERVER				_T("Server")
#define GCFOS_CLIENT_REG_SERVER_IP			_T("ServerIP")
#define GCFOS_CLIENT_REG_SECRETKEY			_T("SecretKey")
#define GCFOS_CLIENT_REG_CLIENTID			_T("ClientID")
#define GCFOS_CLIENT_REG_LCUD_SEQ			_T("LCUDSequence")
#define GCFOS_CLIENT_REG_CLIENT_VALIDATION  _T("ClientValidation")


typedef UINT32 GCFOS_CLIENTID, *PGCFOS_CLIENTID;

const int GCFOS_FILENAME_HASH_LEN = 16;
const int GCFOS_SHA1_LEN = 20;
const int GCFOS_BLOCK_HASH_LEN = 28;
const int GCFOS_BLOCKS_PER_QUERY = 16;
const int GCFOS_MINIMUM_BLOCK_SIZE = 0x100;
const int GCFOS_BLOCK_SIZE = 0x1000; //4KB
const int GCFOS_MAX_BLOCK_SIZE = GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE;
const int GCFOS_SHARED_KEY_LEN = 32;
const int GCFOS_MAX_FILENAME_LEN = 0xf0;
const int GCFOS_VALIDATION_KEY_LEN = 4;
const UINT32 GCFOS_FILE_MINIMUM_SIZE = 0x2000;
const UINT64 GCFOS_FILE_MAX_SIZE = 0x100000000LL; //4GB
const int GCFOS_INFORM_ACTIVE_HASHES_COUNT = 30;

#define GCFOS_SRV_RESP_ENUMERATIONS \
	GCFOS_SRV_RESP_NOTAUTH, \
	GCFOS_SRV_RESP_AUTH, \
	GCFOS_SRV_RESP_ERROR, \
	GCFOS_SRV_RESP_RESIDENT, \
	GCFOS_SRV_RESP_WANTED, \
	GCFOS_SRV_RESP_UNIQUE, \
	GCFOS_SRV_RESP_LIMBO, \
	GCFOS_SRV_RESP_SERVER_BUSY, \
	GCFOS_SRV_RESP_NOT_CONNECTED, \
	GCFOS_SRV_RESP_OK, \
	GCFOS_SRV_RESP_WANT_FILENAME, \
	GCFOS_SRV_RESP_INVALID_VALIDATION_KEY, \
	GCFOS_SRV_RESP_NOT_CONFIGURED, \
	GCFOS_SRV_RESP_TOO_BIG, \
	GCFOS_SRV_RESP_HASHES_AVAILABLE, \
	GCFOS_SRV_RESP_CLIENT_ERROR, \
	GCFOS_SRV_RESP_PARAMETER_ERROR

typedef enum GCFOS_SRV_RESPONSE : UINT16 {
	GCFOS_SRV_RESP_ENUMERATIONS
	} _GCFOS_SRV_RESPONSE, *PGCFOS_SRV_RESPONSE;

#ifdef __cplusplus_cli
namespace GCFOS_MANAGED_CLIENT {
	public enum class GCFOS_SRV_RESPONSE : UINT16 {
		GCFOS_SRV_RESP_ENUMERATIONS
		};
	};
#endif//__cplusplus_cli

#define GCFOS_LOCAL_ERASE_TYPE_ENUMERATIONS \
	GCFOS_LOCAL_ERASE_TYPE_NONE = 0, \
	GCFOS_LOCAL_ERASE_TYPE_BLOCKS, \
	GCFOS_LOCAL_ERASE_TYPE_RESIDENT, \
	GCFOS_LOCAL_ERASE_TYPE_UNIQUE, \
	GCFOS_LOCAL_ERASE_TYPE_HASH 

#ifdef __cplusplus_cli
namespace GCFOS_MANAGED_CLIENT {
	public enum class GCFOS_LOCAL_ERASE_TYPE : UINT16 {
		GCFOS_LOCAL_ERASE_TYPE_ENUMERATIONS
	};
};
#endif//__cplusplus_cli

typedef enum GCFOS_LOCAL_ERASE_TYPE : UINT16 {
	GCFOS_LOCAL_ERASE_TYPE_ENUMERATIONS
	} _GCFOS_LOCAL_ERASE_TYPE;

class GCFOS_CLIENT_API GCFOS_PRIVATE_MEMBERS;
class GCFOS_CLIENT_API GCFOS_PRIVATE_STATICS;

typedef struct GCFOS_CLIENT_SESSIONINFO {
	UINT64	locallyAdded; // number of entries added to local-resident db
	UINT64	locallyResidentHits; // Number of "cache" hits found in local resident db
	UINT64	Resident; // Number of entries in local-resident db
	UINT64	Unique;
	UINT64	UniqueHits;
	UINT64	SHA1Hits; // SHA1 cache hits
	UINT64	SHA1Misses; // SHA1 cache misses
	double	TotalQueryTime; // total time spent querying server
	UINT64	ServerQueries; // total number of queries (non-cached) sent to server
	UINT64  BlocksQueried; // Number of queries to block store
	UINT64  BlocksStored; // Number of blocks stored (misses)
	UINT64	BlocksHitCache; // Number of cache queries resolved by local cache
	double	TotalBlockQueryTime; // time spent querying blocks
	double	TotalBlockStoreTime; // time spent storing blocks
	} *PGCFOS_CLIENT_SESSIONINFO;

#ifdef __cplusplus_cli
// Managed version of GCFOS_CLIENT_SESSIONINFO
namespace GCFOS_MANAGED_CLIENT {
public ref class GCFOS_CLIENT_SESSIONINFO {
public:
	UINT64	locallyAdded;
	UINT64	locallyResidentHits;
	UINT64	Resident;
	UINT64	Unique;
	UINT64	UniqueHits;
	UINT64	SHA1Hits;
	UINT64	SHA1Misses;
	double	TotalQueryTime;
	UINT64	ServerQueries;
	UINT64  BlocksQueried;
	UINT64  BlocksStored;
	UINT64	BlocksHitCache;
	double	TotalBlockQueryTime;
	double	TotalBlockStoreTime;
	GCFOS_CLIENT_SESSIONINFO(PGCFOS_CLIENT_SESSIONINFO info) {
		locallyAdded = info->locallyAdded;
		locallyResidentHits = info->locallyResidentHits;
		Resident = info->Resident;
		Unique = info->Unique;
		UniqueHits = info->UniqueHits;
		SHA1Hits = info->SHA1Hits;
		SHA1Misses = info->SHA1Misses;
		TotalQueryTime = info->TotalQueryTime;
		ServerQueries = info->ServerQueries;
		BlocksQueried = info->BlocksQueried;
		BlocksStored = info->BlocksStored;
		BlocksHitCache = info->BlocksHitCache;
		TotalBlockQueryTime = info->TotalBlockQueryTime;
		TotalBlockStoreTime = info->TotalBlockStoreTime;
		}
	};
};
#endif//__cplusplus_cli

// flags for ContributeFile -- BITFIELDS
#define GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_FORCE 0x1
#define GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_HASHCHAIN 0x2
#define GCFOS_REQUEST_DELETE_FILE_BUT_WANTED 0x4

// forward def
struct GCFOS_REQUEST_CONTRIBUTE_FILE;

#ifdef _WIN32
typedef HANDLE FILEHANDLE;
#else
typedef FILE* FILEHANDLE;
#endif//_WIN32

// This class is exported from the GCFOS_Client.dll
class GCFOS_CLIENT_API GCFOS_Client {
public:
	GCFOS_Client(void);
	~GCFOS_Client(void);
	bool					Connect(LPCTSTR cachePath, LPCTSTR CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache);
	bool					Connect(LPCTSTR cachePath, LPCTSTR CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache, LPCTSTR Server, GCFOS_CLIENTID Client, BYTE const * Secret);
	static void				SetConsoleLogging(bool bLog);
	GCFOS_SRV_RESPONSE		Query(BYTE const * q, UINT32 size);
	void					Close();
	GCFOS_SRV_RESPONSE		Auth();
	bool					ContributeFile(LPCTSTR filename, BYTE const * SHA1, UINT32 size, UCHAR flags = 0);
	bool					ContributeFileByHandle(FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPCTSTR filename, UCHAR flags = 0); // Filename is used only for logging to server
	bool					RetrieveWholeFile(BYTE const * SHA1, UINT32 size, LPCTSTR filename, LPBYTE ValidationKey);
	bool					RetrieveWholeFile(FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPBYTE ValidationKey);
	bool					RetrieveFilePortion(BYTE const * SHA1, UINT32 size, LPBYTE ValidationKey, UINT32 offset, LPBYTE buffer, UINT32 buffersize);
	GCFOS_SRV_RESPONSE		RegisterNewClient(PUINT32 newid, LPBYTE sharedkey);
	GCFOS_SRV_RESPONSE		GetClientDetails(UINT32 id, PUCHAR sharedkey);
	GCFOS_SRV_RESPONSE		DeleteClient(UINT32 id);
	void					GetSessionInfo(PGCFOS_CLIENT_SESSIONINFO info);
	GCFOS_SRV_RESPONSE		DeleteObject(BYTE const * SHA1, UINT32 size, UCHAR flags);
	GCFOS_CLIENTID			GetClientID();
	GCFOS_SRV_RESPONSE		ProvideFileName(LPCTSTR path, BYTE const * SHA1, UINT32 size);
	bool					GetHash(LPCTSTR filename, LPCTSTR filepathForOpen, LPBYTE SHA1, LPFILETIME pFt, PUINT32 pSize, LPBYTE ValidationKey);
	bool					GetHashForHandle(LPCTSTR filename, FILEHANDLE hFile, LPBYTE SHA1, FILETIME Ft, UINT32 Size, LPBYTE ValidationKey);
	bool					GenerateHashForHandle(FILEHANDLE hFile, LPBYTE SHA1, UINT32 expectedsize, LPBYTE ValidationKey);
	bool					GenerateHashForFile(LPCTSTR filename, LPBYTE SHA1, UINT32 expectedsize, LPBYTE ValidationKey);
	bool					FileStoreEnabled();
	bool					EraseLocalCache(LPCTSTR pszCachePath, LPCTSTR CompanyName, GCFOS_LOCAL_ERASE_TYPE type);
	bool					GetHashForFilename(LPCTSTR filename, BYTE *filenamehash);

	// block dedupe functions
	bool					BlockStoreEnabled();
	int						CalculateHashesForBlocks(BYTE const * pBlockData, UINT32 &blks, const UINT32 size, LPBYTE pReferences, PUINT32 outsize, LPBYTE straggler_block /* temp area of 4KB */);
	bool					StoreBlocks(BYTE const * pBlockData, UINT32 size, LPBYTE pReferences, PUINT32 outsize);
	bool					RetrieveBlocks(BYTE const * Hashes, PUINT16 Count, LPBYTE Blocks);
	bool					UpdateLocalBlockCache();
	UINT32					GetHashDataLengthForFileSize(INT64 filesize);
	INT64					GetBlockHashesForFile(FILEHANDLE hFile, LPCTSTR filename, LPBYTE hashdata, UINT32 hashdata_size);
	bool					AttemptAutoConfig(HKEY hKey);
	bool					ValidateLocalBlockCache();


private:
	GCFOS_PRIVATE_MEMBERS *m_priv;
	GCFOS_PRIVATE_STATICS static *m_statics;

	bool					LoadLCUDList();
	bool					SwitchClient(LPCWSTR pszNewComputerName);
	bool					GenerateBlockHashChain(GCFOS_REQUEST_CONTRIBUTE_FILE *pReqContributeFile, FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPCTSTR filename);

	LPTSTR					m_CachePath;
	bool					m_bEnableLocalCache;
	bool					m_bEnableLocalBlockCache;
	bool					m_bEnableExtendedLocalBlockCache;
	bool					m_bBlockPurgingEnabled;
	bool					m_bSimpleAuthSuccessful;
};

void __cdecl BeginCompressionThread(void *myclass);

extern GCFOS_CLIENT_API int nGCFOS_Client_Ver;
   
#ifndef _WIN32
void time_t_to_FILETIME(time_t const t, LPFILETIME ft);
#endif

#endif       
   
     
   
 
 
 
             
    
 
     
