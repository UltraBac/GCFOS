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

//  Constants
const int GCFOS_MAX_LISTEN_SOCKETS = 16;
const int GCFOS_BUFSIZE = 0x40000;
const int GCFOS_MAX_IP_ADDR_LEN = 16;
#ifndef ULTRABAC_CLOUD_USE
const int GCFOS_MAX_DATAGRAM_SIZE = 0x1000;
#endif//ULTRABAC_CLOUD_USE
const UINT32 GCFOS_MAINTENANCE_PERIOD = 30; // Every 30 secs perform maintenance duties (check banned IPs, inactive sessions etc)
const UINT32 GCFOS_INITIAL_ACTIVITY_VALUE = 720; //(multiples of GCFOS_MAINTENANCE_PERIOD -- see MaintenanceWorker)  720=6 hrs

const TCHAR GCFOS_REGISTRY_KEY[] = _T("SOFTWARE\\UltraBac Software\\GCFOS");
const TCHAR GCFOS_REG_RESIDENCY_THRESHOLD[] = _T("ResidencyThreshold");
const TCHAR GCFOS_REG_LIMBO_RETENTION_DAYS[] = _T("LimboRetentionDays");
const TCHAR GCFOS_REG_ACCESS_KEY[] = _T("RepositoryAccessKey");
const TCHAR GCFOS_REG_SECRET_KEY[] = _T("RepositorySecretKey");
const TCHAR GCFOS_REG_REPO_TYPE[] = _T("RepositoryType");
const TCHAR GCFOS_REG_REPO_LOCATION[] = _T("RepositoryLocation");
const TCHAR GCFOS_REG_REPO_ENDPOINT[] = _T("RepositoryEndpoint");
const TCHAR GCFOS_REG_REPO_REGION[] = _T("RepositoryRegion");
const TCHAR GCFOS_REG_REPO_SECONDARY_TYPE[] = _T("SecondaryRepositoryType");
const TCHAR GCFOS_REG_REPO_SECONDARY_LOCATION[] = _T("SecondaryRepositoryLocation");
const TCHAR GCFOS_REG_REPO_SECONDARY_ENDPOINT[] = _T("SecondaryRepositoryEndpoint");
const TCHAR GCFOS_REG_REPO_SECONDARY_REGION[] = _T("SecondaryRepositoryRegion");
const TCHAR GCFOS_REG_SECONDARY_ACCESS_KEY[] = _T("SecondaryRepositoryAccessKey");
const TCHAR GCFOS_REG_SECONDARY_SECRET_KEY[] = _T("SecondaryRepositorySecretKey");
const TCHAR GCFOS_REG_ENABLE_SERVICE_DISCOVERY[] = _T("EnableServiceDiscovery");
const TCHAR GCFOS_REG_BLOCK_STORE_PATH[] = _T("BlockStorePath");
const TCHAR GCFOS_REG_DB_ENV_SIZE[] = _T("DatabaseEnvironmentSizeMB");
const TCHAR GCFOS_REG_DB_ENV_GROW[] = _T("DatabaseEnvironmentGrowMB");
const TCHAR GCFOS_REG_REPO_LCUD_LOCATION_LOCAL[] = _T("LocalLCUDLocation");
const TCHAR GCFOS_REG_REPO_LCUD_LOCATION[] = _T("RepositoryLCUDLocation");
const TCHAR GCFOS_REG_SERVER_VALIDATION[] = _T("ServerValidation");
const TCHAR GCFOS_REG_SECONDARY_BLOCK_STORE_LOCATION[] = _T("SecondaryBlockStoreLocation");
const TCHAR GCFOS_REG_EXPLICIT_IP_ADDRESS[] = _T("ExplicitIPAddress");
const TCHAR GCFOS_REG_BLOCKSTORE_SECONDARY_REPO_MIN_DATA_CHANGE_MB[] = _T("BlockStoreSecondaryRepoMinDataChange_MB");
const TCHAR GCFOS_REG_BLOCKSTORE_SECONDARY_REPO_MAX_TIME_SEC[] = _T("BlockStoreSecondaryRepoMaxTime_Sec");
const TCHAR GCFOS_REG_CONFIG_REDIRECT_CLIENT[] = _T("ConfigRedirectClientID");
const TCHAR GCFOS_REG_CONFIG_REDIRECT_SECRET[] = _T("ConfigRedirectSecret");
const TCHAR GCFOS_REG_CONFIG_REDIRECT_SERVER[] = _T("ConfigRedirectServer");//optional
const TCHAR GCFOS_REG_ENABLE_BLOCKS_PURGING[] = _T("EnableBlocksPurging");
const TCHAR GCFOS_REG_BLOCKS_FILE_ID[] = _T("BlocksFileID");
const TCHAR GCFOS_REG_BLOCKS_FILE_OFFSET[] = _T("BlocksFileOffset");

// Definitions:

typedef enum IOCP_OP_TYPE : unsigned short { 
		IOCP_OP_ACCEPT = 0xf0,
		IOCP_OP_CHALLENGE_SENT,
		IOCP_OP_WAITING_ENC_CHALLENGE,
		IOCP_OP_WAITING_REQUEST,
		IOCP_OP_WAITING_DATABLOCK, // For receiving file from contributor
		IOCP_OP_WRITING_DATABLOCK,
		IOCP_OP_READING_DATABLOCK, // for sending file (restore) to client
		IOCP_OP_READING_DATABLOCK_PORTION, // for sending file (restore) to client
		IOCP_OP_SENDING_LCUD,
		IOCP_OP_AWAITING_BROADCAST, // used only on ULTRABAC_CLOUD_USE
		IOCP_OP_BROADCAST_SENT_RESPONSE, // used only for ULTRABAC_CLOUD_USE
		IOCP_OP_RECEIVING_BLOCKS,
		IOCP_OP_SENT_BLOCK_QUERY_RESPONSE,
		IOCP_OP_SENT_RETRIEVE_BLOCK_RESPONSE,
		IOCP_OP_RECEIVING_INCOMPLETE_COMMAND,
		IOCP_OP_WRITING_HASHCHAIN,
		IOCP_OP_SENT_FINAL_RESPONSE
	} *PIOCP_OP_TYPE;

typedef struct {
	WSAOVERLAPPED	o;
	IOCP_OP_TYPE	op;
	SOCKET			s_list; // listen socket
	char			hostid[32];
    LPFN_ACCEPTEX	fnAcceptEx;
	LPFN_GETACCEPTEXSOCKADDRS fnGetAcceptExSockaddrs;
	int				ai_family;
	int				ai_socktype;
	int				ai_protocol;
#ifndef ULTRABAC_CLOUD_USE
	WSABUF			buffer;
	SOCKADDR		connectedTo;
	int				connectedToLen;
// "Customer" builds
#endif
	} GCFOS_LISTEN_STATE, *PGCFOS_LISTEN_STATE;

typedef enum GCFOS_CONNECT_STATUS : unsigned short {
	STATE_NOT_CONNECTED,
	STATE_ACCEPT,
	STATE_CONNECTED
	} *PGCFOS_CONNECT_STATUS;

typedef struct GCFOS_OBJECT_DESCRIPTOR {
	UINT32			*sizes;
	INT32			cur_entry;
	gcroot<array<System::Byte> ^> objbuf;
	} *PGCFOS_OBJECT_DESCRIPTOR;

class GCFOS_CONNECT_STATE {
public:
	WSAOVERLAPPED	o; // MUST be first parameter (used in IOCP operations)
	IOCP_OP_TYPE	op;
	GCFOS_CONNECT_STATUS status;
	UINT32			activityTimer; // if reaches 0, connection is terminated (zombie session)
	WSABUF			buffer; // buffer
	SOCKET			s_acc; // accept socket
	struct			sockaddr connectedTo;
	INT32			connectedToLen;
	CHAR			connectedToHost[GCFOS_MAX_IP_ADDR_LEN]; // this will either be the computer-name (local) or IP address
	GCFOS_CLIENTID	client;
	// Fields for when accepting a file contribution
	bool			bHdr;
	bool			bCompressed;
	bool			InError;
	GCFOS_REQUEST_DATABLOCK hdr;
	UINT32			remaining;
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	BYTE			ValidationBytes[GCFOS_VALIDATION_KEY_LEN];
	IppsHashState*	ContextForCalculatedHash;
	UINT32			size;
	LPBYTE			inputBuffer;
	UINT16			CurBlock;
	UINT16			BlockSizes[GCFOS_BLOCKS_PER_QUERY];
	LPBYTE			decompressedBuffer;
	UINT32			outputOffset;
	UINT32			offset; // The offset start of this block (used for filename)
	UINT32			time;
	gcroot<array<System::Byte> ^> object_buffer;
#ifdef ULTRABAC_CLOUD_USE
	PUCHAR			challenge; // pointer to challenge string sent for this context (may be NULL!)
#endif
	PGCFOS_OBJECT_DESCRIPTOR od; // only present if currently retrieving object for client
	Hash_FileManager<GCFOS_LOCAL_ENTRY> *pLCUD; // only present if currently sending LCUD data to client

	UINT8			iBlocksExpected;
	Ipp8u			BlockHashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	//Statistics trackers
	UINT32			count_donations;
	UINT32			count_queries;
	UINT32			count_resident_hits;
	UINT32			count_limbo_results;
	UINT32			count_retrieves;
	UINT64			count_retrieve_KB;
	UINT32			count_blks_queried;
	UINT32			count_blks_stored;
	UINT32			count_blks_retrieved;

	//session record
	UINT32			session_record; // the primary key of the session record

	//Functions (implemented in Misc.cpp)
	GCFOS_CONNECT_STATE(SOCKET in_s, IOCP_OP_TYPE in_op, GCFOS_CONNECT_STATUS in_state);
	GCFOS_CONNECT_STATE();
	void InitializeConnectionState(SOCKET in_s, IOCP_OP_TYPE in_op, GCFOS_CONNECT_STATUS in_state);

	~GCFOS_CONNECT_STATE();
	};
typedef GCFOS_CONNECT_STATE *PGCFOS_CONNECT_STATE;

#if 0
template<typename T>
class LockSet {
public:
	dbstl::db_set<T> *s;
	Locker l;

	size_t lockSize() {
		size_t rtn;
		l.Read();
		rtn = s->size();
		l.ReadEnd();
		return rtn;
		}
	};
#endif

#include "GCFOS_DataTypes.h"

typedef enum { NONE, LOCALFILE, S3, OPENSTACK, AZURE } REPOSITORY_TYPE;

const char GCFOS_DBNAME_BANNED[] = "banned";
const char GCFOS_DBNAME_CLIENTDB[] = "clientdb";
const char GCFOS_DBNAME_CLIENTDB2[] = "clientdb_2";
const char GCFOS_DBNAME_LIMBO[] = "limbo";
const char GCFOS_DBNAME_LIMBO2[] = "limbo_2";
const char GCFOS_DBNAME_RESIDENT[] = "resident";
const char GCFOS_DBNAME_WANTED[] = "wanted";
const char GCFOS_DBNAME_UPDATE[] = "update";
//const char GCFOS_DBNAME_UPDATE_SAVE[] = "update_save";
const char GCFOS_DBNAME_SESSIONS[] = "sessions";
const char GCFOS_DBNAME_BLOCKS[] = "blocks";

// Function declarations
int locateEmptyConnectSlot();
unsigned __stdcall GCFOS_Listener(void * param);
unsigned __stdcall UpdateWorker(void * param);
#ifdef ULTRABAC_CLOUD_USE
void ProcessAuthPhase1(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessAuthPhase2(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void BanIP(PGCFOS_CONNECT_STATE context);
bool IsBannedIP(PGCFOS_CONNECT_STATE context);
#define CONTEXT_IS_ADMIN (context->client == 1)
#else
#define BanIP(_x)
#define CONTEXT_IS_ADMIN (true)
void ProcessSimpleAuth(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
#endif//ULTRABAC_CLOUD_USE
void ProcessDeleteClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessGetClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessAddClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void DoDeleteObjects(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessDeleteObject(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessAccept(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void RequestCommand(PGCFOS_CONNECT_STATE context);
void CloseConnection(PGCFOS_CONNECT_STATE context, GCFOS_SESSION_END_REASON reason = FORCED);
void ProcessRequest(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessQuery(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void SendSimpleResponseToClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, const GCFOS_SRV_RESPONSE, IOCP_OP_TYPE newop = IOCP_OP_SENT_FINAL_RESPONSE);
void SendQueryResponseToClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, PGCFOS_SRV_QUERY_RESPONSE);
void ReceiveHashChainFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ReceiveFileFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ReceiveDatablockFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessGetWholeFileCommand(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void SendDataBlockToRequestor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void SendDataBlockPortionToRequestor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessLCUDRequest(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessLCUDBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessProvideFilename(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessBroadcastSentResponse(PGCFOS_LISTEN_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessAutoConfig(PGCFOS_LISTEN_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessQueryBlocks(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessRestoreBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessGetServerVersion(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessInformActiveHashes(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessGetFilePortion(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);


     
   
 
 
 
             
    
 
     
