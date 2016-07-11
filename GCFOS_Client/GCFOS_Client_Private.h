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
// Define private-data structures for GCFOS client

const int GCFOS_CHALLENGE_STR_LEN = 32;
const UINT GCFOS_COMPUTER_NAME_LENGTH = (MAX_COMPUTERNAME_LENGTH+1);
const UINT GCFOS_COMPUTER_NAME_BYTES = (GCFOS_COMPUTER_NAME_LENGTH * sizeof(TCHAR));
const int GCFOS_BLOCK_SIZE_DECOMP = GCFOS_BLOCK_SIZE + 0x400;

const char GCFOS_CLIENT_DB_BLOCKS_NAME[] = "blocks";
const char GCFOS_CLIENT_DB_RESIDENT_NAME[] = "resident";
const char GCFOS_CLIENT_DB_LCUD_NAME[] = "lcud";
const char GCFOS_CLIENT_DB_HASH_NAME[] = "hashes";

const TCHAR GCFOS_COMPUTER_NAME_MININT[] = _T("MININT-");
const size_t GCFOS_COMPUTER_NAME_MININT_LEN = 7;
const TCHAR GCFOS_CLIENT_UBDR_STRING[] = _T("<UBDR>");
const GCFOS_CLIENTID GCFOS_CLIENTID_UBDR = 9999999;


#define GCFOS_LCUD_NOT_PRESENT (UINT32)(-1)

typedef enum {
	GCFOS_REQ_AUTH=1,
	GCFOS_REQ_AUTH_2,
	GCFOS_REQ_SIMPLE_AUTH,
	// values > 100 must be from authenticated clients only
	// sending these values when not authenticated will result in IP being banned
	GCFOS_REQ_QUERY = 100,
	GCFOS_REQ_CONTRIBUTE_FILE,
	GCFOS_REQ_CONTRIBUTE_DATABLOCK,
	GCFOS_REQ_GET_WHOLE_FILE,
	GCFOS_REQ_ADD_CLIENT,
	GCFOS_REQ_GET_CLIENT,
	GCFOS_REQ_DELETE_CLIENT,
	GCFOS_REQ_DELETE_OBJECT,
	GCFOS_REQ_LCUD_REQ,
	GCFOS_REQ_PROVIDE_FILENAME,
	GCFOS_REQ_CONFIG,
	GCFOS_REQ_QUERY_BLOCKS,
	GCFOS_REQ_RESTORE_BLOCK,
	GCFOS_REQ_GET_SERVER_VERSION,
	GCFOS_REQ_INFORM_ACTIVE_HASHES,
	GCFOS_REQ_QUERY_BLOCKCHAIN,
	GCFOS_REQ_GET_FILE_PORTION
	} GCFOS_REQ_TYPE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	unsigned char		SHA1Bytes[GCFOS_SHA1_LEN];
	UINT32				size;
	} GCFOS_REQUEST_QUERY, *PGCFOS_REQUEST_QUERY;

typedef struct GCFOS_SRV_QUERY_RESPONSE {
	GCFOS_SRV_RESPONSE	Response;
	} *PGCFOS_SRV_QUERY_RESPONSE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	} GCFOS_REQUEST_AUTH, *PGCFOS_REQUEST_AUTH;

typedef struct {
	UCHAR				challenge[GCFOS_CHALLENGE_STR_LEN];
	} GCFOS_AUTH_RESPONSE, *PGCFOS_AUTH_RESPONSE;

typedef struct {
	GCFOS_SRV_RESPONSE	result;
	UINT32				seq;
	} GCFOS_AUTH2_RESPONSE, *PGCFOS_AUTH2_RESPONSE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	UCHAR				counter[16];
	UCHAR				challenge_enc[GCFOS_CHALLENGE_STR_LEN];
	UINT32				client;
	} GCFOS_REQUEST_AUTH_2, *PGCFOS_REQUEST_AUTH_2;

typedef struct GCFOS_REQUEST_CONTRIBUTE_FILE {
	GCFOS_REQ_TYPE		type;
	UCHAR				SHA1Bytes[GCFOS_SHA1_LEN];
	UCHAR				flags;
	UCHAR				filler; // make packing alignment obvious
	UINT16				filenamelen;
	UINT32				size;
	CHAR				filename[1]; // variable-length field (length = filenamelen)
	} *PGCFOS_REQUEST_CONTRIBUTE_FILE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	UINT32				size;
	UCHAR				SHA1Bytes[GCFOS_SHA1_LEN];
	CHAR				filename[GCFOS_MAX_FILENAME_LEN];
	} GCFOS_REQUEST_PROVIDE_FILENAME, *PGCFOS_REQUEST_PROVIDE_FILENAME;

typedef struct {
	GCFOS_REQ_TYPE		type;
	UINT32				blocksize;
	UINT32				uncompSize;
	} GCFOS_REQUEST_DATABLOCK, *PGCFOS_REQUEST_DATABLOCK;

typedef struct {
	GCFOS_REQ_TYPE		type;
	unsigned char		SHA1Bytes[GCFOS_SHA1_LEN];
	UINT32				size;
	BYTE				AuthorizationKey[4];
	} GCFOS_REQUEST_GET_WHOLE_FILE, *PGCFOS_REQUEST_GET_WHOLE_FILE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	unsigned char		SHA1Bytes[GCFOS_SHA1_LEN];
	UINT32				size;
	BYTE				AuthorizationKey[4];
	UINT32				Offset;
	UINT32				Length;
	} GCFOS_REQUEST_GET_FILE_PORTION, *PGCFOS_REQUEST_GET_FILE_PORTION;
const UINT32 GCFOS_RETRIEVE_FILE_MAX_PORTION_SIZE = 0x100000;

typedef struct {
	GCFOS_REQ_TYPE		type;
	} GCFOS_REQUEST_ADD_CLIENT, *PGCFOS_REQUEST_ADD_CLIENT;

typedef struct {
	UINT32				client_id;
	UCHAR				shared_key[GCFOS_SHARED_KEY_LEN];
	} GCFOS_CLIENT_INFO, *PGCFOS_CLIENT_INFO;

typedef struct {
	GCFOS_REQ_TYPE		type;
	UINT32				client_id;
	} GCFOS_REQUEST_GET_CLIENT, *PGCFOS_REQUEST_GET_CLIENT;

typedef struct {
	GCFOS_REQ_TYPE		type;
	UINT32				client_id;
	} GCFOS_REQUEST_DELETE_CLIENT, *PGCFOS_REQUEST_DELETE_CLIENT;

typedef struct {
	GCFOS_REQ_TYPE	type;
	UINT32			MySequenceNo; // This is the sequence# I (the client) have
	UINT32			FutureExpansion[4];
	} GCFOS_LCUD_REQUEST, *PGCFOS_LCUD_REQUEST;

typedef struct {
	GCFOS_REQ_TYPE		type;
	Ipp8u				hashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	} GCFOS_REQUEST_QUERY_BLOCKS, *PGCFOS_REQUEST_QUERY_BLOCKS;
typedef struct {
	GCFOS_SRV_RESPONSE	SrvResponse;
	BYTE				present[GCFOS_BLOCKS_PER_QUERY];
	} GCFOS_RESPONSE_QUERY_BLOCKS, *PGCFOS_RESPONSE_QUERY_BLOCKS;
typedef struct {
	GCFOS_REQ_TYPE		type;
	Ipp8u				hashes[GCFOS_BLOCK_HASH_LEN * GCFOS_BLOCKS_PER_QUERY];
	} GCFOS_REQUEST_RETRIEVE_BLOCKS, *PGCFOS_REQUEST_RETRIEVE_BLOCKS;
typedef struct {
	GCFOS_SRV_RESPONSE	SrvResponse;
	UINT16				Sizes[GCFOS_BLOCKS_PER_QUERY];
	// Followed by (compressed) data of all blocks
	} GCFOS_RESPONSE_RETRIEVE_BLOCKS, *PGCFOS_RESPONSE_RETRIEVE_BLOCKS;

#ifndef ULTRABAC_CLOUD_USE

typedef struct {
	GCFOS_REQ_TYPE		type;
	WCHAR				szName[GCFOS_COMPUTER_NAME_LENGTH];
	} GCFOS_REQUEST_SIMPLE_AUTH, *PGCFOS_REQUEST_SIMPLE_AUTH;

typedef struct {
	GCFOS_SRV_RESPONSE	SrvResponse;
	UINT32				client_id;
	UINT32				seq; // LCUD sequence# for this client
	} GCFOS_SIMPLE_AUTH_RESPONSE, *PGCFOS_SIMPLE_AUTH_RESPONSE;

#endif//ULTRABAC_CLOUD_USE

typedef struct {
	GCFOS_REQ_TYPE		type;
	WCHAR				wszComputerName[GCFOS_COMPUTER_NAME_LENGTH];
	} GCFOS_REQUEST_CONFIG, *PGCFOS_REQUEST_CONFIG;

typedef struct {
	USHORT				Size;
	WCHAR				wszComputerName[GCFOS_COMPUTER_NAME_LENGTH];
	WCHAR				wszServerIP[32];
	} GCFOS_CONFIG_RESPONSE, *PGCFOS_CONFIG_RESPONSE;

typedef struct { // this response is sent when a local GCFOS server is responding to a auto-config request
	             // but the server is actually running non-local and will need login credentials
	USHORT				Size; // must not be same size as sizeof(GCFOS_CONFIG_RESPONSE)
	BYTE				Filler[2]; // not used (for alignment only)
	Ipp8u				Secret[GCFOS_SHARED_KEY_LEN];
	WCHAR				wszServerIP[32];
	GCFOS_CLIENTID		ClientID;
	} GCFOS_CONFIG_RESPONSE_2, *PGCFOS_CONFIG_RESPONSE_2;

typedef struct {
	GCFOS_REQ_TYPE		type; //GCFOS_REQ_INFORM_ACTIVE_HASHES
	UINT16				count;
	Ipp8u				hashes[GCFOS_INFORM_ACTIVE_HASHES_COUNT * GCFOS_BLOCK_HASH_LEN];
	} GCFOS_REQUEST_INFORM_ACTIVE_HASHES, *PGCFOS_REQUEST_INFORM_ACTIVE_HASHES;

typedef struct {
	UINT16				Version;
	struct {
		unsigned char	FileStore:1;
		unsigned char	future_use1:7;
		};
	struct {
		unsigned char	BlockStore:1;
		unsigned char	EnableBlockPurging:1;
		unsigned char	future_use2:6;
		};
	UINT32				ServerValidation;
	} GCFOS_GET_SERVER_VERSION_RESPONSE, *PGCFOS_GET_SERVER_VERSION_RESPONSE;

typedef struct {
	GCFOS_REQ_TYPE		type;
	Ipp8u				hash[GCFOS_SHA1_LEN];
	UINT64				i64size;
	} GCFOS_REQUEST_GET_BLOCKCHAIN, *PGCFOS_REQUEST_GET_BLOCKCHAIN;

typedef struct  {
	Ipp8u			hash[GCFOS_BLOCK_HASH_LEN];
	mutable UINT16	last_ref;
	} GCFOS_LOCAL_BLOCK_ENTRY, *PGCFOS_LOCAL_BLOCK_ENTRY;

typedef struct GCFOS_LOCAL_ENTRY {
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;

	bool operator< ( const GCFOS_LOCAL_ENTRY &comp) const
		{
		int rtn;

		rtn = memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN);
		if(rtn == 0)
			{
			rtn = size - comp.size;
			}
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_LOCAL_ENTRY &comp) const
		{
		if(memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN) == 0
		&& size == comp.size)
			return true;
		else
			return false;
		}

	} *PGCFOS_LOCAL_ENTRY;

// Data structures for GCFOS_Cache

typedef struct GCFOS_CLIENT_CACHE_ENTRY {
	Ipp8u				filehash[GCFOS_FILENAME_HASH_LEN];
	mutable FILETIME	ft;
	mutable UINT32		size;
	mutable BYTE		validationKey[GCFOS_VALIDATION_KEY_LEN];
	mutable Ipp8u		SHA1[GCFOS_SHA1_LEN];
	mutable UINT16		last_ref;

	bool operator< ( const GCFOS_CLIENT_CACHE_ENTRY &comp) const
		{
		int rtn;

		rtn = memcmp(&filehash, &comp.filehash, GCFOS_FILENAME_HASH_LEN);
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_CLIENT_CACHE_ENTRY &comp) const
		{
		if(memcmp(&filehash, &comp.filehash, GCFOS_FILENAME_HASH_LEN) == 0)
			return true;
		else
			return false;
		}

	} *PGCFOS_CLIENT_CACHE_ENTRY;

#define GCFOS_SERVER_PORT "1910"

#define GCFOS_CLIENT_SRC_BUFSIZE		0x100000 /* 1 MB */
#define GCFOS_CLIENT_DST_BUFSIZE		0x120000 /* Larger than 1MB as compression may add size */

#define GCFOS_COMPRESSED_BIT			0x80000000 /* High bit of UINT32 -- indicates that this is a compressed block */
#define GCFOS_COMPRESSED_BITMASK		0x7fffffff /* Mask to take out compressed bit */

#define GCFOS_OBJECT_COUNT_FOR_ENTRY(__x) ((__x) / GCFOS_CLIENT_SRC_BUFSIZE + (((__x) & (GCFOS_CLIENT_SRC_BUFSIZE - 1)) == 0 ? 0 : 1))

// This is only a separate class to prevent exposure of internal workings of the GCFOS_Client class






       
   
     
   
 
 
 
             
    
 
     
