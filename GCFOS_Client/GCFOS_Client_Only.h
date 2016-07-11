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

//
// This file is for definitions that are relevant ONLY to the client and NOT
// the server

#pragma warning(push)
#pragma warning(disable:4251) // disable warnings like class 'btree::btree_set<Key>' needs to have dll-interface to be used by clients of class 'GCFOS_PRIVATE_MEMBERS'

class GCFOS_CLIENT_API GCFOS_PRIVATE_STATICS
	{
	// This class is only instantiated ONCE for all instances of GCFOS_Client
	// so the variables here are SHARED amongst all instances. 

	friend class GCFOS_Client;

	private:
		// database info
		gcfosdb		m_db_blocks;
		gcfosdb		m_db_resident;
		gcfosdb		m_db_LCUD;
		gcfosdb		m_db_hashes;

		LARGE_INTEGER liCounterFreq;
		HKEY		m_hKey; // handle to registry containing configuration details

		GCFOS_PRIVATE_STATICS() {
			QueryPerformanceFrequency(&liCounterFreq);
			m_hKey = NULL; // INVALID_HANDLE_VALUE is not valid for HKEYs
			}
		~GCFOS_PRIVATE_STATICS() {
			if(m_hKey != NULL)
				{
				RegCloseKey(m_hKey);
				}
			}
	};

class GCFOS_CLIENT_API GCFOS_PRIVATE_MEMBERS
	{
	public:
		GCFOS_PRIVATE_MEMBERS()
			{
			m_bInit = false;
			m_bConnected = false;
			m_bSecretFound = false;
			m_pLZOState = NULL;
			m_uLZOsize = 0;
			m_locallyAdded = 0;
			m_locallyResidentHits = 0;
			m_UniqueHits = 0;
			m_SHA1Hits = 0;
			m_SHA1Misses = 0;
			m_LCUD_seq = 0;
			m_Queries = 0;
			m_QueryTime = 0;
			m_BlkQueries = 0;
			m_BlkStores = 0;
			m_BlkCacheHit = 0;
			m_BlkQueryTime = 0;
			m_BlkStoreTime = 0;
			memset(&m_SecretKey, 0, GCFOS_SHARED_KEY_LEN);
			m_ClientID = 0;
			memset(&m_ComputerName, 0, GCFOS_COMPUTER_NAME_LENGTH);
			m_bWorkerThreadsInit = false;
			m_WorkerThreadCount = 0;
			m_hWorkerPort = INVALID_HANDLE_VALUE;
			InitializeCriticalSection(&m_csAccess);
			m_HashChainSize = 0;
			m_pHashChain = NULL;
			m_szIPConnection[0] = 0;
			m_szServerConnection[0] = 0;
			};
		~GCFOS_PRIVATE_MEMBERS()
			{
			if(m_uLZOsize > 0)
				{
				m_uLZOsize = 0;
				ippsFree(m_pLZOState);
				m_pLZOState = NULL;
				}
			if(m_HashChainSize > 0 && m_pHashChain != NULL)
				{
				VirtualFree(m_pHashChain, 0, MEM_RELEASE);
				m_HashChainSize = 0;
				}
			}

	friend class GCFOS_Client;

	private:
		SOCKET		m_srv;
		bool		m_bInit;
		bool		m_bConnected;
		bool		m_bSecretFound;
		bool		m_bUBDR;
		Ipp32u		m_uLZOsize;
		IppLZOState_8u *m_pLZOState;
		UINT64		m_locallyResidentHits;
		UINT64		m_locallyAdded;
		UINT64		m_UniqueHits;
		UINT64		m_SHA1Hits;
		UINT64		m_SHA1Misses;
		UINT32		m_LCUD_seq;
		Ipp8u		m_SecretKey[GCFOS_SHARED_KEY_LEN];
		WCHAR		m_ComputerName[GCFOS_COMPUTER_NAME_LENGTH];
		UINT64		m_Queries;
		UINT64		m_QueryTime;
		UINT64		m_BlkQueries;
		UINT64		m_BlkStores;
		UINT64		m_BlkQueryTime;
		UINT64		m_BlkStoreTime;
		UINT64		m_BlkCacheHit;
		GCFOS_CLIENTID	m_ClientID;
		TCHAR		m_szIPConnection[32];
		TCHAR		m_szServerConnection[64];

		// used for block dedupe functions:
		bool		m_bWorkerThreadsInit;
		HANDLE		m_hWorkerPort;
		UINT32		m_WorkerThreadCount;
		GCFOS_GET_SERVER_VERSION_RESPONSE m_ServerVersion;
		CRITICAL_SECTION m_csAccess;

		// Following vars used for restoring (and remembering context) portions of files
		LPBYTE		m_pHashChain;
		INT32		m_HashChainSize;
		Ipp8u		m_SaveSHA1[GCFOS_SHA1_LEN];
		UINT32		m_SaveSize;
		BYTE		m_SaveValidationKey[GCFOS_VALIDATION_KEY_LEN];

		// Functions:
		bool		InitializeCompression();
		bool		InitializeWorkThreads();
	public:
		void		WorkThread();
	};

#pragma warning(pop)
