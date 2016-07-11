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

#ifndef _GCFOS_SERVER
#define _MYEXTERN_ extern
#define _MYINITIALIZER_(__x)
#else
#define _MYEXTERN_
#define _MYINITIALIZER_(__x) __x
#endif

// GLOBALS:
_MYEXTERN_ CRITICAL_SECTION						g_csConnections;
_MYEXTERN_ GCFOS_LISTEN_STATE					g_ListenState[GCFOS_MAX_LISTEN_SOCKETS];
_MYEXTERN_ SYSTEM_INFO							g_SysInfo;
_MYEXTERN_ HANDLE								g_hIOCP _MYINITIALIZER_(= INVALID_HANDLE_VALUE);
_MYEXTERN_ btree::btree_set<PVOID>				g_ConnectState;
_MYEXTERN_ int									g_nZero _MYINITIALIZER_(= 0);
_MYEXTERN_ int									g_nOne _MYINITIALIZER_(= 1);
_MYEXTERN_ gcfosdb								*g_Resident _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Limbo _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Limbo2 _MYINITIALIZER_(=NULL); // secondary index
_MYEXTERN_ gcfosdb								*g_Wanted _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Update _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Clients _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Sessions _MYINITIALIZER_(=NULL);
_MYEXTERN_ TCHAR								g_BlocksDir[MAX_PATH];
_MYEXTERN_ gcfosdb								*g_Blocks _MYINITIALIZER_(=NULL);
_MYEXTERN_ UINT32								g_blks_fileID; // current file id
_MYEXTERN_ UINT32								g_blks_out_offset; // current offset of writing
_MYEXTERN_ HANDLE								g_blks_hFile _MYINITIALIZER_(=INVALID_HANDLE_VALUE);
_MYEXTERN_ bool									g_bDedupeBlocks _MYINITIALIZER_ (=false);
_MYEXTERN_ bool									g_bDedupeFiles _MYINITIALIZER_ (=false);
_MYEXTERN_ bool									g_bEnableBlocksPurging _MYINITIALIZER_ (=false);
_MYEXTERN_ CRITICAL_SECTION						g_csBlksFile;
#ifdef ULTRABAC_CLOUD_USE
_MYEXTERN_ gcfosdb								*g_BannedIPs _MYINITIALIZER_(=NULL);
#else
_MYEXTERN_ gcfosdb								*g_Clients2 _MYINITIALIZER_(=NULL);
#endif//ULTRABAC_CLOUD_USE
_MYEXTERN_ bool									g_VerifyOpens _MYINITIALIZER_(=false);
_MYEXTERN_ LONG									g_SessionsOpen;
_MYEXTERN_ PVOID								g_Txn;
_MYEXTERN_ int									g_debugLvl;
_MYEXTERN_ volatile unsigned long long			g_ThreadsActive;
_MYEXTERN_ HANDLE								g_ExitSignalled;
_MYEXTERN_ bool									g_ShutdownResetLSN _MYINITIALIZER_(=false);
_MYEXTERN_ Repository							*g_Repo _MYINITIALIZER_(=NULL);
_MYEXTERN_ Repository							*g_Repo2 _MYINITIALIZER_(=NULL);
_MYEXTERN_ HKEY									g_MyRegistry;
_MYEXTERN_ FILE									*g_DebugLog;
_MYEXTERN_ CRITICAL_SECTION						g_csDebug;
// CONFIGURATION variables 
_MYEXTERN_ DWORD								g_GCFOS_RESIDENCY_THRESHOLD;  /*minimum of copies needed to move file to residency */
_MYEXTERN_ DWORD								g_GCFOS_RETENTION_DURATION_DAYS; /* number of days to keep file hash in limbo */
_MYEXTERN_ REPOSITORY_TYPE						g_RepositoryType _MYINITIALIZER_(=NONE);
_MYEXTERN_ REPOSITORY_TYPE						g_SecondaryRepositoryType _MYINITIALIZER_(=NONE);
_MYEXTERN_ Repository							*g_LCUD_Repo _MYINITIALIZER_(=NULL);
_MYEXTERN_ DWORD								g_dwInitialEnvSize;
_MYEXTERN_ DWORD								g_dwGrowEnvSize;
_MYEXTERN_ TCHAR								g_LCUD_LocationLocal[96];
_MYEXTERN_ TCHAR								g_LCUD_Location[96];
_MYEXTERN_ UINT32								g_Server_Validation; // Clients check their value against this one, if mismatch they must delete their local cache data
_MYEXTERN_ gcroot<System::String ^>				g_SecondaryBlockStoreLocation _MYINITIALIZER_(=nullptr);
_MYEXTERN_ UINT32								g_BlockStoreSecondaryRepoMinDataChange_MB; // Number of MB written to local blockstore before a copy to secondary is required
_MYEXTERN_ UINT32								g_BlockStoreSecondaryRepoMaxTime_Sec;    // Number of seconds where any change to blockstore must be propagated to secondary

// config REDIRECTION variables
_MYEXTERN_ BYTE									g_RedirectionSecret[GCFOS_SHARED_KEY_LEN] _MYINITIALIZER_(={0});
_MYEXTERN_ GCFOS_CLIENTID						g_RedirectionClientID _MYINITIALIZER_(= 0);
_MYEXTERN_ TCHAR								g_RedirectionServer[32] _MYINITIALIZER_(={0});
_MYEXTERN_ bool									g_bRedirectionMode _MYINITIALIZER_(= false);
// Service-specific variables
_MYEXTERN_ SERVICE_STATUS						g_ServiceStatus;
_MYEXTERN_ SERVICE_STATUS_HANDLE				g_SvcStatusHandle;
#define GCFOS_SERVICE_NAME						"GCFOS Server"
_MYEXTERN_ bool									g_bIsService;
