#ifndef _MIGRATOR_CPP
#define _MYEXTERN_ extern
#define _MYINITIALIZER_(__x)
#else
#define _MYEXTERN_
#define _MYINITIALIZER_(__x) __x
#endif

_MYEXTERN_ int									g_debugLvl _MYINITIALIZER_(=3);
_MYEXTERN_ DWORD								g_dwInitialEnvSize;
_MYEXTERN_ DWORD								g_dwGrowEnvSize;
_MYEXTERN_ gcfosdb								*g_Resident _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Limbo _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Limbo2 _MYINITIALIZER_(=NULL); // secondary index
_MYEXTERN_ gcfosdb								*g_Wanted _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Update _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Clients _MYINITIALIZER_(=NULL);
_MYEXTERN_ gcfosdb								*g_Sessions _MYINITIALIZER_(=NULL);
_MYEXTERN_ TCHAR								g_BlocksDir[MAX_PATH];
_MYEXTERN_ gcfosdb								*g_Blocks _MYINITIALIZER_(=NULL);
#ifdef ULTRABAC_CLOUD_USE
_MYEXTERN_ gcfosdb								*g_BannedIPs _MYINITIALIZER_(=NULL);
#else
_MYEXTERN_ gcfosdb								*g_Clients2 _MYINITIALIZER_(=NULL);
#endif//ULTRABAC_CLOUD_USE
_MYEXTERN_ UINT32								g_blks_fileID; // current file id
_MYEXTERN_ UINT32								g_blks_out_offset; // current offset of writing

const char GCFOS_DBNAME_BANNED[] = "banned";
const char GCFOS_DBNAME_CLIENTDB[] = "clientdb";
const char GCFOS_DBNAME_CLIENTDB2[] = "clientdb_2";
const char GCFOS_DBNAME_LIMBO[] = "limbo";
const char GCFOS_DBNAME_LIMBO2[] = "limbo_2";
const char GCFOS_DBNAME_RESIDENT[] = "resident";
const char GCFOS_DBNAME_WANTED[] = "wanted";
const char GCFOS_DBNAME_UPDATE[] = "update";
const char GCFOS_DBNAME_SESSIONS[] = "sessions";
const char GCFOS_DBNAME_BLOCKS[] = "blocks";

const int GCFOS_MAX_IP_ADDR_LEN = 16;
const UINT GCFOS_COMPUTER_NAME_LENGTH = (MAX_COMPUTERNAME_LENGTH+1);

