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

#define GCFOS_BLOCK_MAXIMUM_FILESIZE 0x10000000 // 256MB

const UINT32 GCFOS_BLOCKSTORE_FILES_PER_DIR = 10000;
// these defines are for the LOCAL naming conventions (on-disk)
#define GCFOS_BLOCKS_DIR_NAMING_FMT _T("%s\\%06u")
#define GCFOS_BLOCKS_FILE_NAMING_FMT _T("%s\\%06u\\%04u")
// these defines are for the REMOTE naming conventions (on-cloud)
#define GCFOS_BLOCKS_OBJECT_NAMING_FMT _T("%06u/%04u")
#define GCFOS_BLOCKS_OBJECT_DIR_NAMING_FMT _T("%06u/")


bool OpenCurrentBlocksFile();
bool RetrieveBlockFileFromSecondary(LPCSTR pszSource, UINT32 fileno);
void SendQueryBlocksResponseToClient(PGCFOS_CONNECT_STATE context, PGCFOS_RESPONSE_QUERY_BLOCKS response);
void ProcessQueryBlocks(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessRestoreBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
void ProcessStoreBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);
int SaveBlock(LPBYTE inbuffer, UINT16 size, LPBYTE hash, gcfosdbTxn *txn);
//void ProcessQueryBlockchain(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen);

