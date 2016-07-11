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
#include <stdafx.h>

#include "Project.h"

bool OpenCurrentBlocksFile()
	{
	TCHAR					szBlksFilename[MAX_PATH];
	TCHAR					szDirName[MAX_PATH];
	DWORD					dwFileSize;

	if(!g_bDedupeBlocks)
		return false; // block store not configured

	if(g_blks_hFile != INVALID_HANDLE_VALUE)
		{
		CloseHandle(g_blks_hFile);
		g_blks_hFile = INVALID_HANDLE_VALUE;
		}

	_stprintf_s(szBlksFilename, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, g_blks_fileID / GCFOS_BLOCKSTORE_FILES_PER_DIR, g_blks_fileID % GCFOS_BLOCKSTORE_FILES_PER_DIR);

	g_blks_hFile = CreateFile(szBlksFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
	if(g_blks_hFile == INVALID_HANDLE_VALUE)
		{
		if(GetLastError() == ERROR_PATH_NOT_FOUND)
			{
			_stprintf_s(szDirName, MAX_PATH, GCFOS_BLOCKS_DIR_NAMING_FMT, g_BlocksDir, g_blks_fileID / GCFOS_BLOCKSTORE_FILES_PER_DIR);
			if(!CreateDirectory(szDirName, NULL))
				{
				DEBUGLOG_L(1, ("OpenCurrentBlocksFile: Failed creating directory %s, %u\n", CStringA(szDirName), GetLastError()));
				return false;
				}
			g_blks_hFile = CreateFile(szBlksFilename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
			}

		if(g_blks_hFile == INVALID_HANDLE_VALUE)
			{
			DEBUGLOG_L(1, ("OpenCurrentBlocksFile: Failed creating file %s, %u\n", CStringA(szBlksFilename), GetLastError()));
			return false;
			}
		}

	// always append at end of file and adjust our offset accordingly

	dwFileSize = GetFileSize(g_blks_hFile, NULL);
	if(dwFileSize > g_blks_out_offset)
		{
		DEBUGLOG_L(2, ("OpenCurrentBlocksFile: File %S is bigger than expected, adjusting our offset to match, %u\n", szBlksFilename));
		g_blks_out_offset = dwFileSize;
		}
	if(INVALID_SET_FILE_POINTER == SetFilePointer(g_blks_hFile, g_blks_out_offset, NULL, FILE_BEGIN))
		{
		DEBUGLOG_L(1, ("OpenCurrentBlocksFile: Failed moving in file %S, %u\n", szBlksFilename, GetLastError()));
		return false;
		}

	return true;
	}

void SendQueryBlocksResponseToClient(PGCFOS_CONNECT_STATE context, PGCFOS_RESPONSE_QUERY_BLOCKS response)
	{
	DWORD				dwLen = sizeof(GCFOS_RESPONSE_QUERY_BLOCKS);

	context->buffer.len = dwLen;
	memcpy(context->buffer.buf, response, sizeof(GCFOS_RESPONSE_QUERY_BLOCKS));

	context->op = IOCP_OP_SENT_BLOCK_QUERY_RESPONSE;

	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: SendQueryBlocksResponseToClient failed to send result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

void ProcessQueryBlocks(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	gcfosdbTxn					*txn;
	int							rc;
	PGCFOS_REQUEST_QUERY_BLOCKS	req = (PGCFOS_REQUEST_QUERY_BLOCKS) context->buffer.buf;
	GCFOS_RESPONSE_QUERY_BLOCKS QueryBlockResp;
	Ipp8u						Sentinel[GCFOS_BLOCK_HASH_LEN];
	int							i;
	Ipp8u						*p;
	GCFOS_BLOCK_ENTRY			blockEntry;
	int							ctxsize;
	Ipp8u						*HashStore;
	GCFOS_UsefulTime			timenow;

	memset(&Sentinel, 0, GCFOS_BLOCK_HASH_LEN);
	memset(&QueryBlockResp, 0, sizeof(GCFOS_RESPONSE_QUERY_BLOCKS));

	if(context->client == 0)
		{
		QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_NOTAUTH;
		SendQueryBlocksResponseToClient(context, &QueryBlockResp);
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("%s: ProcessQueryBlocks received from unauthorized client\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

	if(!g_bDedupeBlocks)
		{
		QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_NOT_CONFIGURED;
		SendQueryBlocksResponseToClient(context, &QueryBlockResp);
		return;// block store not configured
		}

	context->iBlocksExpected = 0;

	// create a READ_ONLY cursor (no writes allowed) unless blocks purging is enabled
	rc = gcfosdb::BeginTxn(NULL, &txn, (g_bEnableBlocksPurging ? 0 : gcfosdb_RDONLY));
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("%s: ProcessQueryBlocks failed to create txn: %d\n", context->connectedToHost, rc));
		QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_ERROR;
		SendQueryBlocksResponseToClient(context, &QueryBlockResp);
		return;
		}

	p = req->hashes;
	HashStore = context->BlockHashes;
	for(i = 0; i < GCFOS_BLOCKS_PER_QUERY; i++)
		{
		if(memcmp(p, Sentinel, GCFOS_BLOCK_HASH_LEN) == 0)
			break; // no more blocks, sentinel reached
		context->count_blks_queried++;
		memcpy(blockEntry.hash, p, GCFOS_BLOCK_HASH_LEN);
		if(g_Blocks->find(&blockEntry, txn) == 0)
			{
			QueryBlockResp.present[i] = TRUE;
			if(g_bEnableBlocksPurging)
				{
				if(timenow.AsDays() - blockEntry.last_ref > 7)
					{
					blockEntry.last_ref = timenow.AsDays();
					rc = g_Blocks->insert(&blockEntry, txn, 0);
					if(rc != 0)
						{
						DEBUGLOG_L(3, ("%s: ProcessQueryBlocks failed insert to update last ref: %d\n", context->connectedToHost, rc));
						}
					}
				}
			}
		else
			{
			context->iBlocksExpected++;
			memcpy(HashStore, p, GCFOS_BLOCK_HASH_LEN);
			HashStore += GCFOS_BLOCK_HASH_LEN;
			}
		p += GCFOS_BLOCK_HASH_LEN;
		}

	rc = gcfosdb::CommitTxn(txn);
	if(rc != 0)
		{
		DEBUGLOG_L(3, ("%s: ProcessQueryBlocks failed to commit txn: %d\n", context->connectedToHost, rc));
		}

	QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_OK;

	if(context->iBlocksExpected > 0)
		{
		if(context->ContextForCalculatedHash == NULL)
			{
			ippsHashGetSize(&ctxsize);
			context->ContextForCalculatedHash = (IppsHashState*)( new Ipp8u [ctxsize]);
			}
		
		if(context->inputBuffer)
			{
			VirtualFree(context->inputBuffer, 0, MEM_RELEASE);
			context->inputBuffer = NULL;
			}
		if(context->decompressedBuffer)
			{
			VirtualFree(context->decompressedBuffer, 0, MEM_RELEASE);
			context->decompressedBuffer = NULL;
			}

		context->inputBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE * GCFOS_BLOCKS_PER_QUERY, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(context->inputBuffer == NULL)
			{
			DEBUGLOG_L(1, ("%s: ProcessQueryBlocks failed to allocate buffer %u\n", context->connectedToHost, GetLastError()));
			QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_ERROR;
			SendQueryBlocksResponseToClient(context, &QueryBlockResp);
			return;
			}
		context->decompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE_DECOMP, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(context->decompressedBuffer == NULL)
			{
			DEBUGLOG_L(1, ("%s: ProcessQueryBlocks failed to allocate decomp buffer %u\n", context->connectedToHost, GetLastError()));
			QueryBlockResp.SrvResponse = GCFOS_SRV_RESP_ERROR;
			SendQueryBlocksResponseToClient(context, &QueryBlockResp);
			return;
			}
		context->remaining = sizeof(UINT16);
		context->bHdr = true;
		context->outputOffset = 0;
		context->CurBlock = 0;
		context->offset = 0;
		memset(&context->BlockSizes, 0, sizeof(context->BlockSizes));
		}

	SendQueryBlocksResponseToClient(context, &QueryBlockResp);
	return;
	}

void SendRetrieveBlocksResponseToClient(PGCFOS_CONNECT_STATE context, PGCFOS_RESPONSE_RETRIEVE_BLOCKS RetrieveBlockResp)
	{
	DWORD				dwLen = sizeof(GCFOS_RESPONSE_RETRIEVE_BLOCKS);
	UINT16				i;

	// note: context->buffer.buf already points to GCFOS_RESPONSE_RETRIEVE_BLOCKS
	context->buffer.len = dwLen;

	context->op = IOCP_OP_SENT_RETRIEVE_BLOCK_RESPONSE;
	if(RetrieveBlockResp->SrvResponse == GCFOS_SRV_RESP_OK)
		{
		for(i = 0; i < GCFOS_BLOCKS_PER_QUERY; i++)
			{
			dwLen += RetrieveBlockResp->Sizes[i];
			}
		}

	DEBUGLOG_L(5, ("%s: SendRetrieveBlocksResponseToClient sending %u bytes\n", context->connectedToHost, dwLen));
	context->remaining = dwLen;
	context->outputOffset = 0;
	context->buffer.len = dwLen;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: SendRetrieveBlocksResponseToClient failed to send result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

bool RetrieveBlockFileFromSecondary(LPCSTR pszSource, UINT32 fileno)
	{
	TCHAR									szObjPath[MAX_PATH];
	TCHAR									szBlksFilename[MAX_PATH];
	DWORD									dwRead;
	System::IO::FileStream					^fs;
	System::IO::Stream						^secondarystream;

	if(g_Repo2 && !System::Object::ReferenceEquals(g_SecondaryBlockStoreLocation, nullptr))
		{
		_stprintf_s(szObjPath, CHARCOUNT(szObjPath), GCFOS_BLOCKS_DIR_NAMING_FMT, g_BlocksDir, fileno / GCFOS_BLOCKSTORE_FILES_PER_DIR);
		CreateDirectory(szObjPath, NULL); // make sure directory exists first
				
		_stprintf_s(szObjPath, CHARCOUNT(szObjPath), GCFOS_BLOCKS_OBJECT_NAMING_FMT, fileno / GCFOS_BLOCKSTORE_FILES_PER_DIR, fileno % GCFOS_BLOCKSTORE_FILES_PER_DIR);
		DEBUGLOG_L(2, ("%s: Retrieving %S from secondary\n", pszSource, szObjPath));
		fs = gcnew System::IO::FileStream(gcnew System::String(szBlksFilename), System::IO::FileMode::Create, System::IO::FileAccess::Write, System::IO::FileShare::None);
		if(!g_Repo2->GetObject(gcnew System::String(szObjPath), secondarystream, NULL, true, g_SecondaryBlockStoreLocation))
			{
			DEBUGLOG_L(2, ("%s: RetrieveSingleBlock failed to get %S from secondary\n", pszSource, szObjPath));
			return false;
			}
		array<System::Byte> ^tmpbuf = gcnew array<System::Byte>(0x8000);
		dwRead = 1;
		while(dwRead > 0)
			{
			dwRead = secondarystream->Read(tmpbuf, 0, 0x8000);
			fs->Write(tmpbuf, 0, dwRead);
			}
		DEBUGLOG_L(2, ("%s: RetrieveSingleBlock retrieved %u bytes from secondary\n", pszSource, fs->Length));
		fs->Close();
		secondarystream->Close();
		return true;
		}

	return false;
	}

bool RetrieveSingleBlock(PGCFOS_CONNECT_STATE context, PGCFOS_BLOCK_ENTRY BlockEntry, LPBYTE p, PUINT16 size)
	{
	HANDLE									hFile;
	TCHAR									szBlksFilename[MAX_PATH];
	DWORD									dwRead;

	_stprintf_s(szBlksFilename, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, BlockEntry->fileno / GCFOS_BLOCKSTORE_FILES_PER_DIR, BlockEntry->fileno % GCFOS_BLOCKSTORE_FILES_PER_DIR);
	hFile = CreateFile(szBlksFilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		// could not open the needed block-store file from the primary location, go to the secondary location and 
		// see if we can copy it to the primary
		if(RetrieveBlockFileFromSecondary(context->connectedToHost, BlockEntry->fileno))
			{
			hFile = CreateFile(szBlksFilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
			}
		}
	if(hFile == INVALID_HANDLE_VALUE)
		{
		DEBUGLOG_L(2, ("%s: RetrieveSingleBlock failed to open %S, %u\n", context->connectedToHost, szBlksFilename, GetLastError()));
		return false;
		}
	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, BlockEntry->offset, NULL, FILE_BEGIN))
		{
		DEBUGLOG_L(2, ("%s: RetrieveSingleBlock failed to move file pointer, %u\n", context->connectedToHost, GetLastError()));
		CloseHandle(hFile);
		return false;
		}
	if(!ReadFile(hFile, size, sizeof(UINT16), &dwRead, NULL) || dwRead != sizeof(UINT16))
		{
		DEBUGLOG_L(2, ("%s: RetrieveSingleBlock failed to read size, %u (%x/%S)\n", context->connectedToHost, GetLastError(), BlockEntry->offset, szBlksFilename));
		CloseHandle(hFile);
		return false;
		}
	if(!ReadFile(hFile, p, *size, &dwRead, NULL) || dwRead != *size)
		{
		DEBUGLOG_L(2, ("%s: RetrieveSingleBlock failed to read data(%u), %u (%x/%S)\n", context->connectedToHost, *size, GetLastError(), BlockEntry->offset, szBlksFilename));
		CloseHandle(hFile);
		return false;
		}
	CloseHandle(hFile);
	return true;
	}

void ProcessRestoreBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	GCFOS_REQUEST_RETRIEVE_BLOCKS	Req;
	PGCFOS_RESPONSE_RETRIEVE_BLOCKS RetrieveBlockResp = (PGCFOS_RESPONSE_RETRIEVE_BLOCKS)context->buffer.buf;
	Ipp8u							Sentinel[GCFOS_BLOCK_HASH_LEN];
	UINT32							i;
	GCFOS_BLOCK_ENTRY				BlockEntry;
	gcfosdbTxn						*txn;
	int								rc;
	LPBYTE							p;
	GCFOS_UsefulTime				timenow;

	if(dwLen != sizeof(GCFOS_REQUEST_RETRIEVE_BLOCKS))
		{
		BanIP(context);
		DEBUGLOG_L(2, ("%s: ProcessRestoreBlock received invalid length (%u)\n", context->connectedToHost, dwLen));
		CloseConnection(context);
		return;// block store not configured
		}

	if(context->client == 0)
		{
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("%s: ProcessRestoreBlock received from unauthorized client\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

	memcpy(&Req, context->buffer.buf, sizeof(GCFOS_REQUEST_RETRIEVE_BLOCKS));
	memset(&RetrieveBlockResp->Sizes, 0, sizeof(RetrieveBlockResp->Sizes));
	memset(Sentinel, 0, GCFOS_BLOCK_HASH_LEN);
	if(!g_bDedupeBlocks)
		{
		DEBUGLOG_L(2, ("%s: ProcessRestoreBlock received when not configured\n", context->connectedToHost));
		RetrieveBlockResp->SrvResponse = GCFOS_SRV_RESP_NOT_CONFIGURED;
		SendRetrieveBlocksResponseToClient(context, RetrieveBlockResp);
		return;// block store not configured
		}
	
	rc = gcfosdb::BeginTxn(NULL, &txn, (g_bEnableBlocksPurging ? 0 : gcfosdb_RDONLY));
	if(rc != 0)
		{
		DEBUGLOG_L(2, ("%s: ProcessRestoreBlock unable to begin txn %d\n", context->connectedToHost, rc));
		RetrieveBlockResp->SrvResponse = GCFOS_SRV_RESP_ERROR;
		SendRetrieveBlocksResponseToClient(context, RetrieveBlockResp);
		return;// block store not configured
		}

	RetrieveBlockResp->SrvResponse = GCFOS_SRV_RESP_OK;
	p = (LPBYTE)context->buffer.buf + sizeof(GCFOS_RESPONSE_RETRIEVE_BLOCKS);
	for(i = 0; i < GCFOS_BLOCKS_PER_QUERY; i++)
		{
		if(memcmp(&Req.hashes[i * GCFOS_BLOCK_HASH_LEN], Sentinel, GCFOS_BLOCK_HASH_LEN) == 0)
			break;
		memcpy(BlockEntry.hash, Req.hashes + (i * GCFOS_BLOCK_HASH_LEN), GCFOS_BLOCK_HASH_LEN);
		rc = g_Blocks->find(&BlockEntry, txn);
		if(rc != 0)
			{
			RetrieveBlockResp->SrvResponse = GCFOS_SRV_RESP_ERROR;
			DEBUGLOG_L(4, ("%s: ProcessRestoreBlock record not found %d\n", context->connectedToHost, rc));
			break;
			}
		if(!RetrieveSingleBlock(context, &BlockEntry, p, &RetrieveBlockResp->Sizes[i]))
			{
			DEBUGLOG_L(4, ("%s: ProcessRestoreBlock retrieve failed\n", context->connectedToHost));
			RetrieveBlockResp->SrvResponse = GCFOS_SRV_RESP_ERROR;
			break;
			}
		if(g_bEnableBlocksPurging)
			{
			if(timenow.AsDays() - BlockEntry.last_ref > 7)
				{
				BlockEntry.last_ref = timenow.AsDays();
				rc = g_Blocks->insert(&BlockEntry, txn, 0);
				if(rc != 0)
					{
					DEBUGLOG_L(3, ("%s: ProcessRestoreBlock failed insert to update last ref: %d\n", context->connectedToHost, rc));
					}
				}
			}
		context->count_blks_retrieved++;
		p += RetrieveBlockResp->Sizes[i];
		}
	gcfosdb::CommitTxn(txn);
	if(RetrieveBlockResp->SrvResponse == GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG_L(5, ("%s: ProcessRestoreBlock sent %d blocks\n", context->connectedToHost, i));
		}
	else
		{
		DEBUGLOG_L(4, ("%s: ProcessRestoreBlock error %u\n", context->connectedToHost, RetrieveBlockResp->SrvResponse));
		}
	SendRetrieveBlocksResponseToClient(context, RetrieveBlockResp);
	return;
}

void ProcessStoreBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	LPBYTE						p = (LPBYTE)context->buffer.buf;
	UINT32						copybytes;
	IppStatus					iDecompressionStatus;
	UINT32						uncompsize;
	int							result;
	DWORD						dwFlags = 0;
	Ipp8u						ValidationHash[GCFOS_BLOCK_HASH_LEN];
	gcfosdbTxn					*txn;
	int							rc;
	int							i;
	DWORD						dwOffset;

	if(context->client == 0)
		{
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("%s: ProcessStoreBlock received from unauthorized client\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}


	while(dwLen)
		{
		if(context->bHdr)
			{
			if(dwLen < sizeof(UINT16))
				{
				// Only 1 byte received -- possibly a slow link, or packet was fragmented. The packet
				// should be reassembled ok, so this is only a warning.
				DEBUGLOG_L(5, ("%s: ProcessStoreBlock incomplete hdr received %u\n", context->connectedToHost, dwLen));
				}
			copybytes = dwLen;
			if(copybytes > context->remaining)
				copybytes = context->remaining;
			memcpy((LPBYTE)&context->BlockSizes[context->CurBlock] + context->offset, p, copybytes);
			dwLen -= copybytes;
			p += copybytes;
			context->remaining -= copybytes;
			context->offset += copybytes;
			if(context->remaining == 0)
				{
				context->bHdr = false;
				context->offset = context->outputOffset;
				context->remaining = context->BlockSizes[context->CurBlock];
				if(context->BlockSizes[context->CurBlock] > GCFOS_BLOCK_SIZE || context->BlockSizes[context->CurBlock] < 8)
					{
					DEBUGLOG_L(2, ("%s: ProcessStoreBlock invalid length received: %u\n", context->connectedToHost, context->BlockSizes[context->CurBlock]));
					CloseConnection(context);
					return;
					}
				if(context->BlockSizes[context->CurBlock] < GCFOS_MINIMUM_BLOCK_SIZE)
					{
					DEBUGLOG_L(5, ("%s: ProcessStoreBlock warning, small block: %u\n", context->connectedToHost, context->BlockSizes[context->CurBlock]));
					}
				}
			continue;
			}
		if(dwLen > context->remaining)
			copybytes = context->remaining;
		else
			copybytes = dwLen;
		memcpy(context->inputBuffer + context->outputOffset, p, copybytes);
		p += copybytes;
		dwLen -= copybytes;
		context->remaining -= copybytes;
		context->outputOffset += copybytes;
		if(context->remaining == 0)
			{
			ippsHashInit(context->ContextForCalculatedHash, IPP_ALG_HASH_SHA512_224);
			if(context->BlockSizes[context->CurBlock] != GCFOS_BLOCK_SIZE)
				{
				uncompsize = GCFOS_BLOCK_SIZE;
				iDecompressionStatus = ippsDecodeLZOSafe_8u(context->inputBuffer + context->offset, context->BlockSizes[context->CurBlock], context->decompressedBuffer, &uncompsize);
				if(iDecompressionStatus != ippStsNoErr || uncompsize != GCFOS_BLOCK_SIZE)
					{
					DEBUGLOG_L(2, ("%s: ProcessStoreBlock failed to decompress buffer %u\n", context->connectedToHost, context->CurBlock));
					CloseConnection(context);
					return;
					}
				ippsHashUpdate(context->decompressedBuffer, GCFOS_BLOCK_SIZE, context->ContextForCalculatedHash);
				}
			else
				{
				ippsHashUpdate(context->inputBuffer + context->offset, GCFOS_BLOCK_SIZE, context->ContextForCalculatedHash);
				}
			ippsHashFinal(ValidationHash, context->ContextForCalculatedHash);
			
			if(memcmp(ValidationHash, context->BlockHashes + (GCFOS_BLOCK_HASH_LEN * context->CurBlock), GCFOS_BLOCK_HASH_LEN) != 0)
				{
				DEBUGLOG_L(2, ("%s: ProcessStoreBlock received block %u that fails validation\n", context->connectedToHost, context->CurBlock));
				// currently no way to gracefully error this condition, so abort
				CloseConnection(context);
				return;
				}

			context->iBlocksExpected--;
			context->count_blks_stored++;
			context->CurBlock++;

			if(context->iBlocksExpected == 0)
				{
				VirtualFree(context->decompressedBuffer, 0, MEM_RELEASE);
				context->decompressedBuffer = NULL;
				delete[] (Ipp8u*)context->ContextForCalculatedHash;
				context->ContextForCalculatedHash = NULL;
				rc = gcfosdb::BeginTxn(NULL, &txn, 0);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("ProcessStoreBlock: Failed to get new txn %u\n", rc));
					CloseConnection(context);
					return;
					}

				while(true)
					{
					for(i = 0, dwOffset = 0; i < GCFOS_BLOCKS_PER_QUERY; i++)
						{
						if(context->BlockSizes[i] == 0)
							break;

						rc = SaveBlock(context->inputBuffer + dwOffset, (UINT16)context->BlockSizes[i], context->BlockHashes + (GCFOS_BLOCK_HASH_LEN * i), txn);
						if(rc == MDB_MAP_FULL)
							{
							gcfosdb::ResizeLMDB(&txn);
							break;
							}
						if(rc != 0)
							{
							DEBUGLOG_L(1, ("%s: ProcessStoreBlock SaveBlock failed, %d\n", context->connectedToHost, rc));
							// currently no way to gracefully error this condition, so abort
							gcfosdb::AbortTxn(txn);
							CloseConnection(context);
							return;
							}
						dwOffset += context->BlockSizes[i];
						}
					if(rc == 0)
						{
						rc = gcfosdb::CommitTxn(txn);
						if(rc == MDB_MAP_FULL)
							{
							gcfosdb::ResizeLMDB(&txn);
							continue; //restart
							}
						if(rc != 0)
							{
							DEBUGLOG_L(1, ("%s: ProcessStoreBlock commit failed, %d\n", context->connectedToHost, rc));
							// currently no way to gracefully error this condition, so abort
							gcfosdb::AbortTxn(txn);
							CloseConnection(context);
							return;
							}
						break; // we completed successfully
						}
					}
				VirtualFree(context->inputBuffer, 0, MEM_RELEASE);
				context->inputBuffer = NULL;
				SendSimpleResponseToClient(context, i, key, GCFOS_SRV_RESP_OK);
				return; // all done
				}
			context->bHdr = true;
			context->remaining = sizeof(UINT16);
			context->offset = 0;
			}
		}






	// this buffer all processed -- request more
	context->buffer.len = context->remaining;
	result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
	if(result == SOCKET_ERROR)
		{
		if(ERROR_IO_PENDING != WSAGetLastError())
			{
			DEBUGLOG_L(1, ("%s: ProcessStoreBlock WSARecv error: %d\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

int SaveBlock(LPBYTE inbuffer, UINT16 size, LPBYTE hash, gcfosdbTxn *txn)
	{
	int								rc;
	GCFOS_BLOCK_ENTRY				blockEntry;
	DWORD							dwLen;
	bool							retry = true;
	GCFOS_UsefulTime				timenow;

	memcpy(&blockEntry.hash, hash, GCFOS_BLOCK_HASH_LEN);
	blockEntry.fileno = g_blks_fileID;
	blockEntry.offset = g_blks_out_offset;
	blockEntry.last_ref = timenow.AsDays();
	rc = g_Blocks->insert(&blockEntry, txn, 0, gcfosdb_NOOVERWRITE);
	if(rc != 0)
		{
		if(rc == gcfosdb_KEYEXIST)
			{
			DEBUGLOG_L(5, ("SaveBlock: discarding duplicate block\n"));
			return 0; // not an error
			}
		DEBUGLOG_L(1, ("SaveBlock: error on initial insert %d\n", rc));
		return rc;
		}

	EnterCriticalSection(&g_csBlksFile);
	if(!WriteFile(g_blks_hFile, &size, sizeof(UINT16), &dwLen, NULL) || dwLen != sizeof(UINT16))
		{
		DEBUGLOG_L(1, ("SaveBlock: Write of size failed %u:%u\n", dwLen, GetLastError()));
		LeaveCriticalSection(&g_csBlksFile);
		return -1;
		}

	if(!WriteFile(g_blks_hFile, inbuffer, size, &dwLen, NULL) || dwLen != size)
		{
		DEBUGLOG_L(1, ("SaveBlock: Write of buffer failed %u:%u\n", dwLen, GetLastError()));
		LeaveCriticalSection(&g_csBlksFile);
		return -1;
		}

	g_blks_out_offset += (sizeof(UINT16) + size);
	if(g_blks_out_offset > (GCFOS_BLOCK_MAXIMUM_FILESIZE - 0x1002))
		{
		g_blks_out_offset = 0;
		g_blks_fileID++;
		if(!OpenCurrentBlocksFile()) // this closes existing file's handle
			{
			DEBUGLOG_L(1, ("SaveBlock: Failed to open next file\n"));
			LeaveCriticalSection(&g_csBlksFile);
			return -1;
			}
		}

	memset(&blockEntry.hash, 0, GCFOS_BLOCK_HASH_LEN);
	blockEntry.fileno = g_blks_fileID;
	blockEntry.offset = g_blks_out_offset;
	blockEntry.last_ref = 0; // not used on the locator-record
	LeaveCriticalSection(&g_csBlksFile);

	rc = g_Blocks->insert(&blockEntry, txn, 0); // this will always be overwrite
	if(rc != 0)
		{
		DEBUGLOG_L(4, ("SaveBlock: error on update offset %d\n", rc));
		return rc;
		}
	return 0;
	}

void ProcessInformActiveHashes(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_INFORM_ACTIVE_HASHES		Request = (PGCFOS_REQUEST_INFORM_ACTIVE_HASHES)context->buffer.buf;
	LPBYTE									NextRequest = NULL;
	WSABUF									TempBuffer;
	DWORD									dwFlags = 0;
	GCFOS_BLOCK_ENTRY						blockEntry;
	int										rc;
	gcfosdbTxn								*txn;
	UINT16									i;
	UINT32									totalread = 0, updated = 0, notfound = 0;
	GCFOS_UsefulTime						timenow;

	// Because this command is quite large, it might be received in chunks
	// because no ACK is expected by client, the buffer actually might contain multiple requests

	while(dwLen > 0)
		{
		if(dwLen + context->offset < sizeof(GCFOS_REQUEST_INFORM_ACTIVE_HASHES))
			{
			if(Request != (PGCFOS_REQUEST_INFORM_ACTIVE_HASHES)context->buffer.buf)
				{
				memcpy(context->buffer.buf, Request, dwLen);
				Request = (PGCFOS_REQUEST_INFORM_ACTIVE_HASHES)context->buffer.buf;
				}
			context->offset += dwLen;
			TempBuffer.buf = context->buffer.buf + context->offset;
			// request exactly what remains of the command
			context->remaining = sizeof(GCFOS_REQUEST_INFORM_ACTIVE_HASHES) - context->offset;
			TempBuffer.len = context->remaining;
			context->op = IOCP_OP_RECEIVING_INCOMPLETE_COMMAND;
			if(WSARecv(context->s_acc, &TempBuffer, 1, &dwLen, &dwFlags, &context->o, NULL) == SOCKET_ERROR)
				{
				if(WSAGetLastError() != ERROR_IO_PENDING)
					{
					DEBUGLOG(("%s: ProcessInformActiveHashes failed to request additional data from client (%u)\n", context->connectedToHost, WSAGetLastError()));
					CloseConnection(context);
					return;
					}
				}
			return;
			}
		
		dwLen += context->offset;

		// we now have a complete commmand

		if(Request->type != GCFOS_REQ_INFORM_ACTIVE_HASHES
		|| Request->count > GCFOS_INFORM_ACTIVE_HASHES_COUNT)
			{
			DEBUGLOG(("%s: ProcessInformActiveHashes - invalid header recd, abandoning update\n", context->connectedToHost));
			DEBUGLOG_L(4, ("%s: ProcessInformActiveHashes Read: %u Updated: %u Not-found: %u\n", context->connectedToHost, totalread, updated, notfound));
			RequestCommand(context);
			return;
			}

		rc = gcfosdb::BeginTxn(NULL, &txn, 0);
		if(rc == 0)
			{
			for(i = 0; i < Request->count; i++)
				{
				memcpy(&blockEntry.hash, &Request->hashes[i * GCFOS_BLOCK_HASH_LEN], GCFOS_BLOCK_HASH_LEN);
				if(g_Blocks->find(&blockEntry, txn) == 0)
					{
					totalread++;
					if(timenow.AsDays() - blockEntry.last_ref > 2)
						{
						blockEntry.last_ref = timenow.AsDays();
						rc = g_Blocks->insert(&blockEntry, txn);
						if(rc == 0)
							{
							updated++;
							}
						}
					}
				else
					{
					notfound++;
					}
				}
			rc = gcfosdb::CommitTxn(txn);
			if(rc != 0)
				{
				DEBUGLOG_L(2, ("%s: ProcessInformActiveHashes failed to commit txn %d\n", context->connectedToHost, rc));
				}
			}
		else
			{
			DEBUGLOG_L(2, ("%s: ProcessInformActiveHashes failed to begin txn %d\n", context->connectedToHost, rc));
			}

		Request++;

		dwLen -= sizeof(GCFOS_REQUEST_INFORM_ACTIVE_HASHES);
		}

	DEBUGLOG_L(5, ("%s: ProcessInformActiveHashes Read: %u Updated: %u Not-found: %u\n", context->connectedToHost, totalread, updated, notfound));

	// No ACK is sent for this command, just a request for another command
	RequestCommand(context);
	return;
	}

UINT32 GetHashDataLengthForFileSize(INT64 filesize)
	{
	UINT32			SizeOfHashes;

	SizeOfHashes = (UINT32)(filesize / (UINT64)GCFOS_BLOCK_SIZE) * GCFOS_BLOCK_HASH_LEN;
	if(filesize % GCFOS_BLOCK_SIZE > 0)
		{
		if(filesize % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			SizeOfHashes += (filesize % GCFOS_BLOCK_SIZE);
			}
		else
			{
			SizeOfHashes += GCFOS_BLOCK_HASH_LEN;
			}
		}
	return SizeOfHashes;
	}


