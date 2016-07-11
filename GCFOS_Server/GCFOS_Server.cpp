/*
GCFOS_Server.cpp : Defines the entry point for the console application.

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

#define unmanaged

#define _GCFOS_SERVER

#include "Project.h"
#include "Handling.h"
#include "tlhelp32.h"

unsigned __stdcall MaintenanceWorker(void * param)
{
// This thread will take care of background cleanup-type tasks (every 30 secs):
//   1. Process the list of banned IPs and remove any too old
//   2. Perform a db checkpoint
//   3. Close zombie connections
//   4. Process the limbo lists when required (on entry, and then after a period of time)

#ifdef ULTRABAC_CLOUD_USE
	gcfosdbTxn						*txn;
	GCFOS_BANNED_ENTRY				bannedEntry;
	int								erased;
	gcfosdbCursor					*c_banned;
#endif//ULTRABAC_CLOUD_USE
	GCFOS_UsefulTime				timenow;
	int								i;
	PGCFOS_CONNECT_STATE			context;
	int								rc;
	SYSTEMTIME						st_last_log_print;
	GCFOS_UsefulTime				ut_last_limbo_process;
	SYSTEMTIME						st_now;
	const UINT32					GCFOS_PROCESS_LIMBO_PERIOD_SECS = (60 * 60 * 24 * 3); // every 3 days

	st_last_log_print.wHour = 0; // force log print upon entry

	while(true)
		{
		// this iterator must be this local scope because otherwise it can cause a crash 
		btree::btree_set<PVOID>::iterator connection;

		if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
			{
			break;
			}
		timenow.ObtainTimeNow();
		GetLocalTime(&st_now);
		if(st_now.wHour != st_last_log_print.wHour)
			{
			DumpSessionsToLogFiles();
			st_last_log_print = st_now;
			}
		if(timenow.Diff(ut_last_limbo_process) > GCFOS_PROCESS_LIMBO_PERIOD_SECS)
			{
			ut_last_limbo_process.ObtainTimeNow();
			ProcessLimboEntries();
			}

#ifdef ULTRABAC_CLOUD_USE
		if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
			{
			DEBUGLOG_L(1, ("MaintenanceWorker: failed to begin txn\n"));
			Sleep(1000);
			continue;
			}

		if(g_BannedIPs->createCursor(&c_banned, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) != 0)
			{
			gcfosdb::AbortTxn(txn);
			DEBUGLOG_L(1, ("MaintenanceWorker: failed to get limbo cursor\n"));
			Sleep(1000);
			continue;
			}

		erased = 0;
		while(true)
			{
			rc = g_BannedIPs->get(c_banned, &bannedEntry, gcfosdb_NEXT | gcfosdb_READ_UNCOMMITTED, txn);
			if(rc != 0)
				{
				if(rc == gcfosdb_LOCK_DEADLOCK)
					{
					DEBUGLOG_L(1, ("MaintenanceWorker: deadlock occurred\n"));
					Sleep(1000);
					continue;
					}
				break;
				}
			if(timenow.Diff(bannedEntry.time_banned) > 60) //more than a minute old?
				{
				// yes, delete it now
				g_BannedIPs->erase(c_banned);
				erased++;
				}
			}
		gcfosdb::CommitTxn(txn);
		if(erased)
			{
			DEBUGLOG_L(3, ("Removed %u entries from banned-IP list\n", erased));
			}
#endif//ULTRABAC_CLOUD_USE

		// Wait for GCFOS_MAINTENANCE_PERIOD secs (or if an exit has been signalled)
		for(i = 0; i < GCFOS_MAINTENANCE_PERIOD; i++)
			{
			if(WaitForSingleObject(g_ExitSignalled, 1000) == WAIT_OBJECT_0)
				{
				break;
				}
			timenow.ObtainTimeNow();
			if(gcfosdb::HasDbChanged() && timenow.Diff(gcfosdb::LastChangeTime) > 3)
				{
				DEBUGLOG_L(5, ("Checkpointing DB\n"));
				rc = gcfosdb::Checkpoint();
				if(rc != 0)
					{
					DEBUGLOG_L(2, ("Checkpointing error: %d\n", rc));
					}
				}
			}

		EnterCriticalSection(&g_csConnections);
		for(connection = g_ConnectState.begin(); connection != g_ConnectState.end(); connection++)
			{
			context = (PGCFOS_CONNECT_STATE)*connection;
			if(context->status == STATE_CONNECTED)
				{
				if(context->activityTimer == 0)
					{
					DEBUGLOG_L(4, ("(%p) Terminating inactive session: %s\n", context, context->connectedToHost));
					UpdateSessionRecord(context, GCFOS_SESSION_END_REASON::TIMEOUT);
					context->session_record = 0;
					if(context->s_acc != INVALID_SOCKET)
						{
						// This will normally cause GetQueuedCompletionStatus to hit with an error and close connection
						// will then be called. If after another inactivity period has elapsed, the connection will
						// be closed by being aborted
						closesocket(context->s_acc);
						context->s_acc = INVALID_SOCKET;
						}
					else
						{
						DEBUGLOG_L(4, ("(%p) Aborting inactive session: %s\n", context, context->connectedToHost));
						CloseConnection(context);
						}
					continue;
					}
				context->activityTimer--;
				}
			}
		LeaveCriticalSection(&g_csConnections);
		}

	InterlockedDecrement(&g_ThreadsActive);
	_endthreadex(0);
	return 0;
}

void ProcessAllUpdates()
	{
	GCFOS_UPDATE_ENTRY		updateEntry;
	int						rc;
	gcfosdbTxn				*txn;
	gcfosdbCursor			*cursor;

	while(true)
		{
		rc = gcfosdb::BeginTxn(NULL, &txn, 0);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: failed to get txn %d\n", rc));
			return;
			}
		rc = g_Update->createCursor(&cursor, 0, txn);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: failed to get txn %d\n", rc));
			gcfosdb::AbortTxn(txn);
			return;
			}
		rc = g_Update->get(cursor, &updateEntry, gcfosdb_FIRST, txn);
		if(rc == gcfosdb_NOTFOUND)
			{
			// end of updates available
			g_Update->closeCursor(cursor);
			gcfosdb::AbortTxn(txn);
			return;
			}
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: get on update cursor failed %d\n", rc));
			g_Update->closeCursor(cursor);
			gcfosdb::AbortTxn(txn);
			break;
			}
		rc = ProcessUpdate(&updateEntry, txn, NULL);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: ProcessUpdated failed %d\n", rc));
			g_Update->closeCursor(cursor);
			gcfosdb::AbortTxn(txn);
			break;
			}
		rc = g_Update->erase(cursor);
		g_Update->closeCursor(cursor);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: erase on update cursor failed %d\n", rc));
			gcfosdb::AbortTxn(txn);
			break;
			}
		rc = gcfosdb::CommitTxn(txn);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateWorker: unable to commit txn %d\n", rc));
			break;
			}
		}

	return;
	}


unsigned __stdcall UpdateWorker(void * param)
{
	while(true)
		{
		if(WaitForSingleObject(g_Update->hNewRecordAvailable, 1000) == WAIT_OBJECT_0)
			{
			ProcessAllUpdates();
			}
		if(g_bIsService)
			{
			EnterCriticalSection(&g_csDebug);
			fflush(g_DebugLog);
			LeaveCriticalSection(&g_csDebug);
			}
		if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
			break;
		}

	InterlockedDecrement(&g_ThreadsActive);
	_endthreadex(0);
	return 0;
}

#ifndef ULTRABAC_CLOUD_USE

void ProcessBroadcastSentResponse(PGCFOS_LISTEN_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	DWORD			dwFlags = 0;
	int				retry;

	context->buffer.len = GCFOS_MAX_DATAGRAM_SIZE;
	context->op = IOCP_OP_AWAITING_BROADCAST;

	for(retry = 0; retry < 10; retry++)
		{
		if(SOCKET_ERROR == WSARecvFrom(context->s_list, &context->buffer, 1, NULL, &dwFlags,
			&context->connectedTo, &context->connectedToLen, &context->o, NULL))
			{
			if(WSAGetLastError() != WSA_IO_PENDING)
				{
				DEBUGLOG_L(2, ("ProcessAutoConfig WSARecvFrom error %d\n", WSAGetLastError()));
				Sleep(500);
				continue;
				}
			break;
			}
		break;
		}
	return;
	}

void ProcessAutoConfig(PGCFOS_LISTEN_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	DWORD			dwFlags = 0;
	TCHAR			szIPAddress[24];
	DWORD			szIPAddressLen = CHARCOUNT(szIPAddress);
	WCHAR			wszComputerName[GCFOS_COMPUTER_NAME_LENGTH];
	DWORD			dwCompLen;
	CHAR			saveport[2];

	PGCFOS_REQUEST_CONFIG request = (PGCFOS_REQUEST_CONFIG)context->buffer.buf;
	PGCFOS_CONFIG_RESPONSE response = (PGCFOS_CONFIG_RESPONSE)context->buffer.buf;
	PGCFOS_CONFIG_RESPONSE_2 response2 = (PGCFOS_CONFIG_RESPONSE_2)context->buffer.buf;

	if(dwLen < sizeof(GCFOS_REQUEST_CONFIG)
	|| request->type != GCFOS_REQ_CONFIG)
		{
		// this is an invalid message, ignore it and request another command
		ProcessBroadcastSentResponse(context, tid, key, dwLen);
		return;
		}

	memset(&wszComputerName, 0, sizeof(wszComputerName));
	_tcsncpy(wszComputerName, request->wszComputerName, GCFOS_COMPUTER_NAME_LENGTH);

	// Remove the port number from "ConnectedTo" so that it is not included in the address returned
	saveport[0] = context->connectedTo.sa_data[0];
	saveport[1] = context->connectedTo.sa_data[1];
	context->connectedTo.sa_data[0] = 0;
	context->connectedTo.sa_data[1] = 0;
	if(SOCKET_ERROR == WSAAddressToString(&context->connectedTo, context->connectedToLen, NULL, szIPAddress, &szIPAddressLen))
		{
		_tcscpy_s(szIPAddress, _T("<unknown>"));
		}

	context->connectedTo.sa_data[0] = saveport[0];
	context->connectedTo.sa_data[1] = saveport[1];
	DEBUGLOG_L(4, ("AutoConfig request from %s:%s\n", CStringA(szIPAddress), CStringA(request->wszComputerName)));
	
	if(g_bRedirectionMode)
		{
		memset(response2, 0, sizeof(GCFOS_CONFIG_RESPONSE_2));
		response2->Size = sizeof(GCFOS_CONFIG_RESPONSE_2);
		response2->ClientID = g_RedirectionClientID;
		memcpy(response2->Secret, g_RedirectionSecret, GCFOS_SHARED_KEY_LEN);
		_tcsncpy(response2->wszServerIP, g_RedirectionServer, CHARCOUNT(response2->wszServerIP));
		context->buffer.len = response2->Size;
		context->op = IOCP_OP_BROADCAST_SENT_RESPONSE;
		if(SOCKET_ERROR == WSASendTo(context->s_list, &context->buffer, 1, NULL, 0,
			&context->connectedTo, context->connectedToLen, &context->o, NULL))
			{
			if(WSAGetLastError() != WSA_IO_PENDING)
				{
				DEBUGLOG_L(2, ("ProcessAutoConfig WSASendTo error %d\n", WSAGetLastError()));
				ProcessBroadcastSentResponse(context, tid, key, dwLen);
				return;
				}
			}
		return;
		}

	memset(response, 0, sizeof(GCFOS_CONFIG_RESPONSE));

	dwCompLen = MAX_COMPUTERNAME_LENGTH+1;
	GetComputerNameW(response->wszComputerName, &dwCompLen);
	_tcsncpy(response->wszServerIP, CString(context->hostid), sizeof(response->wszServerIP));
	response->Size = sizeof(GCFOS_CONFIG_RESPONSE);
	context->op = IOCP_OP_BROADCAST_SENT_RESPONSE;
	context->buffer.len = response->Size;

	if(SOCKET_ERROR == WSASendTo(context->s_list, &context->buffer, 1, NULL, 0,
		&context->connectedTo, context->connectedToLen, &context->o, NULL))
		{
		if(WSAGetLastError() != WSA_IO_PENDING)
			{
			DEBUGLOG_L(2, ("ProcessAutoConfig WSASendTo error %d\n", WSAGetLastError()));
			ProcessBroadcastSentResponse(context, tid, key, dwLen);
			return;
			}
		}
	}
#endif//ULTRABAC_CLOUD_USE

unsigned __stdcall GCFOS_Listener(void * param)
	{
	DWORD				dwLen;
	DWORD				result;
	ULONG_PTR			key;
	DWORD				dwFlags = 0;

	PGCFOS_CONNECT_STATE context;
	UINT32				i = (UINT32)(LONG_PTR)param;
	btree::btree_set<PVOID>::iterator connect_iter;

	while(true)
		{
		result = GetQueuedCompletionStatus(g_hIOCP, &dwLen, &key, (LPOVERLAPPED *)&context, 1000);
		// Before requesting another command, check to see if we're trying to exit
		if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
			{
			InterlockedDecrement(&g_ThreadsActive);
			break; // immediately exit worker thread
			}
		if(context == NULL)
			{
			// timeout
			continue;
			}
		if(!result)
			{
			if(GetLastError() == ERROR_NETNAME_DELETED 
			|| GetLastError() == ERROR_CONNECTION_ABORTED)
				{
				DEBUGLOG_L(3, ("Connection forcibly closed - %s\n", context->connectedToHost));
				CloseConnection(context);
				continue;
				}
			DEBUGLOG(("GCFOS_Listener: Error in GQCS: %d (%p)\n", GetLastError(), context));
			if(context != NULL)
				{
				CloseConnection(context);
				}
			continue;
			}
		EnterCriticalSection(&g_csConnections);
		connect_iter = g_ConnectState.find(context);
		LeaveCriticalSection(&g_csConnections);
		if(connect_iter == g_ConnectState.end() && (PGCFOS_LISTEN_STATE)context != &g_ListenState[key])
			{
			DEBUGLOG_L(4, ("Discarding bytes from unknown context\n"));
			continue;
			}
		if(dwLen == 0 && context->op != IOCP_OP_ACCEPT)
			{
			DEBUGLOG_L(4, ("Closing %s connection normally\n", context->connectedToHost));
			// this client has disconnected
			CloseConnection(context, GCFOS_SESSION_END_REASON::NORMAL);
			continue;
			}
		if(context->status == STATE_CONNECTED)
			{
			context->activityTimer = GCFOS_INITIAL_ACTIVITY_VALUE;
			}
		switch(context->op)
			{
			case IOCP_OP_ACCEPT:
				ProcessAccept(context, i, key, dwLen);
				break;

#ifndef ULTRABAC_CLOUD_USE
			case IOCP_OP_AWAITING_BROADCAST:
				ProcessAutoConfig((PGCFOS_LISTEN_STATE)context, i, key, dwLen);
				break;
			case IOCP_OP_BROADCAST_SENT_RESPONSE:
				ProcessBroadcastSentResponse((PGCFOS_LISTEN_STATE)context, i, key, dwLen);
				break;

#else

			case IOCP_OP_CHALLENGE_SENT:
				context->op = IOCP_OP_WAITING_ENC_CHALLENGE;
				// Not requesting command -- but waiting for encryption response
				context->buffer.len = sizeof(GCFOS_REQUEST_AUTH_2);

				result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
				if(result == SOCKET_ERROR)
					{
					if(ERROR_IO_PENDING != WSAGetLastError())
						{
						DEBUGLOG_L(2, ("IOCP_OP_CHALLENGE_SENT WSARecv error: %d\n", WSAGetLastError()));
						CloseConnection(context);
						break;
						}
					}
				break;

			case IOCP_OP_WAITING_ENC_CHALLENGE:
				// Received encryption response
				ProcessAuthPhase2(context, i, key, dwLen);
				break;
#endif//ULTRABAC_CLOUD_USE

			case IOCP_OP_WAITING_REQUEST:
				ProcessRequest(context, i, key, dwLen);
				break;

			case IOCP_OP_SENT_FINAL_RESPONSE:
				RequestCommand(context); // this command processed - request another
				break;

			case IOCP_OP_WAITING_DATABLOCK:
			case IOCP_OP_WRITING_DATABLOCK:
				ReceiveDatablockFromContributor(context, i, key, dwLen);
				break;

			case IOCP_OP_READING_DATABLOCK:
				SendDataBlockToRequestor(context, i, key, dwLen);
				break;

			case IOCP_OP_READING_DATABLOCK_PORTION:
				SendDataBlockPortionToRequestor(context, i, key, dwLen);
				break;

			case IOCP_OP_SENDING_LCUD:
				ProcessLCUDBlock(context, i, key, dwLen);
				break;

			case IOCP_OP_SENT_BLOCK_QUERY_RESPONSE:
				if(context->iBlocksExpected == 0)
					{
					RequestCommand(context);
					break;
					}
				context->op = IOCP_OP_RECEIVING_BLOCKS;
				context->buffer.len = sizeof(UINT16); // get the first header (size) bytes
				result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
				if(result == SOCKET_ERROR)
					{
					if(ERROR_IO_PENDING != WSAGetLastError())
						{
						DEBUGLOG_L(1, ("%s: GCFOS_Listener WSARecv error: %d\n", context->connectedToHost, WSAGetLastError()));
						CloseConnection(context);
						break;
						}
					}
				break;

			case IOCP_OP_SENT_RETRIEVE_BLOCK_RESPONSE:
				DEBUGLOG_L(5, ("%s: SENT_RETRIEVE_BLOCK_RESPONSE ack %u bytes\n", context->connectedToHost, dwLen));
				context->remaining -= dwLen;
				context->outputOffset += dwLen;
				if(context->remaining)
					{
					break;
					}
				RequestCommand(context);
				break;

			case IOCP_OP_RECEIVING_BLOCKS:
				ProcessStoreBlock(context, i, key, dwLen);
				break;

			case IOCP_OP_RECEIVING_INCOMPLETE_COMMAND:
				ProcessRequest(context, i, key, dwLen);
				break;

			case IOCP_OP_WRITING_HASHCHAIN:
				ReceiveHashChainFromContributor(context, i, key, dwLen);
				break;

			default:
				// ban ip -- invalid data received
				DEBUGLOG(("%s: Invalid op type (%x) received - terminating connection\n", context->connectedToHost, context->op));
				CloseConnection(context);
				break;
			}
		}

	_endthreadex(0);
	return 0;
	}

void ProcessRequest(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_AUTH		auth = (PGCFOS_REQUEST_AUTH) context->buffer.buf;
	PGCFOS_REQUEST_QUERY	req = (PGCFOS_REQUEST_QUERY) context->buffer.buf;

	switch(req->type)
		{
#ifdef ULTRABAC_CLOUD_USE

		// the following REQUESTS are for the server running on UltraBac's cloud

		case GCFOS_REQ_AUTH:
			// phase 1 -- send a challenge string to client
			ProcessAuthPhase1(context, tid, key, dwLen);
			break;

		case GCFOS_REQ_ADD_CLIENT:

			ProcessAddClient(context, tid, key, dwLen);
			// Already sent final response -- command will be automatically requested
			return;

		case GCFOS_REQ_GET_CLIENT:
			ProcessGetClient(context, tid, key, dwLen);
			// Already sent final response -- command will be automatically requested
			return;
#else
		// This request is only valid when running on a customer's local-server

		case GCFOS_REQ_SIMPLE_AUTH:
			ProcessSimpleAuth(context, tid, key, dwLen);
			return;

#endif//ULTRABAC_CLOUD_USE

		case GCFOS_REQ_QUERY_BLOCKS:
			// Because this command is quite large, it might be received in chunks
			if(dwLen < sizeof(GCFOS_REQUEST_QUERY_BLOCKS))
				{
				WSABUF TempBuffer;
				DWORD dwFlags = 0;

				DEBUGLOG_L(5, ("GCFOS_REQ_QUERY_BLOCKS -- incomplete packet received(%u) from %s\n", dwLen, context->connectedToHost));
				if(dwLen + context->offset < sizeof(GCFOS_REQUEST_QUERY_BLOCKS))
					{
					context->offset += dwLen;
					TempBuffer.buf = context->buffer.buf + context->offset;
					// request exactly what remains of the command
					context->remaining = sizeof(GCFOS_REQUEST_QUERY_BLOCKS) - context->offset;
					TempBuffer.len = context->remaining;
					context->op = IOCP_OP_RECEIVING_INCOMPLETE_COMMAND;
					if(WSARecv(context->s_acc, &TempBuffer, 1, &dwLen, &dwFlags, &context->o, NULL) == SOCKET_ERROR)
						{
						if(WSAGetLastError() != ERROR_IO_PENDING)
							{
							DEBUGLOG(("%s: GCFOS_REQ_QUERY_BLOCKS failed to request more data from client (%u)\n", context->connectedToHost, WSAGetLastError()));
							CloseConnection(context);
							return;
							}
						}
					return;
					}
				}
			ProcessQueryBlocks(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_RESTORE_BLOCK:
			ProcessRestoreBlock(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_INFORM_ACTIVE_HASHES:
			ProcessInformActiveHashes(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_GET_SERVER_VERSION:
			ProcessGetServerVersion(context, tid, key, dwLen);
			break;

		case GCFOS_REQ_DELETE_CLIENT:
			ProcessDeleteClient(context, tid, key, dwLen);
			// Already sent final response -- command will be automatically requested
			return;

		case GCFOS_REQ_QUERY:

			if(dwLen < sizeof(GCFOS_REQUEST_QUERY))
				{
				DEBUGLOG(("Query -- wrong length received(%u) from %s - ignoring\n", dwLen, context->connectedToHost));
				// Attempt to read another request
				RequestCommand(context);
				return;
				}
			ProcessQuery(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_CONTRIBUTE_FILE:
			ReceiveFileFromContributor(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_GET_WHOLE_FILE:

			if(dwLen < sizeof(GCFOS_REQUEST_GET_WHOLE_FILE))
				{
				DEBUGLOG(("%s: GCFOS_REQUEST_GET_WHOLE_FILE -- wrong length received(%u) - ignoring\n", context->connectedToHost, dwLen));
				// Attempt to read another request
				RequestCommand(context);
				return;
				}

			ProcessGetWholeFileCommand(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_GET_FILE_PORTION:
			ProcessGetFilePortion(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_DELETE_OBJECT:
			ProcessDeleteObject(context, tid, key, dwLen);
			return;

		case GCFOS_REQ_LCUD_REQ:
			ProcessLCUDRequest(context, tid, key, dwLen);
			break;

		case GCFOS_REQ_PROVIDE_FILENAME:
			ProcessProvideFilename(context, tid, key, dwLen);
			break;

		default:
			if(context->InError)
				{
				DEBUGLOG_L(3, ("%s: Detritus (%u bytes) from failed donation received -- ignoring\n", context->connectedToHost, dwLen));
				RequestCommand(context);
				break;
				}
			DEBUGLOG_L(2, ("%s: Invalid request type (%u) received - ignoring\n", context->connectedToHost, req->type));
			// ban ip
			BanIP(context);
			CloseConnection(context);
			return;
		}

	}

void ProcessGetServerVersion(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_GET_SERVER_VERSION_RESPONSE Response = (PGCFOS_GET_SERVER_VERSION_RESPONSE)context->buffer.buf;

	if(context->client == 0)
		{
		DEBUGLOG_L(2, ("%s: unauthorized client attempting to get version\n", context->connectedToHost));
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	memset(Response, 0, sizeof(GCFOS_GET_SERVER_VERSION_RESPONSE));
	context->buffer.len = sizeof(GCFOS_GET_SERVER_VERSION_RESPONSE);
	Response->BlockStore = (g_bDedupeBlocks ? TRUE : FALSE);
	Response->FileStore = (g_bDedupeFiles ? TRUE : FALSE);
	Response->EnableBlockPurging = (g_bEnableBlocksPurging ? TRUE : FALSE);
	Response->Version = 1;
	Response->ServerValidation = g_Server_Validation;
	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessGetServerVersion failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

#ifndef ULTRABAC_CLOUD_USE
void ProcessSimpleAuth(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	GCFOS_CLIENT_ENTRY				newclient;
	gcfosdbTxn						*txn = NULL;
	int								rc;
	int								deadlockcount = 0;
	gcfosdbCursor					*c_clients;
	UINT32							seq = 0;
	PGCFOS_SIMPLE_AUTH_RESPONSE		response = (PGCFOS_SIMPLE_AUTH_RESPONSE)context->buffer.buf;
	PGCFOS_REQUEST_SIMPLE_AUTH		req = (PGCFOS_REQUEST_SIMPLE_AUTH)context->buffer.buf;
	GCFOS_CLIENT_2_ENTRY			client2Entry;
	UINT32							clientid = 0; // indicates a rejected enrollment

	req->szName[GCFOS_COMPUTER_NAME_LENGTH - 1] = 0; // ensure it is null-terminated

	if(_tcsnicmp(req->szName, GCFOS_COMPUTER_NAME_MININT, GCFOS_COMPUTER_NAME_MININT_LEN) == 0)
		{
		DEBUGLOG_L(2, ("ProcessSimpleAuth: %s denying %s\n", context->connectedToHost, CStringA(req->szName)));
		goto ProcessEntrollment_sendResponse;
		}
	if(_tcscmp(req->szName, GCFOS_CLIENT_UBDR_STRING) == 0)
		{
		clientid = GCFOS_CLIENTID_UBDR;
		DEBUGLOG_L(4, ("ProcessSimpleAuth: %s accepting UBDR request\n", context->connectedToHost));
		goto ProcessEntrollment_sendResponse;
		}

	_tcsupr(req->szName);

ProcessProcessEnrollment_start:
	if(txn != NULL)
		{
		deadlockcount++;
		gcfosdb::AbortTxn(txn);
		txn = NULL;
		}
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc == gcfosdb_LOCK_DEADLOCK)
		{
		deadlockcount++;
		goto ProcessProcessEnrollment_start;
		}

	if(rc != 0)
		{
		DEBUGLOG_L(1, ("ProcessSimpleAuth: unable to begin new txn %d\n", rc));
		clientid = 0; // this will signal the "reject" of the enrollment
		goto ProcessEntrollment_sendResponse; // reject enrollment
		}


	memset(&client2Entry, 0, sizeof(client2Entry));
	_tcsncpy(client2Entry.szName, req->szName, GCFOS_COMPUTER_NAME_LENGTH);
	rc = g_Clients2->find(&client2Entry, txn);
	switch(rc)
		{
		case gcfosdb_LOCK_DEADLOCK:
			deadlockcount++;
			goto ProcessProcessEnrollment_start;
		case 0: // found in cursor
			clientid = client2Entry.clientid;
			newclient.clientid = clientid;
			rc = g_Clients->find(&newclient, txn);
			if(rc == 0)
				{
				seq = newclient.lcud_seq;
				}
			else
				{
				DEBUGLOG_L(3, ("ProcessSimpleAuth: %s failed to find client-rec for client %u, %d\n", context->connectedToHost, client2Entry.clientid, rc));
				}
			DEBUGLOG_L(4, ("ProcessSimpleAuth: %s found client by name %s, client %u, LCUD#:%u\n", context->connectedToHost, CStringA(req->szName), client2Entry.clientid, seq));
			goto ProcessEntrollment_sendResponse;
		case gcfosdb_NOTFOUND:
			break;
		default:
			DEBUGLOG_L(4, ("ProcessSimpleAuth: unexpected error on find: %d\n", rc));
			clientid = 0; // this will signal the "reject" of the enrollment
			goto ProcessEntrollment_sendResponse; // reject enrollment
		}

	// this is a new client -- ENROLL now

	if((rc = g_Clients->createCursor(&c_clients, 0, txn)) != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessProcessEnrollment_start;
			}
		DEBUGLOG_L(1, ("ProcessSimpleAuth: failed to get clients cursor %d\n", rc));
		goto ProcessEntrollment_sendResponse; // reject enrollment
		}

	// Get the LAST entry in clients so we know the new client ID (+1 from last)
	memset(&newclient, 0, sizeof(newclient));
	rc = g_Clients->get(c_clients, &newclient, gcfosdb_LAST, txn);
	switch(rc)
		{
		case gcfosdb_LOCK_DEADLOCK:
			deadlockcount++;
			goto ProcessProcessEnrollment_start;

		default:
			DEBUGLOG_L(1, ("ProcessSimpleAuth: failed to read clients cursor %d\n", rc));
			clientid = 0; // indicates a rejected enrollment
			goto ProcessEntrollment_sendResponse; // reject enrollment

		case gcfosdb_NOTFOUND:
			// the 'get' failed "not found", so start at 2(incremented below)
			clientid = 1; // start at 2 for the first enrolled client
			break;
		
		case 0:
			clientid = newclient.clientid;
			break;
		}
	
	clientid++;
	memset(&newclient, 0, sizeof(newclient));
	memset(&client2Entry, 0, sizeof(client2Entry));
	newclient.clientid = clientid;
	client2Entry.clientid = clientid;
	_tcsncpy(newclient.szName, req->szName, GCFOS_COMPUTER_NAME_LENGTH);
	_tcsncpy(client2Entry.szName, req->szName, GCFOS_COMPUTER_NAME_LENGTH);

	rc = g_Clients->insert(&newclient, txn, 0);
	if(rc != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessProcessEnrollment_start;
			}
		gcfosdb::AbortTxn(txn);
		txn = NULL;
		DEBUGLOG_L(1, ("ProcessSimpleAuth: failed to insert into clients %d\n", rc));
		clientid = 0; // indicates a rejected enrollment
		goto ProcessEntrollment_sendResponse; // reject enrollment
		}
	rc = g_Clients2->insert(&client2Entry, txn, 0);
	if(rc != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessProcessEnrollment_start;
			}
		gcfosdb::AbortTxn(txn);
		txn = NULL;
		DEBUGLOG_L(1, ("ProcessSimpleAuth: failed to insert into clients2 %d\n", rc));
		clientid = 0; // indicates a rejected enrollment
		goto ProcessEntrollment_sendResponse; // reject enrollment
		}

	DEBUGLOG_L(1, ("%s: New client ID:%u, name: %S\n", context->connectedToHost, newclient.clientid, newclient.szName));

ProcessEntrollment_sendResponse:
	if(txn != NULL)
		{
		gcfosdb::CommitTxn(txn);
		txn = NULL;
		}
	context->client = clientid;
	if(clientid == 0)
		{
		response->SrvResponse = GCFOS_SRV_RESP_ERROR;
		}
	else
		{
		// update the connectedToHost (which would be an IP string) to the supplied computer-name
		if(clientid != GCFOS_CLIENTID_UBDR)
			{
			strcpy(context->connectedToHost, CStringA(req->szName));
			}
		response->SrvResponse = GCFOS_SRV_RESP_AUTH;
		AddSessionRecord(context);
		}

	response->client_id = clientid;
	response->seq = seq;
	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_SIMPLE_AUTH_RESPONSE);
	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessSimpleAuth failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

#endif//ULTRABAC_CLOUD_USE


void DoDeleteObjects(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	System::String								^myprefix;
	char										hexstr[(GCFOS_SHA1_LEN * 2)+1];

	tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexstr);
	myprefix =  gcnew System::String(hexstr);
	sprintf_s(hexstr, 9, "%08x", context->size);
	System::String ^sizehex = gcnew System::String(hexstr);
	myprefix += "-";
	myprefix += sizehex;
	myprefix += "/";
	g_Repo->DeleteObjects(myprefix, g_Repo2);
	}

void ProcessProvideFilename(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_PROVIDE_FILENAME	req = (PGCFOS_REQUEST_PROVIDE_FILENAME) context->buffer.buf;
	System::String		^objectname_S;
	CHAR				objectname[128];
	CHAR				hexSHA1[(GCFOS_SHA1_LEN * 2)+1];
	size_t				pathlen;

	if(context->client == 0)
		{
		DEBUGLOG_L(2, ("%s: unauthorized client attempting to provide filename\n", context->connectedToHost));
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(dwLen != sizeof(GCFOS_REQUEST_PROVIDE_FILENAME))
		{
		DEBUGLOG_L(1, ("%u: invalid provide-filename length: %u\n", dwLen));
		_CrtDbgBreak();
		RequestCommand(context);
		return;
		}

	tohex_A(req->SHA1Bytes, GCFOS_SHA1_LEN, hexSHA1);
	sprintf_s(objectname, "%s-%08x/-name", hexSHA1, req->size);

	objectname_S = gcnew System::String(objectname);
	pathlen = strlen(req->filename) + 1;
	array<System::Byte> ^object_buffer = gcnew array<System::Byte>((int)pathlen);
	System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(req->filename), object_buffer, 0, System::Int32(pathlen)); 
	System::IO::MemoryStream ^ms = gcnew System::IO::MemoryStream(object_buffer);

	g_Repo->Put(objectname_S, ms, g_Repo2);

	DEBUGLOG_L(4, ("Accepted filename %s for %s\n", req->filename, hexSHA1));
	SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK);
	return;
	}

void ProcessDeleteObject(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_CONTRIBUTE_FILE	getHdrReq = (PGCFOS_REQUEST_CONTRIBUTE_FILE)context->buffer.buf;
	GCFOS_RESIDENT_ENTRY			residentEntry;
	GCFOS_WANTED_ENTRY				wantedEntry;

	if(!CONTEXT_IS_ADMIN) // must be admin ID
		{
		DEBUGLOG(("%s: Delete object request from unauthorized client\n", context->connectedToHost));
		BanIP(context);
		// ban ip
		CloseConnection(context);
		return;
		}
	if(!g_bDedupeFiles)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_NOT_CONFIGURED);
		return;
		}

	context->size = getHdrReq->size;
	memcpy(context->SHA1, getHdrReq->SHA1Bytes, GCFOS_SHA1_LEN);

	DoDeleteObjects(context, tid, key, dwLen);

	// make sure it's not in resident db or wanted db
	memcpy(residentEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
	residentEntry.size = context->size;
	g_Resident->erase(&residentEntry);
	memcpy(wantedEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
	wantedEntry.size = context->size;
	if(getHdrReq->flags & GCFOS_REQUEST_DELETE_FILE_BUT_WANTED)
		{
		g_Wanted->insert(&wantedEntry);
		}
	else
		{
		g_Wanted->erase(&wantedEntry);
		}
	SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK);
	return;
	}

#ifdef ULTRABAC_CLOUD_USE
// we temporarily disable managed code (CLR) otherwise it causes a problem with linker warning
#pragma managed(push, off)
void ProcessAuthPhase1(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_AUTH		auth = (PGCFOS_REQUEST_AUTH)context->buffer.buf;
	PGCFOS_AUTH_RESPONSE	response = (PGCFOS_AUTH_RESPONSE)context->buffer.buf;
	int						i;
	UINT32					randoms[GCFOS_CHALLENGE_STR_LEN / sizeof(UINT32)];

	if(dwLen != sizeof(GCFOS_REQUEST_AUTH))
		{
		DEBUGLOG_L(2, ("%s: Auth -- wrong length received(%u) - closing\n", context->connectedToHost, dwLen));
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	delete[] context->challenge;
	context->challenge = new UCHAR[GCFOS_CHALLENGE_STR_LEN];
	for(i = 0; i < (GCFOS_CHALLENGE_STR_LEN / sizeof(UINT32)); i++)
		{
		rand_s(&randoms[i]);
		}
	memcpy(response->challenge, randoms, GCFOS_CHALLENGE_STR_LEN);
	memcpy(context->challenge, randoms, GCFOS_CHALLENGE_STR_LEN);
	DEBUGLOG_L(3, ("Phase 1 authorization received - %s\n", context->connectedToHost));

	context->op = IOCP_OP_CHALLENGE_SENT;
	// now send a challenge string (for encryption) back to client
	context->buffer.len = sizeof(GCFOS_AUTH_RESPONSE);
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG_L(2, ("%s: ProcessRequest failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

void ProcessAuthPhase2(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	UCHAR							decrypted_string[GCFOS_CHALLENGE_STR_LEN];
	GCFOS_CLIENT_ENTRY				client_entry;
	PGCFOS_REQUEST_AUTH_2			auth_2 = (PGCFOS_REQUEST_AUTH_2)context->buffer.buf;
	PGCFOS_AUTH2_RESPONSE			response_2 = (PGCFOS_AUTH2_RESPONSE)context->buffer.buf;
	int								rc;
	int								ctxSize;

	if(context->challenge == NULL)
		{
		DEBUGLOG_L(2, ("Phase 2 challenge missing - %s\n", context->connectedToHost));
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	// first, lookup this client to see if in db
	client_entry.clientid = auth_2->client;
	rc = g_Clients->find(&client_entry);
	if(rc != 0)
		{
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("Phase 2 auth - invalid client from %s\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

	ippsAESGetSize(&ctxSize);
	IppsAESSpec* pAES = (IppsAESSpec*)( new Ipp8u [ctxSize] );
	ippsAESInit(client_entry.sharedkey, GCFOS_SHARED_KEY_LEN, pAES, ctxSize);

	ippsAESDecryptCTR(auth_2->challenge_enc, decrypted_string, GCFOS_CHALLENGE_STR_LEN, pAES, auth_2->counter, 64);
	// remove secret and release resource
	ippsAESInit(NULL, GCFOS_CHALLENGE_STR_LEN, pAES, ctxSize);
	delete [] (Ipp8u*)pAES;

	if(memcmp(decrypted_string, context->challenge, GCFOS_CHALLENGE_STR_LEN) != 0)
		{
		// invalid decryption string -- suspect client
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("Phase 2 auth - invalid key from %s\n", context->connectedToHost));
		delete[] context->challenge;
		context->challenge = NULL;
		CloseConnection(context);
		return;
		}

	context->client = auth_2->client;
	delete[] context->challenge;
	context->challenge = NULL;

	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_AUTH2_RESPONSE);
	response_2->result = GCFOS_SRV_RESP_AUTH;
	response_2->seq = client_entry.lcud_seq;

	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessAuthPhase2 failed to send result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	DEBUGLOG_L(4, ("Phase 2 auth - client authenticated %s\n", context->connectedToHost));
	AddSessionRecord(context);
	}
#pragma managed(pop)
#endif//ULTRABAC_CLOUD_USE

int DeleteAllLimboRecordsForClient(GCFOS_CLIENTID clientid, gcfosdbTxn *txn)
	{
	int								rc;
	GCFOS_LIMBO_2_ENTRY				limbo2Entry;
	GCFOS_LIMBO_ENTRY				limboEntry;
	gcfosdbCursor					*cursor;
	UINT64							recs_deleted = 0;

	rc = g_Limbo2->createCursor(&cursor, 0, txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("DeleteAllLimboRecordsForClient: unable to create limbo2 cursor %d\n", rc));
		return rc;
		}

	memset(&limbo2Entry, 0, sizeof(limbo2Entry));
	limbo2Entry.client = clientid;
	rc = g_Limbo2->get(cursor, &limbo2Entry, gcfosdb_SET_RANGE, txn);
	while(rc == 0)
		{
		if(limbo2Entry.client != clientid)
			break;
		rc = g_Limbo2->erase(cursor);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("DeleteAllLimboRecordsForClient: unable to erase limbo2 cursor %d\n", rc));
			gcfosdb::closeCursor(cursor);
			return rc;
			}
		recs_deleted++;
		memcpy(limboEntry.SHA1, limbo2Entry.SHA1, GCFOS_SHA1_LEN);
		limboEntry.size = limbo2Entry.size;
		limboEntry.client = limbo2Entry.client;
		rc = g_Limbo->erase(&limboEntry, txn);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("DeleteAllLimboRecordsForClient: unable to erase limbo record %d\n", rc));
			}
		rc = g_Limbo2->get(cursor, &limbo2Entry, gcfosdb_NEXT, txn);
		}

	DEBUGLOG_L(1, ("DeleteAllLimboRecordsForClient: deleted %u records\n", recs_deleted));
	gcfosdb::closeCursor(cursor);
	return 0;
	}

void ProcessDeleteClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_DELETE_CLIENT	req = (PGCFOS_REQUEST_DELETE_CLIENT)context->buffer.buf;
	int								rc;
	int								deadlockcount = 0;
	GCFOS_CLIENT_ENTRY				client_entry;
#ifndef ULTRABAC_CLOUD_USE
	GCFOS_CLIENT_2_ENTRY			client_2_entry;
#endif//ULTRABAC_CLOUD_USE
	GCFOS_SRV_RESPONSE				result = GCFOS_SRV_RESP_ERROR;
	HANDLE							hFind;
	TCHAR							szFindPath[LCUD_FILE_PATH_LEN];
	WIN32_FIND_DATA					fd;
	UINT32							filesDeleted=0;
	gcfosdbTxn						*txn;

	if(!CONTEXT_IS_ADMIN)
		{
		// not an admin
		// ban ip
		BanIP(context);
		DEBUGLOG_L(1, ("ProcessDeleteClient: unauthenticated admin - banned\n"));
		CloseConnection(context);
		return;
		}

	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("ProcessDeleteClient: failed to get txn:%d\n", rc));
		}

	// txn processing is already in erase() with deadlock handling
	client_entry.clientid = req->client_id;

#ifndef ULTRABAC_CLOUD_USE
	rc = g_Clients->find(&client_entry, txn);
	if(rc == 0)
		{
		memcpy(client_2_entry.szName, client_entry.szName, GCFOS_COMPUTER_NAME_BYTES);
		rc = g_Clients2->erase(&client_2_entry, txn);
		if(rc != 0)
			{
			DEBUGLOG_L(2, ("ProcessDeleteClient: Unable to delete %u:%S from clients2:%d\n", req->client_id, client_2_entry.szName, rc));
			}
		}
	else
		{
		DEBUGLOG_L(2, ("ProcessDeleteClient: Unable to find %u in clients:%d\n", req->client_id, rc));
		}
#endif//ULTRABAC_CLOUD_USE

	rc = g_Clients->erase(&client_entry, txn);
	if(rc == 0)
		{
		DEBUGLOG_L(2, ("ProcessDeleteClient: Deleted client %u record from clients-db\n", req->client_id));
		result = GCFOS_SRV_RESP_OK;
		}
	else
		{
		DEBUGLOG_L(2, ("ProcessDeleteClient: Delete client %u on clients-db failed: %d\n", req->client_id, rc));
		}

	rc = DeleteAllLimboRecordsForClient(req->client_id, txn);
	if(rc != 0)
		{
		DEBUGLOG_L(2, ("ProcessDeleteClient: DeleteAllLimboRecordsForClient %u failed: %d\n", req->client_id, rc));
		gcfosdb::AbortTxn(txn);
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	rc = gcfosdb::CommitTxn(txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("ProcessDeleteClient: failed to commit txn:%d\n", rc));
		}

	_stprintf_s(szFindPath, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\*.*"), g_LCUD_LocationLocal, req->client_id);
	hFind = FindFirstFile(szFindPath, &fd);
	if(hFind != INVALID_HANDLE_VALUE)
		{
		do
			{
			if(fd.cFileName[0] == '.' || _tcslen(fd.cFileName) > 8)
				continue;
			// Delete single found file
			_stprintf_s(szFindPath, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\%s"), g_LCUD_LocationLocal, req->client_id, fd.cFileName);
			if(DeleteFile(szFindPath))
				{
				filesDeleted++;
				}
			} while(FindNextFile(hFind, &fd));
		FindClose(hFind);
		_stprintf_s(szFindPath, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT, g_LCUD_LocationLocal, req->client_id);
		RemoveDirectory(szFindPath);
		DEBUGLOG_L(3, ("ProcessDeleteClient: Deleted %u files in LCUD for client\n", filesDeleted, req->client_id));
		}

	SendSimpleResponseToClient(context, tid, key, result);
	}

#ifdef ULTRABAC_CLOUD_USE

void ProcessGetClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_GET_CLIENT		req = (PGCFOS_REQUEST_GET_CLIENT)context->buffer.buf;
	PGCFOS_CLIENT_INFO				response = (PGCFOS_CLIENT_INFO)context->buffer.buf;
	int								rc;
	GCFOS_CLIENT_ENTRY				client_entry;

	if(!CONTEXT_IS_ADMIN)
		{
		// not an admin
		// ban ip
		BanIP(context);
		DEBUGLOG_L(4, ("ProcessGetClient: unauthenticated admin\n"));
		CloseConnection(context);
		return;
		}

	// find does it's own retry processing
	client_entry.clientid = req->client_id;
	rc = g_Clients->find(&client_entry);

	if(rc != 0)
		{
		response->client_id = 0;
		}
	else if(rc == 0)
		{
		// successfully found this client record -- copy over the info
		response->client_id = client_entry.clientid;
		memcpy(response->shared_key, client_entry.sharedkey, GCFOS_SHARED_KEY_LEN);
		}
	else
		{
		DEBUGLOG_L(1, ("ProcessGetClient: failed to get client info %d\n", rc));
		CloseConnection(context);
		return;
		}

	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_CLIENT_INFO);

	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessRequest failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

void CreateDefaultUserIfNonePresent()
	{
	gcfosdbTxn						*txn = NULL;
	gcfosdbCursor					*c_clients;
	int								rc;
	UINT32							newsharedkey[(GCFOS_SHARED_KEY_LEN / sizeof(UINT32))];
	int								i;
	GCFOS_CLIENT_ENTRY				newclient;
	TCHAR							szSecret[GCFOS_SHARED_KEY_LEN * 2 + 1]; // hex representation of secret key (written in registry)
	DWORD							dwLen;
	LONG							status;
	HKEY							hKey;
	TCHAR							OneText[] = _T("1");

	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("CreateDefaultUserIfNonePresent: unable to begin new txn %d\n", rc));
		return;
		}

	if((rc = g_Clients->createCursor(&c_clients, 0, txn)) != 0)
		{
		gcfosdb::AbortTxn(txn);
		return;
		}

	rc = g_Clients->get(c_clients, &newclient, gcfosdb_LAST, txn);
	if(rc != gcfosdb_NOTFOUND)
		{
		// there is already at least one user defined -- this will already be the admin user
		// nothing to do.
		gcfosdb::AbortTxn(txn);
		return;
		}

	// this is the first time that the server has run
	// create a new user that is the "admin" user
	memset(&newclient, 0, sizeof(newclient));
	newclient.clientid = 1; // 1 indicates the admin user, the next user 2+ will be all standard users
	for(i = 0; i < (GCFOS_SHARED_KEY_LEN / sizeof(UINT32)); i++)
		{
		rand_s(&newsharedkey[i]);
		}
	memcpy(newclient.sharedkey, newsharedkey, GCFOS_SHARED_KEY_LEN);

	rc = g_Clients->insert(&newclient, txn, 0);
	if(rc != 0)
		{
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("CreateDefaultUserIfNonePresent: failed to create new admin user: %d\n", rc));
		return;
		}

	status = RegCreateKey(g_MyRegistry, _T("Client"), &hKey);
	if(status != ERROR_SUCCESS)
		{
		DEBUGLOG_L(1, ("CreateDefaultUserIfNonePresent: failed to create client registry key %08x\n", status));
		gcfosdb::CommitTxn(txn);
		return;
		}
	dwLen = sizeof(szSecret);
	tohex(newclient.sharedkey, GCFOS_SHARED_KEY_LEN, szSecret);
	status = RegSetValueEx(hKey, GCFOS_CLIENT_REG_SECRETKEY, NULL, REG_SZ, (LPBYTE)&szSecret, dwLen);
	if(status != ERROR_SUCCESS)
		{
		DEBUGLOG_L(1, ("CreateDefaultUserIfNonePresent: failed to update registry with secret %08x\n", status));
		gcfosdb::CommitTxn(txn);
		return;
		}
	status = RegSetValueEx(hKey, GCFOS_CLIENT_REG_CLIENTID, NULL, REG_SZ, (LPBYTE)&OneText, 4/* sizeof L"1" in bytes */);
	if(status != ERROR_SUCCESS)
		{
		DEBUGLOG_L(1, ("CreateDefaultUserIfNonePresent: failed to update registry with client-id %08x\n", status));
		gcfosdb::CommitTxn(txn);
		return;
		}

	gcfosdb::CommitTxn(txn);
	RegCloseKey(hKey);
	}

void ProcessAddClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	UINT32							newsharedkey[(GCFOS_SHARED_KEY_LEN / sizeof(UINT32))];
	int								i;
	CHAR							hexstr[(GCFOS_SHARED_KEY_LEN *2) + 1];
	GCFOS_CLIENT_ENTRY				newclient;
	gcfosdbTxn						*txn = NULL;
	int								rc;
	int								deadlockcount = 0;
	gcfosdbCursor					*c_clients;
	PGCFOS_CLIENT_INFO				response = (PGCFOS_CLIENT_INFO)context->buffer.buf;
	UINT32							clientid;

	if(!CONTEXT_IS_ADMIN)
		{
		// not an admin
		BanIP(context);
		DEBUGLOG_L(1, ("ProcessAddClient: unauthenticated admin from %s\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

ProcessAddClient_start:
	if(txn != NULL)
		{
		deadlockcount++;
		gcfosdb::AbortTxn(txn);
		}
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("ProcessAddClient: unable to begin new txn %d\n", rc));
		CloseConnection(context);
		return;
		}

	if((rc = g_Clients->createCursor(&c_clients, 0, txn)) != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessAddClient_start;
			}
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("ProcessAddClient: failed to get clients cursor %d\n", rc));
		CloseConnection(context);
		return;
		}

	if((rc = g_Clients->get(c_clients, &newclient, gcfosdb_LAST, txn)) != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessAddClient_start;
			}
		if(rc != gcfosdb_NOTFOUND)
			{
			gcfosdb::AbortTxn(txn);
			DEBUGLOG_L(1, ("ProcessAddClient: failed to read clients cursor %d\n", rc));
			CloseConnection(context);
			return;
			}
		clientid = 0;
		}
	else
		{
		clientid = newclient.clientid + 1;
		}
	
	memset(&newclient, 0, sizeof(newclient));
	newclient.clientid = clientid;
	for(i=0; i < (GCFOS_SHARED_KEY_LEN / sizeof(UINT32)); i++)
		{
		rand_s(&newsharedkey[i]);
		}

	memcpy(newclient.sharedkey, newsharedkey, GCFOS_SHARED_KEY_LEN);

	rc = g_Clients->insert(&newclient, txn, 0);
	if(rc != 0)
		{
		if(rc == gcfosdb_LOCK_DEADLOCK)
			{
			deadlockcount++;
			goto ProcessAddClient_start;
			}
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("ProcessAddClient: failed to insert into clients %d\n", rc));
		CloseConnection(context);
		return;
		}
	gcfosdb::CommitTxn(txn);

	tohex_A((LPBYTE)&newsharedkey, GCFOS_SHARED_KEY_LEN, hexstr);

	DEBUGLOG_L(1, ("%s: New client ID:%u, sharedkey: %s\n", context->connectedToHost, newclient.clientid, hexstr));

	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_CLIENT_INFO);
	response->client_id = clientid;
	memcpy(response->shared_key, newclient.sharedkey, GCFOS_SHARED_KEY_LEN);

	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessRequest failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

#endif//ULTRABAC_CLOUD_USE

void ProcessGetWholeFileCommand(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_GET_WHOLE_FILE	getHdrReq = (PGCFOS_REQUEST_GET_WHOLE_FILE)context->buffer.buf;

	System::String								^myprefix;
	System::String								^myhashchain;
	char										hexstr[(GCFOS_SHA1_LEN * 2)+1];
	char										hexdate[9];
	INT32										blks;
	INT32										i, idx;
	bool										bValidated = false;
	UINT32										ValidationOffset;
	BYTE										ValidationBytes[GCFOS_VALIDATION_KEY_LEN];
	UINT32										bytesread, offset, remaining;
	array<System::Byte>							^name_buffer = nullptr;
	System::Collections::Generic::List<System::String ^> ^names = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;
	System::String								^myobj;
	System::IO::Stream							^Stream;
	DWORD										dwRead;

	if(context->client == 0)
		{
		DEBUGLOG(("%s: Get Whole File Request received from unauthorized client\n", context->connectedToHost));
		BanIP(context);
		// ban ip
		CloseConnection(context);
		return;
		}
	if(!g_bDedupeFiles)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_NOT_CONFIGURED);
		return;
		}
	
	memcpy(context->SHA1, getHdrReq->SHA1Bytes, GCFOS_SHA1_LEN);
	memcpy(ValidationBytes, getHdrReq->AuthorizationKey, GCFOS_VALIDATION_KEY_LEN);
	context->size = getHdrReq->size;

	tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexstr);
	sprintf_s(hexdate, 9, "%08x", context->size);
	DEBUGLOG_L(4, ("%s: Retrieve request: %s-%s\n", context->connectedToHost, hexstr, hexdate));
	System::String ^sizehex = gcnew System::String(hexdate);
	myprefix =  gcnew System::String(hexstr);
	myprefix += "-";
	myprefix += sizehex;
	myprefix += "/";

	myhashchain = gcnew System::String(myprefix);
	myhashchain += "h";
	if(g_bDedupeBlocks && g_Repo->GetObject(myhashchain, Stream, g_Repo2, false))
		{
		DEBUGLOG_L(5, ("ProcessGetWholeFileCommand: Found hashchain for %s-%s\n", hexstr, hexdate));
		context->remaining = (UINT32)Stream->Length;
		context->offset = 0;
		context->object_buffer = gcnew array<System::Byte>(context->remaining);
		i = context->remaining;
		offset = 0;
		while(i)
			{
			dwRead = Stream->Read(context->object_buffer, offset, i);
			i -= dwRead;
			offset += dwRead;
			}
		Stream->Close();
		assert((UINT32)context->object_buffer->Length == context->remaining);
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_HASHES_AVAILABLE, IOCP_OP_READING_DATABLOCK);
		return;
		}

	context->object_buffer = nullptr; // make sure that this is clear

	// At most, there should be 4096 entries (a 1MB max per file, gives us 4GB max file size)
	blks = GCFOS_OBJECT_COUNT_FOR_ENTRY(context->size);
	_ASSERTE(blks <= 4096);

	context->od = new GCFOS_OBJECT_DESCRIPTOR;
	context->od->sizes = new UINT32[blks];
	memset(context->od->sizes, 0xff, sizeof(UINT32) * blks);

	if(!g_Repo->GetList(myprefix, names, sizes, g_Repo2))
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	for (idx = 0; idx < names->Count; idx++)
		{
		if(names[idx]->Length > 54)
			{
			// this will be true for "-name" objects
			if(g_debugLvl >= 5)
				{
				if(g_Repo->GetObject(names[idx], Stream, g_Repo2))
					{
					UINT32 rem = (UINT32)Stream->Length;
					dwRead = 0, offset = 0;
					name_buffer = gcnew array<System::Byte>(rem);
					while(rem > 0)
						{
						dwRead = Stream->Read(name_buffer, offset, rem);
						rem -= dwRead;
						offset += dwRead;
						}
					Stream->Close();
					delete Stream;
					}
				}
			continue; // don't need to process the -name object
			}
		i = System::Convert::ToInt32(names[idx]->Substring(50, 3), 16/*radix*/);
		if(i > blks)
			break; // invalid data parsed
		context->od->sizes[i] = sizes[idx];
		if(names[idx]->Substring(53, 1)->Equals("c"))
			context->od->sizes[i] |= GCFOS_COMPRESSED_BIT;
		}

	context->bHdr = true;
	context->time = GetTickCount();
	context->od->cur_entry = 0;

	for(i = 0; i < blks; i++)
		{
		if(context->od->sizes[i] == -1)
			{
			// this entry was not received -- bad data -- ignore request
			delete [] context->od->sizes;
			delete context->od;
			context->od = NULL;
			// This will send an error state to caller and request a new
			// command
			DEBUGLOG_L(3, ("%s: unable to get size array for retrieve\n", context->connectedToHost));
			SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
			return;
			}
		}


	// Validate the retrieval -- check key provided by client as matching data contained in file
	// leave buffer loaded so that it need not be re-loaded to re-send first block

	myobj = myprefix;
	myobj += "000";
	if((context->od->sizes[0] & GCFOS_COMPRESSED_BIT) == 0)
		myobj += "n";
	else
		myobj += "c";
	if(!g_Repo->GetObject(myobj, Stream, g_Repo2))
		{
		DEBUGLOG_L(1, ("%s: Failed to get 000 object for validation check\n", context->connectedToHost));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	ValidationOffset = DetermineOffsetForValidationKey(context->client, context->SHA1, context->size);

	remaining = (UINT32)Stream->Length;
	context->od->objbuf = gcnew array<System::Byte>(remaining);
	// ALL DATA is read from stream now, as it will be assumed to be present as first block later
	// addressed at context->od->objbuf
	offset = 0;
	while(remaining > 0)
		{
		bytesread = Stream->Read(context->od->objbuf, offset, remaining);
		offset += bytesread;
		remaining -= bytesread;
		}
	Stream->Close();

#ifdef ULTRABAC_CLOUD_USE
	IppStatus									iDecompressionStatus;
	Ipp32u										uncompsize;

	if(CONTEXT_IS_ADMIN || bValidated)
		{
		// admin, or already validated
		bValidated = true; // when admin client requests retrieval, assume valid
		}
	else if((context->od->sizes[0] & GCFOS_COMPRESSED_BIT) != 0)
		{
		// Decompress data for compare -- the decompressed data
		Ipp8u * decompressedBuffer = (Ipp8u *)VirtualAlloc(NULL, GCFOS_CLIENT_DST_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		Ipp8u *compressedBuffer = (Ipp8u *)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, 0, System::IntPtr(compressedBuffer), offset);
		uncompsize = GCFOS_CLIENT_DST_BUFSIZE;
		iDecompressionStatus = ippsDecodeLZOSafe_8u(compressedBuffer, context->od->sizes[0] & GCFOS_COMPRESSED_BITMASK, decompressedBuffer, &uncompsize);
		if(iDecompressionStatus == ippStsNoErr)
			{
			if(memcmp(decompressedBuffer + ValidationOffset, getHdrReq->AuthorizationKey, GCFOS_VALIDATION_KEY_LEN) == 0)
				{
				bValidated = true;
				}
			}
		VirtualFree(decompressedBuffer, 0, MEM_RELEASE);
		VirtualFree(compressedBuffer, 0, MEM_RELEASE);
		}
	else
		{
		System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, ValidationOffset, System::IntPtr(ValidationBytes), GCFOS_VALIDATION_KEY_LEN);
		if(memcmp(ValidationBytes, getHdrReq->AuthorizationKey, GCFOS_VALIDATION_KEY_LEN) == 0)
			{
			bValidated = true;
			}
		}
#else
	bValidated = true;
#endif//ULTRABAC_CLOUD_USE

	if(!bValidated)
		{
		delete [] context->od->sizes;
		delete context->od;
		context->od = NULL;
		// This will send an error state to caller
		DEBUGLOG_L(2, ("%s: Invalid ValidationKey received from client %s\n", context->connectedToHost, context->connectedToHost));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_INVALID_VALIDATION_KEY);
		// ban this client to prevent guessing the validation key
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(g_debugLvl >= 5)
		{
		if(name_buffer == nullptr)
			{
			DEBUGLOG_L(4, ("%s: Sending <UNKNOWN>(%s) to client", context->connectedToHost, CStringA(myprefix)));
			}
		else
			{
			DEBUGLOG_L(4, ("%s: Sending %s %s to client", context->connectedToHost, CStringA(System::Text::Encoding::UTF8->GetString(name_buffer)), CStringA(myprefix)));
			}
		}
	
	SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK, IOCP_OP_READING_DATABLOCK);
	return;
	}

void ProcessGetFilePortion(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_GET_FILE_PORTION	getHdrReq = (PGCFOS_REQUEST_GET_FILE_PORTION)context->buffer.buf;
	System::String								^myprefix;
	System::String								^myhashchain;
	char										hexstr[(GCFOS_SHA1_LEN * 2)+1];
	char										hexdate[9];
	INT32										blks;
	INT32										i, idx;
	bool										bValidated = false;
	UINT32										ValidationOffset;
	UINT32										bytesread, offset, remaining;
	array<System::Byte>							^name_buffer = nullptr;
	System::Collections::Generic::List<System::String ^> ^names = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;
	System::String								^myobj;
	System::IO::Stream							^Stream;
	DWORD										dwRead;
	UINT32										PortionOffset, PortionLength;
	IppStatus									iDecompressionStatus;
	Ipp32u										uncompsize;

	// First, sanity checking

	if(dwLen != sizeof(GCFOS_REQUEST_GET_FILE_PORTION))
		{
		DEBUGLOG_L(4, ("%s: ProcessGetFilePortion() -- wrong length received(%u) - ignoring\n", context->connectedToHost, dwLen));
		// Attempt to read another request
		RequestCommand(context);
		return;
		}

	if(context->client == 0)
		{
		// invalid state
		// ban ip
		DEBUGLOG(("%s: Get File Portion Request received from unauthorized client\n", context->connectedToHost));
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(getHdrReq->Offset + getHdrReq->Length > getHdrReq->size)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}
	PortionOffset = getHdrReq->Offset;
	PortionLength = getHdrReq->Length;

	if(!g_bDedupeFiles)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_NOT_CONFIGURED);
		return;
		}

	if(context->size == getHdrReq->size
	&& memcmp(context->SHA1, getHdrReq->SHA1Bytes, GCFOS_SHA1_LEN) == 0
	&& memcmp(context->ValidationBytes, getHdrReq->AuthorizationKey, GCFOS_VALIDATION_KEY_LEN) == 0)
		{
		// this is a portion retrieval from the same (validated) file as last time
		// no validation is therefore necessary
		bValidated = true;
		}

	tohex_A(getHdrReq->SHA1Bytes, GCFOS_SHA1_LEN, hexstr);
	sprintf_s(hexdate, 9, "%08x", getHdrReq->size);
	DEBUGLOG_L(5, ("%s: Retrieve file portion request: %s-%s %x-%x\n", context->connectedToHost, hexstr, hexdate, PortionOffset, PortionLength));
	System::String ^sizehex = gcnew System::String(hexdate);
	myprefix =  gcnew System::String(hexstr);
	myprefix += "-";
	myprefix += sizehex;
	myprefix += "/";

	myhashchain = gcnew System::String(myprefix);
	myhashchain += "h";
	if(g_bDedupeBlocks && g_Repo->GetObject(myhashchain, Stream, g_Repo2, false))
		{
		DEBUGLOG_L(5, ("ProcessGetFilePortion: Found hashchain for %s-%s\n", hexstr, hexdate));
		remaining = (UINT32)Stream->Length;
		context->object_buffer = gcnew array<System::Byte>(remaining);
		i = remaining;
		offset = 0;
		while(i)
			{
			dwRead = Stream->Read(context->object_buffer, offset, i);
			i -= dwRead;
			offset += dwRead;
			}
		Stream->Close();
		assert((UINT32)context->object_buffer->Length == remaining);
		context->offset = 0;
		context->remaining = remaining;
		// Normal IOCP_OP_READING_DATABLOCK necessary here as this processes hashchains correctly
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_HASHES_AVAILABLE, IOCP_OP_READING_DATABLOCK);
		// NOTE: Validation is not necessary when using hashchain retrieval since this can only be activated on local installations
		return;
		}

	// we only test for this condition here because the length of the retrieve doesn't matter if the
	// file is represented by a hash-chain
	if(getHdrReq->Length > GCFOS_RETRIEVE_FILE_MAX_PORTION_SIZE)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_TOO_BIG);
		return;
		}

	context->object_buffer = nullptr; // make sure that this is clear (otherwise it signals a hashchain retrieval)
	context->bHdr = false;

	blks = GCFOS_OBJECT_COUNT_FOR_ENTRY(getHdrReq->size);
	_ASSERTE(blks <= 4096);
	
	context->offset = PortionOffset;
	context->remaining = PortionLength;

	// if bValidate is true, then we have already loaded the od structure with all the sizes for this file
	// and it is therefore unnecessary to do it again (the structure is not deleted since it is likely
	// another portion will be requested from the same file)
	if(bValidated && context->od != NULL)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK, IOCP_OP_READING_DATABLOCK_PORTION);
		return;
		}

	// At most, there should be 4096 entries (a 1MB max per file, gives us 4GB max file size)
	context->od = new GCFOS_OBJECT_DESCRIPTOR;
	context->od->sizes = new UINT32[blks];
	if(context->decompressedBuffer == NULL)
		{
		context->decompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_DST_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(context->decompressedBuffer == NULL)
			{
			SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
			}
		}

	memset(context->od->sizes, 0xff, sizeof(UINT32) * blks);

	if(!g_Repo->GetList(myprefix, names, sizes, g_Repo2))
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	for (idx = 0; idx < names->Count; idx++)
		{
		if(names[idx]->Length > 54)
			{
			// this will be true for "-name" objects
			if(g_debugLvl >= 5)
				{
				if(g_Repo->GetObject(names[idx], Stream, g_Repo2))
					{
					UINT32 rem = (UINT32)Stream->Length;
					dwRead = 0, offset = 0;
					name_buffer = gcnew array<System::Byte>(rem);
					while(rem > 0)
						{
						dwRead = Stream->Read(name_buffer, offset, rem);
						rem -= dwRead;
						offset += dwRead;
						}
					Stream->Close();
					delete Stream;
					}
				}
			continue; // don't need to process the -name object
			}
		i = System::Convert::ToInt32(names[idx]->Substring(50, 3), 16/*radix*/);
		if(i > blks)
			break; // invalid data parsed
		context->od->sizes[i] = sizes[idx];
		if(names[idx]->Substring(53, 1)->Equals("c"))
			context->od->sizes[i] |= GCFOS_COMPRESSED_BIT;
		}
	context->time = GetTickCount();
	context->od->cur_entry = 0;
		
	for(i = 0; i < blks; i++)
		{
		if(context->od->sizes[i] == -1)
			{
			// this entry was not received -- bad data -- ignore request
			delete [] context->od->sizes;
			delete context->od;
			context->od = NULL;
			// This will send an error state to caller and request a new
			// command
			DEBUGLOG_L(3, ("%s: unable to get size array for retrieve\n", context->connectedToHost));
			SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
			return;
			}
		}

	// Validate the retrieval -- check key provided by client as matching data contained in file
	// leave buffer loaded so that it need not be re-loaded to re-send first block

	myobj = myprefix;
	myobj += "000";
	if((context->od->sizes[0] & GCFOS_COMPRESSED_BIT) == 0)
		myobj += "n";
	else
		myobj += "c";
	if(!g_Repo->GetObject(myobj, Stream, g_Repo2))
		{
		DEBUGLOG_L(1, ("%s: Failed to get 000 object for validation check\n", context->connectedToHost));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	ValidationOffset = DetermineOffsetForValidationKey(context->client, getHdrReq->SHA1Bytes, getHdrReq->size);

	remaining = (UINT32)Stream->Length;
	context->od->objbuf = gcnew array<System::Byte>(remaining);

	// ALL DATA is read from stream now, as it will be assumed to be present as first block later
	// addressed at context->od->objbuf
	offset = 0;
	while(remaining > 0)
		{
		bytesread = Stream->Read(context->od->objbuf, offset, remaining);
		offset += bytesread;
		remaining -= bytesread;
		}
	Stream->Close();

	if((context->od->sizes[0] & GCFOS_COMPRESSED_BIT) != 0)
		{
		// Decompress data for compare -- the decompressed data
		Ipp8u *compressedBuffer = (Ipp8u *)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, 0, System::IntPtr(compressedBuffer), offset);
		uncompsize = GCFOS_CLIENT_DST_BUFSIZE;
		iDecompressionStatus = ippsDecodeLZOSafe_8u(compressedBuffer, context->od->sizes[0] & GCFOS_COMPRESSED_BITMASK, context->decompressedBuffer, &uncompsize);
		VirtualFree(compressedBuffer, 0, MEM_RELEASE);
		}
	else
		{
		System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, 0, System::IntPtr(context->decompressedBuffer), context->od->sizes[0] & GCFOS_COMPRESSED_BITMASK);
		}

#ifdef ULTRABAC_CLOUD_USE
	if(CONTEXT_IS_ADMIN)
		{
		bValidated = true; // when admin client requests retrieval, assume valid
		}
	else if(memcmp(getHdrReq->AuthorizationKey, context->decompressedBuffer + ValidationOffset, GCFOS_VALIDATION_KEY_LEN) == 0)
		{
		bValidated = true;
		}
#else
	bValidated = true;
#endif//ULTRABAC_CLOUD_USE

	if(!bValidated)
		{
		delete [] context->od->sizes;
		delete context->od;
		context->od = NULL;
		// This will send an error state to caller
		DEBUGLOG_L(2, ("%s: Invalid ValidationKey received from client %s\n", context->connectedToHost, context->connectedToHost));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_INVALID_VALIDATION_KEY);
		// ban this client to prevent guessing the validation key
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(g_debugLvl >= 5)
		{
		if(name_buffer == nullptr)
			{
			DEBUGLOG_L(5, ("%s: Sending first portion <UNKNOWN>(%s) to client", context->connectedToHost, CStringA(myprefix)));
			}
		else
			{
			DEBUGLOG_L(5, ("%s: Sending first portion %s %s to client", context->connectedToHost, CStringA(System::Text::Encoding::UTF8->GetString(name_buffer)), CStringA(myprefix)));
			}
		}
	
	memcpy(context->SHA1, getHdrReq->SHA1Bytes, GCFOS_SHA1_LEN);
	memcpy(context->ValidationBytes, getHdrReq->AuthorizationKey, GCFOS_VALIDATION_KEY_LEN);
	context->size = getHdrReq->size;
	SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK, IOCP_OP_READING_DATABLOCK_PORTION);
	return;
	}

void SendDataBlockToRequestor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	CHAR			SHAHex[GCFOS_SHA1_LEN * 2 + 1];
	CHAR			objname[128];
	INT32			cur;
	INT				tocopy;
	int				blks = GCFOS_OBJECT_COUNT_FOR_ENTRY(context->size);
	System::IO::Stream ^Stream;

	if(context->client == 0)
		{
		// invalid state
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(context->object_buffer != nullptr)
		{
		// this is a hashchain retrieval, NOT a file retrieval
		if(context->remaining == 0)
			{
			context->count_retrieves++;
			context->count_retrieve_KB += ((context->offset + 1023) / 1024);
			context->object_buffer = nullptr; // let GC take care of it
			RequestCommand(context);
			return;
			}

		if(context->remaining > GCFOS_BUFSIZE)
			tocopy = GCFOS_BUFSIZE;
		else
			tocopy = context->remaining;

		System::Runtime::InteropServices::Marshal::Copy(context->object_buffer, context->offset, System::IntPtr(context->buffer.buf), tocopy);
		context->offset += tocopy;
		context->remaining -= tocopy;
		context->buffer.len = tocopy;
		if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
			{
			if(WSAGetLastError() != ERROR_IO_PENDING)
				{
				DEBUGLOG(("%s: SendDataBlockToRequestor failed to send hashdata to client (%u)\n", context->connectedToHost, WSAGetLastError()));
				CloseConnection(context);
				return;
				}
			}
		return;
		}

	if(context->od == NULL)
		{
		DEBUGLOG_L(2, ("%s: get file datablock unable to action - not initialized correctly\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

	if(context->bHdr)
		{
		INT32 *pInt = (INT32 *) context->buffer.buf;
		memcpy(context->buffer.buf, context->od->sizes, sizeof(INT32) * blks);
		context->buffer.len = sizeof(INT32) * blks;
		context->remaining = 0;
		context->outputOffset = 0;
		context->bHdr = false;
		if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
			{
			if(WSAGetLastError() != ERROR_IO_PENDING)
				{
				DEBUGLOG(("%s: SendDataBlockToRequestor failed to send hdr to client (%u)\n", context->connectedToHost, WSAGetLastError()));
				CloseConnection(context);
				return;
				}
			}
		return;
		}

	while(true)
		{
		if(context->remaining > 0)
			{
			tocopy = min(context->remaining, GCFOS_BUFSIZE);
			System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, context->outputOffset, System::IntPtr(context->buffer.buf), tocopy);
			context->outputOffset += tocopy;
			context->remaining -= tocopy;
			context->buffer.len = tocopy;
			if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
				{
				if(WSAGetLastError() != ERROR_IO_PENDING)
					{
					DEBUGLOG(("%s: SendDataBlockToRequestor failed to send data to client (%u)\n", context->connectedToHost, WSAGetLastError()));
					CloseConnection(context);
					return;
					}
				}
			return;
			}

		cur = context->od->cur_entry;
		if(cur == blks)
			{
			// we're all done -- delete resources, then wait for new request
			delete [] context->od->sizes;
			delete context->od;
			context->od = NULL;
			context->count_retrieve_KB += (context->size >> 10); //convert size to KB
			context->count_retrieves++;
			RequestCommand(context); // this command processed - request another
			return;
			}
		if(cur == 0)
			{
			// the data will be in the buffer ready from when it was loaded for validation
			context->remaining = context->od->sizes[cur] & GCFOS_COMPRESSED_BITMASK;
			context->outputOffset = 0;
			context->od->cur_entry++; // prepare to read next object in sequence
			continue;
			}
		tohex_A(context->SHA1, GCFOS_SHA1_LEN, SHAHex);
		sprintf_s(objname, sizeof(objname), "%s-%08x/%03x%c",
			SHAHex, context->size,
			cur, ((context->od->sizes[cur] & GCFOS_COMPRESSED_BIT) == 0 ? 'n' : 'c'));
		if(!g_Repo->GetObject(gcnew System::String(objname), Stream, g_Repo2))
			{
			DEBUGLOG_L(1, ("%s: SendDataBlockToRequestor failed to get object for client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		if((UINT32)Stream->Length != (context->od->sizes[cur] & GCFOS_COMPRESSED_BITMASK))
			{
			DEBUGLOG_L(2, ("Size discrepancy discovered for %s, %u:%u\n", objname, (UINT32)Stream->Length, (context->od->sizes[cur] & GCFOS_COMPRESSED_BITMASK)));
			}

		UINT32 bytesread, offset, remaining;

		remaining = (UINT32)Stream->Length;
		context->od->objbuf = gcnew array<System::Byte>(remaining);
		offset = 0;
		while(remaining > 0)
			{
			bytesread = Stream->Read(context->od->objbuf, offset, remaining);
			offset += bytesread;
			remaining -= bytesread;
			}
		Stream->Close();
		context->remaining = context->od->sizes[cur] & GCFOS_COMPRESSED_BITMASK;
		context->outputOffset = 0;
		context->od->cur_entry++; // prepare to read next object in sequence
		}
	}

void SendDataBlockPortionToRequestor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	INT32					idx_needed;
	CHAR					SHAHex[GCFOS_SHA1_LEN * 2 + 1];
	CHAR					objname[128];
	int						blks = GCFOS_OBJECT_COUNT_FOR_ENTRY(context->size);
	System::IO::Stream		^Stream;
	UINT32					bytesread, offset, remaining;
	Ipp32u					uncompsize;
	IppStatus				iDecompressionStatus;
	UINT32					blk_offset, blk_remain, copybytes;

	if(context->client == 0)
		{
		// invalid state
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	if(context->od == NULL)
		{
		DEBUGLOG_L(2, ("%s: get file datablock portion unable to action - not initialized correctly\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}

	if(context->remaining == 0)
		{
		// we don't delete the object_descriptor as we might need it for another portion request shortly
		RequestCommand(context); // this command processed - request another
		return;
		}

	idx_needed = context->offset / GCFOS_CLIENT_SRC_BUFSIZE;

	if(idx_needed != context->od->cur_entry)
		{
		tohex_A(context->SHA1, GCFOS_SHA1_LEN, SHAHex);
		sprintf_s(objname, sizeof(objname), "%s-%08x/%03x%c",
			SHAHex, context->size,
			idx_needed, ((context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BIT) == 0 ? 'n' : 'c'));
		if(!g_Repo->GetObject(gcnew System::String(objname), Stream, g_Repo2))
			{
			DEBUGLOG_L(1, ("%s: SendDataBlockToRequestor failed to get object for client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		if((UINT32)Stream->Length != (context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BITMASK))
			{
			DEBUGLOG_L(2, ("Size discrepancy discovered for %s, %u:%u\n", objname, (UINT32)Stream->Length, (context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BITMASK)));
			}

		remaining = (UINT32)Stream->Length;
		context->od->objbuf = gcnew array<System::Byte>(remaining);
		offset = 0;
		while(remaining > 0)
			{
			bytesread = Stream->Read(context->od->objbuf, offset, remaining);
			offset += bytesread;
			remaining -= bytesread;
			}
		Stream->Close();

		if((context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BIT) != 0)
			{
			// Decompress data for compare -- the decompressed data
			Ipp8u *compressedBuffer = (Ipp8u *)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, 0, System::IntPtr(compressedBuffer), offset);
			uncompsize = GCFOS_CLIENT_DST_BUFSIZE;
			iDecompressionStatus = ippsDecodeLZOSafe_8u(compressedBuffer, context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BITMASK, context->decompressedBuffer, &uncompsize);
			VirtualFree(compressedBuffer, 0, MEM_RELEASE);
			}
		else
			{
			System::Runtime::InteropServices::Marshal::Copy(context->od->objbuf, 0, System::IntPtr(context->decompressedBuffer), context->od->sizes[idx_needed] & GCFOS_COMPRESSED_BITMASK);
			}

		context->od->objbuf = nullptr;
		context->od->cur_entry = idx_needed;
		}

	blk_offset = context->offset % GCFOS_CLIENT_SRC_BUFSIZE;
	blk_remain = GCFOS_CLIENT_SRC_BUFSIZE - blk_offset;
	copybytes = context->remaining;
	if(copybytes > blk_remain)
		copybytes = blk_remain;
	memcpy(context->buffer.buf, context->decompressedBuffer + blk_offset, copybytes);
	context->offset += copybytes;
	context->remaining -= copybytes;
	context->buffer.len = copybytes;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: SendDataBlockPortionToRequestor failed to send data to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

	// When the block-store is enabled, the client will store all of the blocks that constitute the file
// in the block-store and generate a hash-chain for the file (one 28-byte hash for each 4KB block)
// There may be some straggler data bytes subsequent to the hash chain (max 255 bytes) that are not
// stored in the block-store. 
void ReceiveHashChainFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	int								result;
	DWORD							dwFlags = 0;
	System::IO::MemoryStream		^ms;
	CHAR							hexSHA1[(GCFOS_SHA1_LEN * 2)+1];
	CHAR							objectname[128];
	System::String					^objectname_S;
	int								rc;
	GCFOS_RESIDENT_ENTRY			residentEntry;
	GCFOS_WANTED_ENTRY				wantedEntry;
	gcfosdbTxn						*txn;

	if(context->bHdr == false)
		{
		if(dwLen > context->remaining)
			{
			DEBUGLOG_L(1, ("ReceiveHashChainFromContributor data overflow %u:%u\n", dwLen, context->remaining));
			CloseConnection(context);
			return;
			}
		System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(context->buffer.buf), context->object_buffer, context->outputOffset, dwLen);
		context->outputOffset += dwLen;
		context->remaining -= dwLen;
		if(context->remaining == 0)
			{
			tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexSHA1);
			sprintf_s(objectname, "%s-%08x/h", hexSHA1, context->size);
			objectname_S = gcnew System::String(objectname);
			ms = gcnew System::IO::MemoryStream(context->object_buffer);
			if(g_Repo->Put(objectname_S, ms, g_Repo2))
				{
				// signal that this file is now resident
				rc = gcfosdb::BeginTxn(NULL, &txn, 0);
				if(rc == 0)
					{
					memcpy(residentEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
					residentEntry.size = context->size;
					g_Resident->insert(&residentEntry, txn);
					// Signal that this file is no longer wanted
					memcpy(wantedEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
					wantedEntry.size = context->size;
					g_Wanted->erase(&wantedEntry, txn);
					context->count_donations++;
					// now inform client that file has been received successfully
					rc = gcfosdb::CommitTxn(txn);
					if(rc == MDB_MAP_FULL)
						{
						gcfosdb::ResizeLMDB(&txn);
						gcfosdb::AbortTxn(txn);
						DEBUGLOG_L(2, ("%s: ReceiveHashChainFromContributor: txn failed --resized\n", context->connectedToHost));
						}
					else if(rc != 0)
						{
						DEBUGLOG_L(2, ("%s: ReceiveHashChainFromContributor: commit txn failed %d\n", context->connectedToHost, rc));
						}
					}
				else
					{
					DEBUGLOG_L(2, ("%s: ReceiveHashChainFromContributor: begin txn failed %d\n", context->connectedToHost, rc));
					}
				}
			delete ms;
			context->object_buffer = nullptr;
			context->count_donations++;
			RequestCommand(context);
			return;
			}
		}

	// Request more data from the contributor
	context->buffer.len = context->remaining > GCFOS_BUFSIZE ? GCFOS_BUFSIZE : context->remaining;
	context->bHdr = false;
	result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
	if(result == SOCKET_ERROR)
		{
		if(ERROR_IO_PENDING != WSAGetLastError())
			{
			DEBUGLOG_L(1, ("ReceiveHashChainFromContributor WSARecv error: %d\n", WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	return;
	}

void ReceiveFileFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_CONTRIBUTE_FILE contributeFile = (PGCFOS_REQUEST_CONTRIBUTE_FILE) context->buffer.buf;
	DWORD							dwFlags = 0;
	GCFOS_WANTED_ENTRY				wantedEntry;
	int								rc;
	CHAR							objectname[128];
	System::String					^objectname_S;
	CHAR							hexSHA1[(GCFOS_SHA1_LEN * 2)+1];
	array<System::Byte>				^object_buffer;
	int								ctxsize;

	if(context->client == 0)
		{
		DEBUGLOG_L(2, ("%s: unauthorized client attempting file contribution\n", context->connectedToHost));
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	contributeFile->filename[contributeFile->filenamelen] = 0; // Put extra null byte for termination
	memcpy(context->SHA1, contributeFile->SHA1Bytes, GCFOS_SHA1_LEN);
	tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexSHA1);
	context->size = contributeFile->size;

	// Make sure this entry is still WANTED
	memcpy(wantedEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
	wantedEntry.size = context->size;
	rc = g_Wanted->find(&wantedEntry);
	if(rc != 0)
		{
#ifdef ULTRABAC_CLOUD_USE
		if(context->client == 1 && (contributeFile->flags & GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_FORCE))
			{
			DEBUGLOG_L(5, ("%s: Accepting unwanted (forced) donation from admin client\n", context->connectedToHost));
			// allow the addition
			}
		else
#else
		if(contributeFile->flags & GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_FORCE)
			{
			DEBUGLOG_L(3, ("%s: Accepting forced donation for file %s-%08x - %s\n", context->connectedToHost, hexSHA1, context->size, contributeFile->filename));
			}
		else
#endif//ULTRABAC_CLOUD_USE
			{
			// this file IS NOT wanted -- inform client 
			DEBUGLOG_L(2, ("%s: Client attempting to donate unwanted file %s-%08x - %s\n", context->connectedToHost, hexSHA1, context->size, contributeFile->filename));
			SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
			return;
			}
		}
	if(dwLen != (DWORD)(FIELD_OFFSET(GCFOS_REQUEST_CONTRIBUTE_FILE, filename) + contributeFile->filenamelen))
		{
		DEBUGLOG_L(3, ("%u: Incorrect length received for contribution attempt(%u)\n", context->connectedToHost, dwLen));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}
	context->offset = 0;
	context->outputOffset = 0;
	context->remaining = sizeof(context->hdr);
	context->bHdr = true;
	context->time = GetTickCount();
	context->InError = false;

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
	if(context->ContextForCalculatedHash != NULL)
		{
		delete[] (Ipp8u*)context->ContextForCalculatedHash;
		context->ContextForCalculatedHash = NULL;
		}

	DEBUGLOG_L(4, ("%s: Accepting %s-%08x - %s\n", context->connectedToHost, hexSHA1, context->size, contributeFile->filename));
	if(contributeFile->filenamelen > 0)
		{
		// Store the "-name" file in S3 now
		sprintf_s(objectname, "%s-%08x/-name", hexSHA1, context->size);
		objectname_S = gcnew System::String(objectname);
		object_buffer = gcnew array<System::Byte>(contributeFile->filenamelen + 1);
		System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(contributeFile->filename), object_buffer, 0, System::Int32(contributeFile->filenamelen));
		object_buffer[contributeFile->filenamelen] = 0; // null-terminate filename string
		System::IO::MemoryStream ^ms = gcnew System::IO::MemoryStream(object_buffer);

		if(!g_Repo->Put(objectname_S, ms, g_Repo2))
			{
			DEBUGLOG_L(1, ("%s: ReceiveFileFromContributor failed to store name %s\n", context->connectedToHost, objectname));
			}
		}

	if(contributeFile->flags & GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_HASHCHAIN)
		{
		// we are NOT going to store the file that is contributed, but rather a string of hashes into the block
		// store to represent the file. This will take up less space.
		context->remaining = (context->size / GCFOS_BLOCK_SIZE) * GCFOS_BLOCK_HASH_LEN;
		if(context->size % GCFOS_BLOCK_SIZE > 0)
			{
			if((context->size % GCFOS_BLOCK_SIZE) < GCFOS_MINIMUM_BLOCK_SIZE)
				{
				context->remaining += context->size % GCFOS_BLOCK_SIZE;
				}
			else
				{
				context->remaining += GCFOS_BLOCK_HASH_LEN;
				}
			}
		context->object_buffer = gcnew array<System::Byte>(context->remaining);
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK, IOCP_OP_WRITING_HASHCHAIN);
		return;
		}

	ippsHashGetSize(&ctxsize);
	context->ContextForCalculatedHash = (IppsHashState*)( new Ipp8u [ctxsize]);
	ippsHashInit(context->ContextForCalculatedHash, IPP_ALG_HASH_SHA1);


#if 0
	// Enable delay (disable TCP_NODELAY) - the "default" behavior is more appropriate
	// when sending large blocks (Nagle algorithm should enhance performance)
	DWORD							result;
	result = setsockopt(context->s_acc, IPPROTO_TCP, TCP_NODELAY, (char *)&g_nZero, sizeof(g_nZero));
	if(result == SOCKET_ERROR)
		{
		DEBUGLOG_L(2, ("ReceiveFileFromContributor: setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
		}
#endif

	// Note GCFOS_CLIENT_SRC_BUFSIZE use as the buffer size here is intentional
	context->inputBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(context->inputBuffer == NULL)
		{
		DEBUGLOG_L(1, ("%s: ReceiveFileFromContributor failed to allocate buffer\n", context->connectedToHost));
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}
	context->decompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_DST_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(context->decompressedBuffer == NULL)
		{
		DEBUGLOG_L(1, ("%s: ReceiveFileFromContributor failed to allocate buffer\n", context->connectedToHost));
		VirtualFree(context->inputBuffer, 0, MEM_RELEASE);
		context->inputBuffer = NULL;
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
		return;
		}

	// tell client that we want the file and we're ready to receive
	// now send a result back to client
	SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_OK, IOCP_OP_WRITING_DATABLOCK);
	return;
	}

void ReceiveDatablockFromContributor(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	LPBYTE				p = (LPBYTE)context->buffer.buf;
	Ipp32u				bytes;
	System::String		^objectname_S;
	CHAR				objectname[128];
	DWORD				result;
	DWORD				dwFlags = 0;
	CHAR				hexSHA1[(GCFOS_SHA1_LEN * 2)+1];
	GCFOS_WANTED_ENTRY	wantedEntry;
	GCFOS_RESIDENT_ENTRY residentEntry;
	UINT32				closetime;
	FLOAT				copyrate;
	IppStatus			iDecompressionStatus;
	Ipp32u				uncompsize;
	Ipp8u				CalcSHA1[GCFOS_SHA1_LEN];
	GCFOS_SRV_RESPONSE	srv_response;
	int					rc;
	gcfosdbTxn			*txn;

	if(context->client == 0)
		{
		// invalid state
		// ban ip
		BanIP(context);
		CloseConnection(context);
		return;
		}

	while(true)
		{
		if(context->InError)
			{
			if(context->remaining != UINT32_MAX)
				{
				context->remaining = UINT32_MAX;
				SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_ERROR);
				}
			return;
			}

		if(context->op == IOCP_OP_WRITING_DATABLOCK)
			{
			// Check to see if the final WRITE is being completed now
			if(context->offset == context->size)
				{
				// we're all done now with all of the parts of this file
				// Free the resources --
				tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexSHA1);

				closetime = GetTickCount();
				if(closetime == context->time)
					closetime++; // prevent divide-by-zero
				copyrate = (FLOAT)context->size / (FLOAT)(closetime - context->time) / 1024.0f; // Now MB/s
				DEBUGLOG_L(4, ("Received: %s:%08x - %0.2f MB/s\n", hexSHA1, context->size, copyrate));

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
				if(context->InError == false)
					{
					ippsHashFinal(CalcSHA1, context->ContextForCalculatedHash);
					if(memcmp(&CalcSHA1, &context->SHA1, GCFOS_SHA1_LEN) != 0)
						{
						DEBUGLOG_L(2, ("ReceiveDatablockFromContributor: Calculated hash differs from expected, abandoning donation from %s\n", context->connectedToHost));
						context->InError = true;
						}
					delete[] (Ipp8u*)context->ContextForCalculatedHash;
					context->ContextForCalculatedHash = NULL;				
					}
				srv_response = GCFOS_SRV_RESP_ERROR;
				if(context->InError == false)
					{
					// signal that this file is now resident
					rc = gcfosdb::BeginTxn(NULL, &txn, 0);
					if(rc == 0)
						{
						memcpy(residentEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
						residentEntry.size = context->size;
						g_Resident->insert(&residentEntry, txn);
						// Signal that this file is no longer wanted
						memcpy(wantedEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
						wantedEntry.size = context->size;
						g_Wanted->erase(&wantedEntry, txn);
						context->count_donations++;
						// now inform client that file has been received successfully
						rc = gcfosdb::CommitTxn(txn);
						if(rc == MDB_MAP_FULL)
							{
							gcfosdb::ResizeLMDB(&txn);
							gcfosdb::AbortTxn(txn);
							DEBUGLOG_L(2, ("%s: ReceiveDatablockFromContributor: txn failed --resized\n", context->connectedToHost));
							}
						else if(rc == 0)
							{
							srv_response = GCFOS_SRV_RESP_OK;
							}
						else
							{
							DEBUGLOG_L(2, ("%s: ReceiveDatablockFromContributor: commit txn failed %d\n", context->connectedToHost, rc));
							}
						}
					else
						{
						DEBUGLOG_L(2, ("%s: ReceiveDatablockFromContributor: begin txn failed %d\n", context->connectedToHost, rc));
						}
					}

				SendSimpleResponseToClient(context, tid, key, srv_response);
				return;
				}

			// Request more data from the contributor
			context->op	= IOCP_OP_WAITING_DATABLOCK;
			context->remaining = sizeof(context->hdr);
			context->buffer.len = context->remaining;
			context->bHdr = true;
			result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
			if(result == SOCKET_ERROR)
				{
				if(ERROR_IO_PENDING != WSAGetLastError())
					{
					DEBUGLOG_L(1, ("ReceiveDatablockFromContributor WSARecv error: %d\n", WSAGetLastError()));
					CloseConnection(context);
					return;
					}
				}
			return;
			}

		if(context->bHdr)
			{
			if(dwLen > context->remaining)
				bytes = context->remaining;
			else
				bytes = dwLen;

			memcpy(&context->hdr, p, bytes);
			dwLen -= bytes;
			context->remaining -= bytes;
			p += bytes;
			if(context->remaining == 0)
				{
				if(context->hdr.type != GCFOS_REQ_CONTRIBUTE_DATABLOCK
				|| (context->hdr.blocksize & GCFOS_COMPRESSED_BITMASK) > GCFOS_CLIENT_SRC_BUFSIZE)
					{
					DEBUGLOG_L(1, ("ReceiveDatablockFromContributor: Invalid data hdr for %s\n", objectname));
					context->InError = true;
					continue; // this will invoke error processing
					}
				context->bHdr = false;
				if(context->hdr.blocksize & GCFOS_COMPRESSED_BIT)
					{
					context->bCompressed = true;
					context->remaining = context->hdr.blocksize & GCFOS_COMPRESSED_BITMASK;
					}
				else
					{
					context->bCompressed = false;
					context->remaining = context->hdr.blocksize;
					}
				context->outputOffset = 0;
				}
			}

		if(dwLen > context->remaining)
			bytes = context->remaining;
		else
			bytes = dwLen;

		if(context->outputOffset + bytes > GCFOS_CLIENT_SRC_BUFSIZE)
			{
			_CrtDbgBreak();
			}

		context->remaining -= bytes;
		memcpy(context->inputBuffer + context->outputOffset, p, bytes);
		context->outputOffset += bytes;
		
		p += bytes;
		dwLen -= bytes;

		if(context->remaining == 0)
			{
			if(context->InError == false)
				{
				_ASSERTE(context->inputBuffer != NULL);
				// write the data for this block
				context->op	= IOCP_OP_WRITING_DATABLOCK;

				tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexSHA1);
				// object name will be ordinal of 1MB chunks -- from 000 to fff (if it was a 4gb file)
				sprintf_s(objectname, "%s-%08x/%03x%c", hexSHA1, context->size, (context->offset / GCFOS_CLIENT_SRC_BUFSIZE), (context->bCompressed ? 'c' : 'n'));
				if(dwLen != 0)
					{
					DEBUGLOG_L(1, ("ReceiveDatablockFromContributor: Data overrun detected for %s\n", objectname));
					}
				objectname_S = gcnew System::String(objectname);
				array<System::Byte> ^object_buffer = gcnew array<System::Byte>(context->outputOffset);
				System::Runtime::InteropServices::Marshal::Copy(System::IntPtr(context->inputBuffer), object_buffer, 0, System::Int32(context->outputOffset)); 
				System::IO::MemoryStream ^ms = gcnew System::IO::MemoryStream(object_buffer);
				context->offset += context->hdr.uncompSize;

				if(!g_Repo->Put(objectname_S, ms, g_Repo2))
					{
					DEBUGLOG_L(1, ("ReceiveDatablockFromContributor: Error during PutObject for %s", objectname));
					// undo the buffer changes to force re-send of this object needed
					context->InError = true;
					}
				if(context->hdr.blocksize & GCFOS_COMPRESSED_BIT)
					{
					uncompsize = GCFOS_CLIENT_DST_BUFSIZE;
					iDecompressionStatus = ippsDecodeLZOSafe_8u(context->inputBuffer, context->hdr.blocksize & GCFOS_COMPRESSED_BITMASK, context->decompressedBuffer, &uncompsize);
					if(iDecompressionStatus != ippStsNoErr || uncompsize != context->hdr.uncompSize)
						{
						DEBUGLOG_L(1, ("ReceiveDatablockFromContributor: Decompression error for %s", objectname));
						context->InError = true;
						}
					else
						{
						ippsHashUpdate(context->decompressedBuffer, uncompsize, context->ContextForCalculatedHash);
						}
					}
				else
					{
					ippsHashUpdate(context->inputBuffer, context->hdr.blocksize, context->ContextForCalculatedHash);
					}
				}
			// We need another header now
			continue;
			}

		if(dwLen == 0)
			{
			// Request more data from the contributor
			context->op	= IOCP_OP_WAITING_DATABLOCK;
			context->buffer.len = (context->remaining > GCFOS_BUFSIZE ? GCFOS_BUFSIZE : context->remaining);
			result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
			if(result == SOCKET_ERROR)
				{
				if(ERROR_IO_PENDING != WSAGetLastError())
					{
					DEBUGLOG_L(1, ("ReceiveDatablockFromContributor Req WSARecv error: %d\n", WSAGetLastError()));
					CloseConnection(context);
					return;
					}
				}
			return;
			}
		}
	}


void ProcessQuery(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_REQUEST_QUERY	req = (PGCFOS_REQUEST_QUERY) context->buffer.buf;
	GCFOS_RESIDENT_ENTRY	residentEntry;
	GCFOS_LIMBO_ENTRY		limboEntry;
	GCFOS_LIMBO_2_ENTRY		limbo2Entry;
	GCFOS_WANTED_ENTRY		wantedEntry;
	GCFOS_UPDATE_ENTRY		updateEntry;
	GCFOS_SRV_QUERY_RESPONSE QueryResp;
	gcfosdbTxn				*txn;
	int						rc;
	char					hexstring[GCFOS_SHA1_LEN * 2 + 1];
	System::Collections::Generic::List<System::String ^> ^names = gcnew System::Collections::Generic::List<System::String ^>; 
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;

	memset(&QueryResp, 0, sizeof(GCFOS_SRV_QUERY_RESPONSE));

	QueryResp.Response = GCFOS_SRV_RESP_ERROR;

	if(context->client == 0)
		{
		QueryResp.Response = GCFOS_SRV_RESP_NOTAUTH;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		// ban ip
		BanIP(context);
		DEBUGLOG_L(2, ("%s: Request received from unauthorized client\n", context->connectedToHost));
		CloseConnection(context);
		return;
		}
	if(!g_bDedupeFiles)
		{
		SendSimpleResponseToClient(context, tid, key, GCFOS_SRV_RESP_NOT_CONFIGURED);
		return;
		}

	// query ResidentList to see if we have this file

	if(g_debugLvl > 3)
		{
		tohex_A(req->SHA1Bytes, GCFOS_SHA1_LEN, hexstring);
		DEBUGLOG_L(5, ("%s: Request received for %s:%08x\n", context->connectedToHost, hexstring, req->size));
		}

	if(req->size < GCFOS_FILE_MINIMUM_SIZE)
		{
		// send error -- invalid size
		DEBUGLOG_L(5, ("%s: Rejecting invalid size query %08x\n", context->connectedToHost, req->size));
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}

	context->count_queries++;

	memcpy(context->SHA1, req->SHA1Bytes, GCFOS_SHA1_LEN);
	context->size = req->size;

	memcpy(residentEntry.SHA1, req->SHA1Bytes, GCFOS_SHA1_LEN);
	residentEntry.size = req->size;
	
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("%s: ProcessQuery failed start txn %d\n", context->connectedToHost, rc));
		QueryResp.Response = GCFOS_SRV_RESP_ERROR;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}

	rc = g_Resident->find(&residentEntry, txn);
	if(rc == 0)
		{

		System::String								^myprefix, ^firstpart;
		char										hexstr[(GCFOS_SHA1_LEN * 2)+1];
		bool										bfound = false;

		gcfosdb::AbortTxn(txn); // cheaper(?) to abort, no writes possible at this point

		tohex_A(context->SHA1, GCFOS_SHA1_LEN, hexstr);
		myprefix =  gcnew System::String(hexstr);
		sprintf_s(hexstr, 9, "%08x", context->size);
		System::String ^sizehex = gcnew System::String(hexstr);
		myprefix += "-";
		myprefix += sizehex;
		firstpart = myprefix;
		context->count_resident_hits++;
#if 0
		//KLUDGE FIX !! ! ! ! !! 
		//before responding RESIDENT, need to see if S3 holds uncompressed data -- if so, re-request the file
		//(after deleting all S3 objects for this SHA1) (the client had a bug and was not compressing data
		//file).
		myprefix = firstpart;
		myprefix += "/";
		g_Repo->GetList(myprefix, names, sizes, g_Repo2);

		if(names->Count < 2)
			{
			DEBUGLOG_L(4, ("Files not present for %s - rerequesting\n", myprefix));
			g_Resident->erase(&residentEntry);
			memcpy(wantedEntry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
			wantedEntry.size = context->size;
			g_Wanted->insert(&wantedEntry);
			DoDeleteObjects(context, tid, key, dwLen);
			gcfosdb::AbortTxn(txn); // cheaper(?) to abort, no writes possible at this point
			QueryResp.Response = GCFOS_SRV_RESP_WANTED;
			SendQueryResponseToClient(context, tid, key, &QueryResp);
			return;
			}
#endif
		// this file IS resident -- inform client 
		QueryResp.Response = GCFOS_SRV_RESP_RESIDENT;
		delete sizehex;

#if 0
		// Temp feature -- if filename is missing, request it
		// TODO: Remove this code, as the filename object will be stored in the Repository at contribution-time
		System::String			^name;

		myprefix = firstpart;
		myprefix += "/-name";
		g_Repo->GetList(myprefix, names, sizes, g_Repo2);

		bfound = false;
		for each (^name in names)
			{			
			if(sizes[0] > 0)
				bfound = true;
			break;
			}

		if(bfound == false)
			{
			QueryResp.Response = GCFOS_SRV_RESP_WANT_FILENAME;
			}
#endif
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}

	// find if this file is WANTED
	memcpy(wantedEntry.SHA1, req->SHA1Bytes, GCFOS_SHA1_LEN);
	wantedEntry.size = req->size;
	rc = g_Wanted->find(&wantedEntry, txn);
	if(rc == 0)
		{
		gcfosdb::AbortTxn(txn); // cheaper(?) to abort, no writes possible at this point
		// this file IS wanted -- inform client 
		QueryResp.Response = GCFOS_SRV_RESP_WANTED;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}

	// Don't consider this file in limbo if the client connected is 
	// the administrator (when running on UB's cloud)

#ifdef ULTRABAC_CLOUD_USE
	if(CONTEXT_IS_ADMIN)
		{
		gcfosdb::AbortTxn(txn); // cheaper(?) to abort, no writes possible at this point
		QueryResp.Response = GCFOS_SRV_RESP_LIMBO;
		context->count_limbo_results++;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}
#endif

	// no need to determine if file is already in limbo db -- 
	// we'll just insert a record. We'll NOT overwrite the existing
	// record so that the record keeps the OLD date. The thinking here
	// is that the clock has already started on this file, and it would be
	// expected that it would be backed up again from the same client, so
	// backups from the same client should not re-start the clock. If no
	// other clients sufficient to trigger wanted-status occurs, then this
	// file can be considerered to be unique to this client.
	
retry_insertLimbo:
	memcpy(limboEntry.SHA1, req->SHA1Bytes, GCFOS_SHA1_LEN);
	limboEntry.size = req->size;
	limboEntry.client = context->client;

	// add to our "limbo list"
	limboEntry.whenAdded.ObtainTimeNow();
	rc = g_Limbo->insert(&limboEntry, txn, 0, gcfosdb_NOOVERWRITE);
	if(rc == MDB_MAP_FULL)
		{
		gcfosdb::ResizeLMDB(&txn);
		goto retry_insertLimbo;
		}

	if(rc != 0 && rc != gcfosdb_KEYEXIST)
		{
		DEBUGLOG_L(1, ("%s: ProcessQuery failed to insert rec to limbo (%d)\n", context->connectedToHost, rc));
		gcfosdb::AbortTxn(txn);
		QueryResp.Response = GCFOS_SRV_RESP_ERROR;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}
	limbo2Entry.client = limboEntry.client;
	limbo2Entry.size = limboEntry.size;
	memcpy(limbo2Entry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
	limbo2Entry.whenAdded = limboEntry.whenAdded;
	rc = g_Limbo2->insert(&limbo2Entry, txn, 0, gcfosdb_NOOVERWRITE);
	if(rc == MDB_MAP_FULL)
		{
		gcfosdb::ResizeLMDB(&txn);
		goto retry_insertLimbo;
		}
	if(rc != 0 && rc != gcfosdb_KEYEXIST)
		{
		DEBUGLOG_L(1, ("%s: ProcessQuery failed to insert rec to limbo2 (%d)\n", context->connectedToHost, rc));
		gcfosdb::AbortTxn(txn);
		QueryResp.Response = GCFOS_SRV_RESP_ERROR;
		SendQueryResponseToClient(context, tid, key, &QueryResp);
		return;
		}

	// add to our "update list" -- this will check to see if sufficient
	// instances have been encountered to qualify this file as wanted
	memcpy(updateEntry.SHA1, req->SHA1Bytes, GCFOS_SHA1_LEN);
	updateEntry.size = req->size;
	updateEntry.rec = 0;
	//rc = g_Update->insert(&updateEntry, txn);
	QueryResp.Response = GCFOS_SRV_RESP_LIMBO; // this might be changed to WANTED by ProcessUpdate()
	rc = ProcessUpdate(&updateEntry, txn, &QueryResp.Response);
	if(rc == MDB_MAP_FULL)
		{
		gcfosdb::ResizeLMDB(&txn);
		goto retry_insertLimbo;
		}
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("%s: ProcessQuery failed to process update record %d\n", context->connectedToHost, rc));
		gcfosdb::AbortTxn(txn);
		QueryResp.Response = GCFOS_SRV_RESP_ERROR;
		}
	else
		{
		rc = gcfosdb::CommitTxn(txn);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("%s: ProcessQuery failed to commit txn %d\n", context->connectedToHost, rc));
			}
		}
	context->count_limbo_results++;
	SendQueryResponseToClient(context, tid, key, &QueryResp);
	return;
	}

void SendSimpleResponseToClient(PGCFOS_CONNECT_STATE context,UINT32 tid, ULONG_PTR key, const GCFOS_SRV_RESPONSE res, IOCP_OP_TYPE newop /*= IOCP_OP_SENT_FINAL_RESPONSE*/)
	{
	DWORD				dwLen = 0;

	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_SRV_RESPONSE);
	*(PGCFOS_SRV_RESPONSE)(context->buffer.buf) = res;

	context->op = newop;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: SendSimpleResponseToClient failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

void SendQueryResponseToClient(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, PGCFOS_SRV_QUERY_RESPONSE pResponse)
	{
	DWORD				dwLen = 0;

	// now send a result back to client
	context->buffer.len = sizeof(GCFOS_SRV_QUERY_RESPONSE);
	memcpy(context->buffer.buf, pResponse, sizeof(GCFOS_SRV_QUERY_RESPONSE));

	context->op = IOCP_OP_SENT_FINAL_RESPONSE;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: SendQueryResponseToClient failed to send query result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}


void ProcessAccept(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	DWORD				result;
	PGCFOS_CONNECT_STATE newcontext;
	bool				bBanned = false;

	result = setsockopt(context->s_acc, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&g_ListenState[key].s_list, sizeof(SOCKET));

	if(result == SOCKET_ERROR)
		{
		DEBUGLOG_L(2, ("ProcessAccept: setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed: %d\n", WSAGetLastError()));
		}

	context->connectedToLen = sizeof(context->connectedTo);
	result = getpeername(context->s_acc, &context->connectedTo, &context->connectedToLen);
	getnameinfo(&context->connectedTo, context->connectedToLen, context->connectedToHost, sizeof(context->connectedToHost), NULL, 0, NI_NUMERICHOST);

#ifdef ULTRABAC_CLOUD_USE
	if(IsBannedIP(context))
		{
		DEBUGLOG_L(2, ("ProcessAccept: banned IP %s recognized\n", context->connectedToHost));
		bBanned = true;
		}
#endif//ULTRABAC_CLOUD_USE

	// Disable delay
	result = setsockopt(context->s_acc, IPPROTO_TCP, TCP_NODELAY, (char *)&g_nOne, sizeof(g_nOne));
	if(result == SOCKET_ERROR)
		{
		DEBUGLOG(("ProcessAccept: setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
		}

	// This call takes too long:
	//getnameinfo(&context->connectedTo, context->connectedToLen, context->connectedToHostStr, sizeof(context->connectedToHostStr), NULL, 0, 0);

	// Check if server is too busy to process this accept
	if(bBanned)
		{
		CloseConnection(context);
		// carry on -- we need another accept pending
		}
	else
		{
		DEBUGLOG_L(4, ("Accepting connection on %s from %s\n", g_ListenState[key].hostid, context->connectedToHost));
		}
				
	// prepare another socket for accepting another session
	// create another accept socket now
	SOCKET acc;
	acc = WSASocket(g_ListenState[key].ai_family, g_ListenState[key].ai_socktype, g_ListenState[key].ai_protocol, NULL, NULL, WSA_FLAG_OVERLAPPED);
	if(acc == INVALID_SOCKET)
		{
		DEBUGLOG_L(1, ("ProcessAccept: WSASocket failed. Error: %d\n", WSAGetLastError()));
		return;
		}

	// Disable output buffering
#if 0
	result = setsockopt(acc, SOL_SOCKET, SO_SNDBUF, (char *)&g_nZero, sizeof(g_nZero));
	if(result == SOCKET_ERROR)
		{
		DEBUGLOG(("setsockopt(SNDBUF) failed: %d\n", WSAGetLastError()));
		}
#endif
	// Disable delay
	result = setsockopt(acc, IPPROTO_TCP, TCP_NODELAY, (char *)&g_nOne, sizeof(g_nOne));
	if(result == SOCKET_ERROR)
		{
		DEBUGLOG(("ProcessAccept: setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
		}

	g_hIOCP = CreateIoCompletionPort((HANDLE)acc, g_hIOCP, key, 0);
	newcontext = new GCFOS_CONNECT_STATE();
	newcontext->op = IOCP_OP_ACCEPT;
	newcontext->status = STATE_ACCEPT;
	newcontext->s_acc = acc;
	newcontext->session_record = 0; // accept sesions do not have a session record
	newcontext->activityTimer = GCFOS_INITIAL_ACTIVITY_VALUE;
	EnterCriticalSection(&g_csConnections);
	g_ConnectState.insert(newcontext);
	LeaveCriticalSection(&g_csConnections);
	result = g_ListenState[key].fnAcceptEx(g_ListenState[key].s_list, acc,
					(PVOID)(newcontext->buffer.buf + 0x100),
					0,
					sizeof(SOCKADDR_STORAGE) + 16,
					sizeof(SOCKADDR_STORAGE) + 16,
					&dwLen, 
					&newcontext->o);
	if(dwLen != 0)
		{
		DEBUGLOG(("Warning - AcceptEx returned data (%u)\n", dwLen));
		}
	if(result == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError()) )
		{
		DEBUGLOG_L(2, ("ProcessAccept: AcceptEx() failed: %d\n", WSAGetLastError()));
		closesocket(acc);
		}

	context->client = 0; // indicate NOT AUTHORIZED yet
	context->status = STATE_CONNECTED;

	if(bBanned)
		{
		return;
		}

	// now request (read) the first command for this socket
	RequestCommand(context); // this command processed - request another
	}

void RequestCommand(PGCFOS_CONNECT_STATE context)
	{
	DWORD				result;
	DWORD				dwFlags = 0;
	DWORD				dwLen;

	context->buffer.len = GCFOS_BUFSIZE; // Make sure that no requests can be larger..

	context->op = IOCP_OP_WAITING_REQUEST;
	context->remaining = 0;
	context->offset = 0;

	result = WSARecv(context->s_acc, &context->buffer, 1, &dwLen, &dwFlags, (LPWSAOVERLAPPED)&context->o, NULL);
	if(result == SOCKET_ERROR)
		{
		if(ERROR_IO_PENDING != WSAGetLastError())
			{
			DEBUGLOG(("RequestCommand WSARecv error: %d\n", WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	return;
	}

void CloseConnection(PGCFOS_CONNECT_STATE context, GCFOS_SESSION_END_REASON reason/*= FORCED*/)
	{
	if(g_Sessions != NULL)
		{
		UpdateSessionRecord(context, reason);
		}

	EnterCriticalSection(&g_csConnections);
	g_ConnectState.erase(context);
	LeaveCriticalSection(&g_csConnections);
	delete context;
	return;
	}

void ProcessLCUDBlock(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	context->op = IOCP_OP_SENDING_LCUD;

	// Handle special case where remaining==0 this indicate an EMPTY LCUD db, but we need
	// to send at least the header (UINT64) that indicates #of records.

	if(context->remaining > 0 && context->offset >= context->pLCUD->Size())
		{
		// all done, get next command
		delete context->pLCUD;
		context->pLCUD = NULL;
		RequestCommand(context);
		return;
		}

	context->pLCUD->PackToMemory(context);

	context->buffer.len = GCFOS_BUFSIZE - context->remaining;
	if(WSASend(context->s_acc, &context->buffer, 1, &dwLen, 0, &context->o, NULL) == SOCKET_ERROR)
		{
		if(WSAGetLastError() != ERROR_IO_PENDING)
			{
			DEBUGLOG(("%s: ProcessLCUDBlock failed to send result to client (%u)\n", context->connectedToHost, WSAGetLastError()));
			CloseConnection(context);
			return;
			}
		}
	}

void ProcessLCUDRequest(PGCFOS_CONNECT_STATE context, UINT32 tid, ULONG_PTR key, DWORD dwLen)
	{
	PGCFOS_LCUD_REQUEST			req = (PGCFOS_LCUD_REQUEST)context->buffer.buf;
	bool						status;

	if(context->pLCUD != NULL)
		delete context->pLCUD;

	context->pLCUD = new Hash_FileManager<GCFOS_LOCAL_ENTRY>;
	if(context->pLCUD == NULL)
		{
		// this is an error condition -- can't indicate failure back to caller, so just request
		// another command.
		RequestCommand(context);
		return;
		}
	if(req->MySequenceNo == GCFOS_LCUD_NOT_PRESENT || req->MySequenceNo < 2)
		{
		status = context->pLCUD->Load(context->client);
		}
	else
		{
		status = context->pLCUD->LoadRange(context->client, req->MySequenceNo);
		}

	if(status == false)
		{
		RequestCommand(context);
		return;
		}
	context->offset = 0;
	context->size = 0;
	context->remaining = 0; // Indicates that NO DATA has yet been sent to client
	memset(&context->SHA1, 0, GCFOS_SHA1_LEN);
	ProcessLCUDBlock(context, tid, key, dwLen);
	return;
	}

bool IsRunningAsService()
{
	PROCESSENTRY32	PID;
	bool			bService = false;
	HANDLE			hProcessSnapshot;
	DWORD			dwParentId = 0;
	DWORD			dwThisProcessID = GetCurrentProcessId();
	
	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnapshot != INVALID_HANDLE_VALUE)
		{
		PID.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hProcessSnapshot, &PID))
			{
			while(true)
				{
				if(dwParentId && dwParentId == PID.th32ProcessID)
					{
					if(_tcsicmp(PID.szExeFile, L"services.exe") == 0)
						{
						bService = true;
						}
					break;
					}
				else if(dwThisProcessID == PID.th32ProcessID)
					{
					dwParentId = PID.th32ParentProcessID;
					Process32First(hProcessSnapshot, &PID); // re-start from beginning
					}
				if(!Process32Next(hProcessSnapshot, &PID))
					break;
				}
			}
		CloseHandle(hProcessSnapshot);
		}

	return bService;
}


void GCFOS_CtrlHandler(DWORD dwCtrl)
	{
	InterlockedIncrement(&g_ThreadsActive);

	switch(dwCtrl) 
		{  
		case SERVICE_CONTROL_STOP: 
			g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus(g_SvcStatusHandle, &g_ServiceStatus);

			// Signal the service to stop.

			SetEvent(g_ExitSignalled);
			while(g_ThreadsActive > 1)
				{
				Sleep(100);
				}

			g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(g_SvcStatusHandle, &g_ServiceStatus);
			break;

		default: 
		case SERVICE_CONTROL_INTERROGATE: 
			break; 
		} 

	InterlockedDecrement(&g_ThreadsActive);
	}


VOID WINAPI GCFOS_ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
	{
    // Register the handler function for the service

	g_SvcStatusHandle = RegisterServiceCtrlHandler(_T(GCFOS_SERVICE_NAME), GCFOS_CtrlHandler);

    if(!g_SvcStatusHandle)
	    { 
        DEBUGLOG_L(1, ("RegisterServiceCtrlHandler error %d\n", GetLastError())); 
        return; 
		} 

    // Report initial status to the SCM
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	SetServiceStatus(g_SvcStatusHandle, &g_ServiceStatus);
}

void __cdecl ServiceThreadBegin(void *unused)
	{
	SERVICE_TABLE_ENTRY DispatchTable[] = { 
			{ _T(GCFOS_SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION) GCFOS_ServiceMain }, 
			{ NULL, NULL } 
		}; 	

	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;
	g_ServiceStatus.dwWaitHint = 500;
		
	if(!StartServiceCtrlDispatcher(DispatchTable))
		{
		DEBUGLOG_L(1, ("StartServiceCtrlDispatcher failed, error %u\n", GetLastError()));
		}
	return;
	}

void VerifyLimboSync()
	{
	UINT64			recordsRead = 0;
	UINT64			missing = 0;
	gcfosdbCursor	*c_limbo;
	GCFOS_LIMBO_2_ENTRY limbo2Entry;
	GCFOS_LIMBO_ENTRY limboEntry;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	int				rc;

	DEBUGLOG_L(1, ("VerifyLimboSync: Entry\n"));

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("VerifyLimboSync: failed to begin txn\n"));
		return;
		}

	if(g_Limbo->createCursor(&c_limbo, 0, txn) != 0)
		{
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("VerifyLimboSync: failed to get limbo cursor\n"));
		return;
		}

	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Limbo->get(c_limbo, (PUCHAR)&limboEntry, getflags, txn);
		getflags = gcfosdb_NEXT;
		if(rc != 0)
			break;
		recordsRead++;
		limbo2Entry.client = limboEntry.client;
		limbo2Entry.size = limboEntry.size;
		memcpy(limbo2Entry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
		rc = g_Limbo2->find(&limbo2Entry, txn);
		if(rc != 0)
			{
			missing++;
			g_Limbo->erase(c_limbo);
			}
		}

	gcfosdb::closeCursor(c_limbo);
	DEBUGLOG_L(1, ("VerifyLimboSync: Complete. LIMBO2 Summary: Total records = %I64u, missing = %I64u\n", recordsRead, missing));

	missing = 0;
	recordsRead = 0;

	if(g_Limbo2->createCursor(&c_limbo, 0, txn) != 0)
		{
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("VerifyLimboSync: failed to get limbo2 cursor\n"));
		return;
		}

	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Limbo2->get(c_limbo, (PUCHAR)&limbo2Entry, getflags, txn);
		getflags = gcfosdb_NEXT;
		if(rc != 0)
			break;
		recordsRead++;
		limboEntry.client = limbo2Entry.client;
		limboEntry.size = limbo2Entry.size;
		memcpy(limboEntry.SHA1, limbo2Entry.SHA1, GCFOS_SHA1_LEN);
		rc = g_Limbo->find(&limboEntry, txn);
		if(rc != 0)
			{
			missing++;
			g_Limbo->erase(c_limbo);
			}
		}

	gcfosdb::closeCursor(c_limbo);

	DEBUGLOG_L(1, ("VerifyLimboSync: Complete. LIMBO Summary: Total records = %I64u, missing = %I64u\n", recordsRead, missing));
	gcfosdb::CommitTxn(txn);
	}

int _tmain(int argc, _TCHAR* argv[])
	{
    int				retVal;
    WSADATA			wsaData;
    struct addrinfo myaddr;
    struct addrinfo *res = NULL;
    struct addrinfo *pAddr;
	char			myinterface;
	char			portListen[] = GCFOS_SERVER_PORT;
	int				i = 0;
	SOCKET			s, acc;
	HANDLE			hThread;
	GUID			acceptex_guid = WSAID_ACCEPTEX; // GUID to Microsoft specific extensions
	GUID			getacceptexsockaddrs_guid = WSAID_GETACCEPTEXSOCKADDRS; //GetAcceptExSockaddrs address (Microsoft-specific)
	DWORD			dwLen;
	HANDLE			hConsole;
	CONSOLE_SCREEN_BUFFER_INFOEX consoleInfo;
	LSTATUS			Result;
	DWORD			dwDefault;
	TCHAR			szAccessKey[128];
	TCHAR			szSecretKey[128];
	TCHAR			szRepoType[64];
	TCHAR			szBucket[256]; // Bucket (or Location)
	TCHAR			szEndpoint[256]; // Service endpoint/URL for repository
	TCHAR			szRegion[64];
	// Secondary/optional second repository:
	TCHAR			szSecondaryAccessKey[64];
	TCHAR			szSecondarySecretKey[64];
	TCHAR			szSecondaryRepoType[64] = { 0 };
	TCHAR			szSecondaryBucket[256] = { 0 }; // Bucket (or Location)
	TCHAR			szSecondaryEndpoint[256] = { 0 }; // Service endpoint/URL for repository
	TCHAR			szSecondaryRegion[64] = { 0 };
	PGCFOS_CONNECT_STATE newcontext;
//	DB_FileManager<GCFOS_UPDATE_ENTRY> UpdateManager;
	CHAR			log_filename[60];
	CHAR			szExeName[MAX_PATH];
	LPSTR			pszLastBackslash;
	BOOL			bEnableServiceDiscovery = TRUE; // create a UDP port for auto-configuration
	GCFOS_BLOCK_ENTRY blockEntry;
	int				rc;
	UINT			NewServerValidation;
	TCHAR			szExplicitIPAddress[64];
	bool			bFoundExplicitIPAddress = false;

	g_ExitSignalled = CreateEvent(NULL, TRUE, FALSE, NULL);

	if(GetModuleFileNameA(NULL, szExeName, sizeof(szExeName)))
		{
		pszLastBackslash = strrchr(szExeName, '\\');
		if(pszLastBackslash)
			{
			*pszLastBackslash = 0;
			SetCurrentDirectoryA(szExeName);
			*pszLastBackslash = '\\';
			}
		}

	InitializeCriticalSection(&g_csDebug);
	g_bIsService = IsRunningAsService();

	if(g_bIsService)
		{
		time_t			timenow;
		struct tm		timeinfo;

		time(&timenow);
		localtime_s(&timeinfo, &timenow);
		strftime(log_filename, sizeof(log_filename), "logs\\svc_%y%m%d.txt", &timeinfo);
		g_DebugLog = _fsopen(log_filename, "a", _SH_DENYWR);

		_beginthread(ServiceThreadBegin, 0, NULL);

		}
	else
		{
		g_DebugLog = stdout;
		}

	for(i = 1; i < argc; i++)
		{
		switch(argv[i][0])
			{
			case '-':
			case '/':
				switch(argv[i][1])
					{
					case 'v':
						g_VerifyOpens = true;
						break;
					default:
						break;
					}
				break;
			default:
				break;
			}
		}

	InitializeCriticalSection(&g_csConnections);
	g_debugLvl = 4;
	g_ThreadsActive = 0;

	g_SessionsOpen = 0;

	DEBUGLOG_L(1, ("GCFOS Server starting, built %s %s\n", __DATE__, __TIME__));
	DEBUGLOG_L(1, ("This software must be used according to license, and is copyright UltraBac Software 2013-2015\n"));

	if(!g_bIsService)
		{
		_set_error_mode(_OUT_TO_MSGBOX);

		hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		consoleInfo.cbSize = sizeof(consoleInfo);
		GetConsoleScreenBufferInfoEx(hConsole, &consoleInfo);

		if(!SetConsoleTitle(L"GCFOS SERVER"))
			{
			DEBUGLOG(("SetConsoleTitle failed error %u\n", GetLastError()));
			}
		}

	retVal = WSAStartup(MAKEWORD(2,2), &wsaData);

	if(retVal != 0)
		{
		DEBUGLOG_L(1, ("WSAStartup failed %d\n", GetLastError()));
		return -1;
		}

	Result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, GCFOS_REGISTRY_KEY, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &g_MyRegistry, NULL);
	if(ERROR_SUCCESS != Result)
		{
		DEBUGLOG_L(1, ("Failed to open registry key at %S, error %d\n", GCFOS_REGISTRY_KEY, Result));
		return -1;
		}
	
	memset(&myaddr, 0, sizeof(myaddr));
    myaddr.ai_family = AF_UNSPEC;
    myaddr.ai_protocol = IPPROTO_TCP;
    myaddr.ai_socktype = SOCK_STREAM;
    myaddr.ai_flags = AI_PASSIVE;

    // getaddrinfo is the protocol independent version of GetHostByName.
    // the res contains the result.
    myinterface = NULL;
	if(getaddrinfo(&myinterface, portListen, &myaddr, &res) != NO_ERROR)
		{
        printf("getaddrinfo failed. Error = %d\n", WSAGetLastError());
        goto CLEANUP;
		}

	g_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	if(INVALID_HANDLE_VALUE == g_hIOCP)
		{
		return -1;
		}

#ifndef ULTRABAC_CLOUD_USE
	// Load registry values to see if redirection is active first
	if(ERROR_SUCCESS == SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_CONFIG_REDIRECT_CLIENT, &g_RedirectionClientID, REG_DWORD, sizeof(GCFOS_CLIENTID), NULL))
		{
		// Borrow szBucket to hold string representation of hex secret key
		if(ERROR_SUCCESS == SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_CONFIG_REDIRECT_SECRET, &szBucket, REG_SZ, sizeof(szBucket), NULL))
			{
			tobin(szBucket, GCFOS_SHARED_KEY_LEN * 2, g_RedirectionSecret);
			g_bRedirectionMode = true;
			DEBUGLOG_L(2, ("Configured for redirection mode (respond-only for configuration), using clientid=%u\n", g_RedirectionClientID));
			if(ERROR_SUCCESS == SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_CONFIG_REDIRECT_SERVER, &g_RedirectionServer, REG_SZ, sizeof(g_RedirectionServer), NULL))
				{
				DEBUGLOG_L(2, ("Redirecting to server: %S\n", g_RedirectionServer));
				}
			else
				{
				g_RedirectionServer[0] = 0; // use the default server
				}
			goto setup_UDP_listener;
			}
		}
#endif//ULTRABAC_CLOUD_USE

	// Load registry configuration details

	if(ERROR_SUCCESS != SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_TYPE, &szRepoType, REG_SZ, sizeof(szRepoType), NULL))
		{
		DEBUGLOG_L(1, ("Repository type not defined in registry - disabling file deduplication\n"));
		g_bDedupeFiles = false;
		}
	else
		{
		g_bDedupeFiles = true;

		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_LOCATION, &szBucket, REG_SZ, sizeof(szBucket), _T(GCFOS_REPOSITORY_BUCKET));
		if(ERROR_SUCCESS != Result)
			{
			return -1;
			}

		szRegion[0] = 0; // no region by default
		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_REGION, &szRegion, REG_SZ, sizeof(szRegion), _T(""));
		if(ERROR_SUCCESS != Result)
			{
			return -1;
			}

		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_ENDPOINT, &szEndpoint, REG_SZ, sizeof(szEndpoint), _T(GCFOS_REPO_DEFAULT_ENDPOINT));
		if(ERROR_SUCCESS != Result)
			{
			return -1;
			}
		if(ERROR_SUCCESS != SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_ACCESS_KEY, &szAccessKey, REG_SZ, sizeof(szAccessKey), NULL))
			{
			szAccessKey[0] = 0;
			}
		if(ERROR_SUCCESS != SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_SECRET_KEY, &szSecretKey, REG_SZ, sizeof(szSecretKey), NULL))
			{
			szSecretKey[0] = 0;
			}

		if(ERROR_SUCCESS != SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_EXPLICIT_IP_ADDRESS, &szExplicitIPAddress, REG_SZ, sizeof(szExplicitIPAddress), NULL))
			{
			szExplicitIPAddress[0] = 0;
			}
		dwDefault = 14;
		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_LIMBO_RETENTION_DAYS, &g_GCFOS_RETENTION_DURATION_DAYS, REG_DWORD, sizeof(DWORD), &dwDefault);
		if(ERROR_SUCCESS != Result)
			{
			return -1;
			}
		if(g_GCFOS_RETENTION_DURATION_DAYS < 3 || g_GCFOS_RETENTION_DURATION_DAYS > 365)
			{
#ifndef _DEBUG
			DEBUGLOG_L(1, ("%S set to an invalid range, resetting to default (30)\n", GCFOS_REG_LIMBO_RETENTION_DAYS));
			g_GCFOS_RETENTION_DURATION_DAYS = 30;
#endif
			}

		dwDefault = 4;
		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_RESIDENCY_THRESHOLD, &g_GCFOS_RESIDENCY_THRESHOLD, REG_DWORD, sizeof(DWORD), &dwDefault);
		if(ERROR_SUCCESS != Result)
			{
			return -1;
			}	
		if(g_GCFOS_RESIDENCY_THRESHOLD < 2 || g_GCFOS_RESIDENCY_THRESHOLD > 50)
			{
#ifndef _DEBUG
			DEBUGLOG_L(1, ("%S set to an invalid range, resetting to default (4)\n", GCFOS_REG_RESIDENCY_THRESHOLD));
			g_GCFOS_RESIDENCY_THRESHOLD = 4;
#endif
			}

		DEBUGLOG_L(2, ("Parameters used:\n  Residency threshold = %u\n  Limbo retention = %u\n", g_GCFOS_RESIDENCY_THRESHOLD, g_GCFOS_RETENTION_DURATION_DAYS));
		}

	// Load registry alternate/secondary OPTIONAL repository configuration details

	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_SECONDARY_TYPE, &szSecondaryRepoType, REG_SZ, sizeof(szSecondaryRepoType), NULL);
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_SECONDARY_LOCATION, &szSecondaryBucket, REG_SZ, sizeof(szSecondaryBucket), NULL);
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_SECONDARY_REGION, &szSecondaryRegion, REG_SZ, sizeof(szSecondaryRegion), NULL);
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_SECONDARY_ENDPOINT, &szSecondaryEndpoint, REG_SZ, sizeof(szSecondaryEndpoint), NULL);
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_SECONDARY_ACCESS_KEY, &szSecondaryAccessKey, REG_SZ, sizeof(szSecondaryAccessKey), NULL);
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_SECONDARY_SECRET_KEY, &szSecondarySecretKey, REG_SZ, sizeof(szSecondarySecretKey), NULL);

	Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_BLOCK_STORE_PATH, &g_BlocksDir, REG_SZ, sizeof(g_BlocksDir), NULL);
	if(ERROR_SUCCESS != Result || g_BlocksDir[0] == 0)
		{
		g_bDedupeBlocks = false;
		}
	else
		{
		DEBUGLOG_L(3, ("Using block store at: %s\n", CStringA(g_BlocksDir)));
		g_bDedupeBlocks = true;
		}

	if(!g_bDedupeFiles && !g_bDedupeBlocks)
		{
		DEBUGLOG_L(1, ("Neither file or block store configured -- nothing to do\n"));
		return -1;
		}

	if(g_bDedupeBlocks)
		dwDefault = 16 * 1024; // 16GB default if block-dedupe enabled
	else
		dwDefault = 4 * 1024;
	Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_DB_ENV_SIZE, &g_dwInitialEnvSize, REG_DWORD, sizeof(DWORD), &dwDefault);
	if(ERROR_SUCCESS != Result)
		{
		return -1;
		}	
	if(g_bDedupeBlocks)
		dwDefault = 2 * 1024; // Grow-by 2GB default if block-dedupe enabled
	else
		dwDefault = 512; // Grow-by 0.5GB otherwise
	Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_DB_ENV_GROW, &g_dwGrowEnvSize, REG_DWORD, sizeof(DWORD), &dwDefault);
	if(ERROR_SUCCESS != Result)
		{
		return -1;
		}


#if 0
	disable proxy by editing app.config:

<system.net>
  <defaultProxy enabled="false">
    <proxy/>
    <bypasslist/>
    <module/>
  </defaultProxy>
</system.net>
#endif

	if(_tcsicmp(szRepoType, L"S3") == 0)
		{
		g_RepositoryType = S3;
		g_Repo = new S3Repository();
		}
	else if(_tcsicmp(szRepoType, L"OpenStack") == 0)
		{
		g_Repo = new OpenStackRepository();
		g_RepositoryType = OPENSTACK;
		}
	else if(_tcsicmp(szRepoType, L"LocalFile") == 0)
		{
		g_Repo = new FileRepository();
		g_RepositoryType = LOCALFILE;
		}
	if(_tcsicmp(szRepoType, L"Azure") == 0)
		{
		g_RepositoryType = AZURE;
		g_Repo = new AzureRepository();
		}

	if(_tcsicmp(szSecondaryRepoType, L"S3") == 0)
		{
		g_SecondaryRepositoryType = S3;
		g_Repo2 = new S3Repository();
		}
	else if(_tcsicmp(szSecondaryRepoType, L"OpenStack") == 0)
		{
		g_Repo2 = new OpenStackRepository();
		g_SecondaryRepositoryType = OPENSTACK;
		}
	else if(_tcsicmp(szSecondaryRepoType, L"LocalFile") == 0)
		{
		g_Repo2 = new FileRepository();
		g_RepositoryType = LOCALFILE;
		}
	else if(_tcsicmp(szSecondaryRepoType, L"Azure") == 0)
		{
		g_Repo2 = new AzureRepository();
		g_RepositoryType = AZURE;
		}

	if(g_bDedupeFiles)
		{
		if(g_Repo == NULL)
			{
			DEBUGLOG_L(1, ("Repository Type not known\n"));
			goto CLEANUP;
			}

		if(!g_Repo->Initialize(szBucket, szAccessKey, szSecretKey, szEndpoint, szRegion))
			{
			DEBUGLOG_L(1, ("Error connecting to Repository\n"));
			goto CLEANUP;
			}

		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_LCUD_LOCATION_LOCAL, &g_LCUD_LocationLocal, REG_SZ, sizeof(g_LCUD_LocationLocal), _T(GCFOS_LCUD_LOCAL_DEFAULT));
		if(ERROR_SUCCESS != Result)
			{
			goto CLEANUP;
			}
		if(!CreateDirectory(g_LCUD_LocationLocal, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
			{
			DEBUGLOG_L(1, ("Failed to create local LCUD path %S, error %u", g_LCUD_LocationLocal, GetLastError()));
			goto CLEANUP;
			}
		if(g_RepositoryType == LOCALFILE && g_Repo2 != NULL)
			{
			g_LCUD_Repo = g_Repo2;
			}
		}

	if(g_Repo2 != NULL)
		{
		if(!g_Repo2->Initialize(szSecondaryBucket, szSecondaryAccessKey, szSecondarySecretKey, szSecondaryEndpoint, szSecondaryRegion))
			{
			DEBUGLOG_L(1, ("Error connecting to SECONDARY Repository\n"));
			goto CLEANUP;
			}
		// if we are using a secondary repository, see if we should use it to store the block-store
		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_SECONDARY_BLOCK_STORE_LOCATION, &szBucket, REG_SZ, sizeof(szBucket), NULL);
		if(Result == ERROR_SUCCESS)
			{
			// szBucket is borrowed (not used anymore) to instantiate a new System::String
			g_SecondaryBlockStoreLocation = gcnew System::String(szBucket);
			if(!g_Repo2->CreateContainer(g_SecondaryBlockStoreLocation))
				{
				DEBUGLOG_L(1, ("Error creating %S container for secondary block store location\n", szBucket));
				goto CLEANUP;
				}
			dwDefault = 20;
			SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_BLOCKSTORE_SECONDARY_REPO_MIN_DATA_CHANGE_MB, &g_BlockStoreSecondaryRepoMinDataChange_MB, REG_DWORD, sizeof(g_BlockStoreSecondaryRepoMinDataChange_MB), &dwDefault);
			dwDefault = 1800;
			SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_BLOCKSTORE_SECONDARY_REPO_MAX_TIME_SEC, &g_BlockStoreSecondaryRepoMaxTime_Sec, REG_DWORD, sizeof(g_BlockStoreSecondaryRepoMaxTime_Sec), &dwDefault);
			}
		}

	Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_REPO_LCUD_LOCATION, &g_LCUD_Location, REG_SZ, sizeof(g_LCUD_Location), _T(GCFOS_LCUD_REPO_DEFAULT));
	if(ERROR_SUCCESS != Result)
		{
		goto CLEANUP;
		}

	rand_s(&NewServerValidation);
	Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_SERVER_VALIDATION, &g_Server_Validation, REG_DWORD, sizeof(g_Server_Validation), &NewServerValidation);
	if(ERROR_SUCCESS != Result)
		{
		goto CLEANUP;
		}

	GetSystemInfo(&g_SysInfo);

	// for each returned interface, create a listening socket.
    for(pAddr = res; pAddr != NULL; pAddr = pAddr->ai_next)
	    {
		if(i >= GCFOS_MAX_LISTEN_SOCKETS)
			break; // all full

		if(pAddr->ai_family != AF_INET)
			{
			// NOT interested in IPv6 addresses at this time
			continue;
			}

		getnameinfo(pAddr->ai_addr, (socklen_t)pAddr->ai_addrlen, g_ListenState[i].hostid, sizeof(g_ListenState[i].hostid), NULL, 0, NI_NUMERICHOST);

		if(szExplicitIPAddress[0])
			{
			if(strcmp(g_ListenState[i].hostid, CStringA(szExplicitIPAddress)) != 0)
				{
				DEBUGLOG_L(4, ("Ignoring address: %s\n", g_ListenState[i].hostid));
				continue;
				}
			bFoundExplicitIPAddress = true;
			}

		DEBUGLOG_L(4, ("This address: %s\n", g_ListenState[i].hostid));

        s = WSASocket(pAddr->ai_family, 
                            pAddr->ai_socktype,
                            pAddr->ai_protocol,
                            NULL,
                            NULL,
                            WSA_FLAG_OVERLAPPED);
        if(s == INVALID_SOCKET)
			{
            DEBUGLOG_L(1, ("WSASocket failed. Error = %d\n", WSAGetLastError()));
            DEBUGLOG_L(1, ("Ignoring this address and continuing with the next. \n\n"));
            
            // anyway, let's continue with other addresses.
            continue;
			}

        DEBUGLOG_L(4, ("Created socket with handle = %d\n", s));

#if 0
		// Disable output buffering
		retVal = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&g_nZero, sizeof(g_nZero));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG_L(1, ("setsockopt(SNDBUF) failed: %d\n", WSAGetLastError()));
            closesocket(s);
			continue;
			}
#endif		
		// Disable delay
		retVal = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&g_nOne, sizeof(g_nOne));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG(("setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
			}
		// Allow socket re-use
		retVal = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&g_nOne, sizeof(g_nOne));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG_L(1, ("setsockopt(SO_REUSEADDR) failed: %d\n", WSAGetLastError()));
            closesocket(s);
			continue;
			}

		// bind the socket.
        if(bind(s, pAddr->ai_addr, (int)pAddr->ai_addrlen) == SOCKET_ERROR)
			{
            DEBUGLOG_L(1, ("bind failed. Error = %d\n", WSAGetLastError()));
            closesocket(s);
            continue;
			}

        DEBUGLOG_L(4, ("Socket bound successfully\n"));        

        // listen for upto MAX_CONNECTIONS number of clients.
        if(listen(s, SOMAXCONN) != NO_ERROR)
			{
            DEBUGLOG_L(1, ("listen failed. Error = %d\n", WSAGetLastError()));
            closesocket(s);
            continue;
			}

        DEBUGLOG_L(4, ("Listen successful\n"));

		g_hIOCP = CreateIoCompletionPort((HANDLE)s, g_hIOCP, i, 0);
		if(NULL == g_hIOCP)
			{
			DEBUGLOG_L(1, ("IOCP Creation failed, error: %d\n", GetLastError()));
			continue;
			}

		DEBUGLOG_L(4, ("IOCP completed\n"));

		g_ListenState[i].s_list = s;

        retVal = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptex_guid, sizeof(acceptex_guid), &g_ListenState[i].fnAcceptEx,
						sizeof(LPFN_ACCEPTEX), &dwLen, NULL, NULL);
        if(retVal == SOCKET_ERROR)
			{
            DEBUGLOG_L(1, ("failed to load AcceptEx: %d\n", WSAGetLastError()));
            return FALSE;
			}

		retVal = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &getacceptexsockaddrs_guid, sizeof(getacceptexsockaddrs_guid), &g_ListenState[i].fnGetAcceptExSockaddrs,
						sizeof(LPFN_GETACCEPTEXSOCKADDRS), &dwLen, NULL, NULL);
        if(retVal == SOCKET_ERROR)
			{
            DEBUGLOG(("failed to find GetAcceptExSockaddrs: %d\n", WSAGetLastError()));
            return FALSE;
			}

		// create accept socket now
        acc = WSASocket(pAddr->ai_family, 
                            pAddr->ai_socktype,
                            pAddr->ai_protocol,
                            NULL,
                            NULL,
                            WSA_FLAG_OVERLAPPED);
        if(acc == INVALID_SOCKET)
			{
            DEBUGLOG_L(1, ("WSASocket failed. Error = %d\n", WSAGetLastError()));
            DEBUGLOG_L(1, ("Ignoring this address and continuing with the next. \n\n"));
            
            // anyway, let's continue with other addresses.
            continue;
			}

		// copy address info about this protocol/interface
		g_ListenState[i].ai_family = pAddr->ai_family;
		g_ListenState[i].ai_socktype = pAddr->ai_socktype;
		g_ListenState[i].ai_protocol = pAddr->ai_protocol;

		DEBUGLOG_L(4, ("accept socket created\n"));

		g_hIOCP = CreateIoCompletionPort((HANDLE)acc, g_hIOCP, i, 0);
		if(NULL == g_hIOCP)
			{
			DEBUGLOG_L(1, ("IOCP(2) Creation failed, error: %d\n", GetLastError()));
			continue;
			}

		// Disable output buffering
#if 0
		retVal = setsockopt(acc, SOL_SOCKET, SO_SNDBUF, (char *)&g_nZero, sizeof(g_nZero));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG_L(1, ("setsockopt(SNDBUF) failed: %d\n", WSAGetLastError()));
            closesocket(s);
			continue;
			}
#endif
		// Disable delay
		retVal = setsockopt(acc, IPPROTO_TCP, TCP_NODELAY, (char *)&g_nOne, sizeof(g_nOne));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG(("setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
			}

		newcontext = new GCFOS_CONNECT_STATE();
		newcontext->s_acc = acc;
		newcontext->status = STATE_ACCEPT;
		g_ListenState[i].s_list = s;

		newcontext->op = IOCP_OP_ACCEPT;

		EnterCriticalSection(&g_csConnections);
		g_ConnectState.insert(newcontext);
		LeaveCriticalSection(&g_csConnections);
		retVal = g_ListenState[i].fnAcceptEx(s, acc,
						(PVOID)(newcontext->buffer.buf+0x100),
						0, //GCFOS_BUFSIZE - (2 * (sizeof(SOCKADDR_STORAGE) + 16)),
						sizeof(SOCKADDR_STORAGE) + 16,
						sizeof(SOCKADDR_STORAGE) + 16,
						&dwLen, 
						&newcontext->o);
		if(retVal == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError()) )
			{
			DEBUGLOG_L(1, ("AcceptEx() failed: %d\n", WSAGetLastError()));
			closesocket(s);
			closesocket(acc);
			continue;
			}

		DEBUGLOG(("Server successfully listening on %s\n", g_ListenState[i].hostid));

		i++;

		}

	if(szExplicitIPAddress[0] && bFoundExplicitIPAddress == false)
		{
		DEBUGLOG_L(1, ("***WARNING*** ------- Could not find explicitly requested IP address %S\n", szExplicitIPAddress));
		}

	if(gcfosdb::CreateEnvironment() != 0)
		{
		DEBUGLOG_L(1, ("Unable to open gcfosdb environment\n"));
		return -2;
		}

	// Open the databases


	DEBUGLOG(("Opening limbo list\n"));
	g_Limbo = new gcfosdb();
	if(!g_Limbo->open(GCFOS_DBNAME_LIMBO, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_LIMBO_ENTRY, client), FIELD_OFFSET(GCFOS_LIMBO_ENTRY, whenAdded), RTL_FIELD_SIZE(GCFOS_LIMBO_ENTRY, whenAdded)))
		{
		DEBUGLOG_L(1, ("failed to open limbo list db\n"));
		goto CLOSE_DB;
		}
	DEBUGLOG(("Opening limbo list secondary\n"));
	g_Limbo2 = new gcfosdb();
	if(!g_Limbo2->open(GCFOS_DBNAME_LIMBO2, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_LIMBO_2_ENTRY, size), FIELD_OFFSET(GCFOS_LIMBO_2_ENTRY, whenAdded), RTL_FIELD_SIZE(GCFOS_LIMBO_2_ENTRY, whenAdded)))
		{
		DEBUGLOG_L(1, ("failed to open limbo2 list db\n"));
		goto CLOSE_DB;
		}

	DEBUGLOG(("Opening resident list\n"));
	g_Resident = new gcfosdb();
	if(!g_Resident->open(GCFOS_DBNAME_RESIDENT, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_RESIDENT_ENTRY, size), RTL_SIZEOF_THROUGH_FIELD(GCFOS_RESIDENT_ENTRY, size), 0))
		{
		DEBUGLOG_L(1, ("failed to open resident list db\n"));
		goto CLOSE_DB;
		}
	DEBUGLOG(("Opening wanted list\n"));
	g_Wanted = new gcfosdb();
	if(!g_Wanted->open(GCFOS_DBNAME_WANTED, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_WANTED_ENTRY, size), FIELD_OFFSET(GCFOS_WANTED_ENTRY, size), 0))
		{
		DEBUGLOG_L(1, ("failed to open wanted list db\n"));
		goto CLOSE_DB;
		}
	DEBUGLOG(("Opening update list\n"));
	g_Update = new gcfosdb();
	if(!g_Update->open(GCFOS_DBNAME_UPDATE, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_UPDATE_ENTRY, rec),
		FIELD_OFFSET(GCFOS_UPDATE_ENTRY, SHA1), RTL_SIZEOF_THROUGH_FIELD(GCFOS_UPDATE_ENTRY, size) - RTL_SIZEOF_THROUGH_FIELD(GCFOS_UPDATE_ENTRY, rec), 0, gcfosdb_RECNO, true))
		{
		DEBUGLOG_L(1, ("failed to open update list db\n"));
		goto CLOSE_DB;
		}
//	UpdateManager.ImportList(GCFOS_DBNAME_UPDATE_SAVE, g_Update, gcfosdb_APPEND);
//	DeleteFileA(GCFOS_DBNAME_UPDATE_SAVE);

	DEBUGLOG(("Opening clientdb\n"));
	g_Clients = new gcfosdb();
	if(!g_Clients->open(GCFOS_DBNAME_CLIENTDB, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_CLIENT_ENTRY, clientid),
		FIELD_OFFSET(GCFOS_CLIENT_ENTRY, sharedkey), RTL_SIZEOF_THROUGH_FIELD(GCFOS_CLIENT_ENTRY, future_expansion) - RTL_SIZEOF_THROUGH_FIELD(GCFOS_CLIENT_ENTRY, clientid), 0, gcfosdb_RECNO))
		{
		DEBUGLOG_L(1, ("failed to open update list db\n"));
		goto CLOSE_DB;
		}
#ifndef ULTRABAC_CLOUD_USE
	DEBUGLOG(("Opening clientdb secondary\n"));
	g_Clients2 = new gcfosdb();

	if(!g_Clients2->open(GCFOS_DBNAME_CLIENTDB2, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_CLIENT_2_ENTRY, szName), FIELD_OFFSET(GCFOS_CLIENT_2_ENTRY, clientid),
		RTL_FIELD_SIZE(GCFOS_CLIENT_2_ENTRY, clientid), 0)) // no duplicates allowed on computer name secondary-key
		{
		DEBUGLOG_L(1, ("failed to open client2 db\n"));
		goto CLOSE_DB;
		}
#if 0 // associations not used anymore (not supported by lmdb)
	if(g_Clients2->associate(g_Clients, Clientdb_2_Callback) != 0)
		{
		DEBUGLOG_L(1, ("Unable to associate secondary index for clientsdb\n"));
		goto CLOSE_DB;
		}
#endif//0
#else
	DEBUGLOG(("Opening BannedIP list\n"));
	g_BannedIPs = new gcfosdb();
	if(!g_BannedIPs->open(GCFOS_DBNAME_BANNED, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_BANNED_ENTRY, ip_address), FIELD_OFFSET(GCFOS_BANNED_ENTRY, time_banned), RTL_FIELD_SIZE(GCFOS_BANNED_ENTRY, time_banned)))
		{
		DEBUGLOG_L(1, ("failed to open banned list db\n"));
		goto CLOSE_DB;
		}
#endif//ULTRABAC_CLOUD_USE
	DEBUGLOG(("Opening sessions db\n"));
	g_Sessions = new gcfosdb();
	if(!g_Sessions->open(GCFOS_DBNAME_SESSIONS, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_SESSION_ENTRY, recno),
		FIELD_OFFSET(GCFOS_SESSION_ENTRY, start), RTL_SIZEOF_THROUGH_FIELD(GCFOS_SESSION_ENTRY, future_expansion) - RTL_SIZEOF_THROUGH_FIELD(GCFOS_SESSION_ENTRY, recno), 0, gcfosdb_RECNO))
		{
		DEBUGLOG_L(1, ("failed to open sessions db\n"));
		goto CLOSE_DB;
		}
	DeleteIncompleteSessionRecords();

	if(g_bDedupeBlocks)
		{
		DEBUGLOG(("Opening blocks db\n"));
		g_Blocks = new gcfosdb();
		if(!g_Blocks->open(GCFOS_DBNAME_BLOCKS, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_BLOCK_ENTRY, hash),
			FIELD_OFFSET(GCFOS_BLOCK_ENTRY, fileno), RTL_SIZEOF_THROUGH_FIELD(GCFOS_BLOCK_ENTRY, last_ref) - RTL_SIZEOF_THROUGH_FIELD(GCFOS_BLOCK_ENTRY, hash), 0))
			{
			DEBUGLOG_L(1, ("failed to open blocks db\n"));
			goto CLOSE_DB;
			}
		memset(&blockEntry, 0, sizeof(GCFOS_BLOCK_ENTRY));
		if(g_Blocks->find(&blockEntry) == 0)
			{
			g_blks_fileID = blockEntry.fileno;
			g_blks_out_offset = blockEntry.offset;
			}
		else
			{
			g_blks_fileID = 0;
			g_blks_out_offset = 0;
			}
		dwLen = sizeof(DWORD);
		if(ERROR_SUCCESS != RegQueryValueEx(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_ID, NULL, NULL, (LPBYTE)&g_blks_fileID, &dwLen)
		|| ERROR_SUCCESS != RegQueryValueEx(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_OFFSET, NULL, NULL, (LPBYTE)&g_blks_out_offset, &dwLen))
			{
			DEBUGLOG_L(4, ("No override values in registry for blocks file id/offset\n"));
			}
		else
			{
			// delete the registry values now, write them back during an orderly shutdown
			RegDeleteKey(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_ID);
			RegDeleteKey(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_OFFSET);
			DEBUGLOG_L(4, ("Blocks ID/offset loaded from registry, %u/%u\n", g_blks_fileID, g_blks_out_offset));
			if(g_blks_fileID > blockEntry.fileno || (g_blks_fileID == blockEntry.fileno && g_blks_out_offset > blockEntry.offset))
				{
				DEBUGLOG_L(4, ("Blocks ID/offset overrided from registry\n"));
				blockEntry.fileno = g_blks_fileID;
				blockEntry.offset = g_blks_out_offset;
				}
			else
				{
				if(g_blks_fileID != blockEntry.fileno || g_blks_out_offset != blockEntry.offset)
					{
					DEBUGLOG_L(4, ("db contains more recent values, restoring\n"));
					}
				g_blks_fileID = blockEntry.fileno;
				g_blks_out_offset = blockEntry.offset;
				}
			}
		rc = g_Blocks->insert(&blockEntry);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("Failed to insert initial state to blocks db %d\n", rc));
			goto CLOSE_DB;
			}
		DEBUGLOG_L(4, ("Blocks file = %u, offset = %u\n", g_blks_fileID, g_blks_out_offset));
		CreateDirectory(g_BlocksDir, NULL);
		InitializeCriticalSection(&g_csBlksFile);
		if(!OpenCurrentBlocksFile())
			{
			DEBUGLOG_L(1, ("Failed to open block store file\n"));
			goto CLOSE_DB;
			}
		dwDefault = 1;
		Result = SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_ENABLE_BLOCKS_PURGING, &dwLen, REG_DWORD, sizeof(DWORD), &dwDefault);
		if(ERROR_SUCCESS == Result && dwLen > 0)
			{
			g_bEnableBlocksPurging = true;
			DEBUGLOG_L(4, ("Blocks purging enabled\n"));
			}
#if 0 
this code was used to update the blocks database to include a new field
"days_since_last_ref" which will be used to track when this hash
has been referenced (for restore or subsequent re-backup)
At some point it will be possible to purge old records from the blocks db by
processing all of the blocks files and deleting parts of it that haven't
been referenced in a long time

		UINT64 recs = 0;
		gcfosdbCursor *c_blocks;
		gcfosdbTxn *txn;
		int rc;
		GCFOS_BLOCK_ENTRY entry;
		GCFOS_UsefulTime timenow;

		DEBUGLOG_L(1, ("Patching blocksdb\n"));
		rc = gcfosdb::BeginTxn(NULL, &txn, 0);
		rc = g_Blocks->createCursor(&c_blocks, 0, txn);
		rc = g_Blocks->get(c_blocks, &entry, gcfosdb_FIRST, txn);
		while(rc == 0)
			{
			entry.days_since_last_ref = timenow.AsDays();
			rc = g_Blocks->put(c_blocks, &entry);
			if(rc != 0)
				{
				DEBUGLOG_L(1, ("Error during put: %d\n", rc));
				}
			recs++;
			if(recs % 10000 == 0)
				{
				printf("Processing record %I64u            \r", recs);
				rc = g_Blocks->closeCursor(c_blocks);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error closing cursor: %d\n", rc));
					break;
					}
				rc = gcfosdb::CommitTxn(txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error committing txn: %d\n", rc));
					break;
					}
				rc = gcfosdb::BeginTxn(NULL, &txn, 0);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error beginning txn: %d\n", rc));
					break;
					}
				rc = g_Blocks->createCursor(&c_blocks, 0, txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error creating cursor: %d\n", rc));
					break;
					}
				rc = g_Blocks->get(c_blocks, &entry, MDB_SET, txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error during get: %d\n", rc));
					break;
					}
				}
			rc = g_Blocks->getNext(c_blocks, &entry);
			}
		printf("\n");
		if(rc != gcfosdb_NOTFOUND)
			{
			DEBUGLOG_L(1, ("Error reading blocksdb: %d\n", rc));
			}
		rc = g_Blocks->closeCursor(c_blocks);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("Error closing cursor: %d\n", rc));
			}
		rc = gcfosdb::CommitTxn(txn);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("Error committing txn: %d\n", rc));
			}

#endif
		}

#ifndef ULTRABAC_CLOUD_USE
setup_UDP_listener:

	dwDefault = TRUE;
	SetRegEntryWithDefault(g_MyRegistry, GCFOS_REG_ENABLE_SERVICE_DISCOVERY, &bEnableServiceDiscovery, REG_DWORD, sizeof(DWORD), &dwDefault);
	if(g_bRedirectionMode && !bEnableServiceDiscovery)
		{
		DEBUGLOG_L(1, ("Service discovery must be enabled when using redirection mode\n"));
		goto CLEANUP;
		}

	if(bEnableServiceDiscovery)
		{
		// now go through addresses again and create UDP ports
		for(pAddr = res; pAddr != NULL; pAddr = pAddr->ai_next)
			{
			DWORD dwFlags = 0;
			// this is a "customer" installation -- create/bind UDP socket (for service discovery)
			if(i >= GCFOS_MAX_LISTEN_SOCKETS)
				break; // all full

			if(pAddr->ai_family != AF_INET)
				{
				// NOT interested in IPv6 addresses at this time
				continue;
				}

			g_ListenState[i].s_list = WSASocket(pAddr->ai_family, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL, WSA_FLAG_OVERLAPPED);
			if(INVALID_SOCKET == g_ListenState[i].s_list)
				{
				DEBUGLOG_L(1, ("Failed to create UDP socket: %d", WSAGetLastError()));
				continue;
				}

			retVal = setsockopt(g_ListenState[i].s_list, SOL_SOCKET, SO_REUSEADDR, (char *)&g_nOne, sizeof(g_nOne));
			if(retVal == SOCKET_ERROR)
				{
				DEBUGLOG_L(1, ("setsockopt(UDP:SO_REUSEADDR) failed: %d\n", WSAGetLastError()));
				closesocket(g_ListenState[i].s_list);
				continue;
				}
			if(bind(g_ListenState[i].s_list, pAddr->ai_addr, (int)pAddr->ai_addrlen) == SOCKET_ERROR)
				{
				DEBUGLOG_L(1, ("bind(UDP:SO_REUSEADDR) failed: %d\n", WSAGetLastError()));
				closesocket(g_ListenState[i].s_list);
				continue;
				}
			g_hIOCP = CreateIoCompletionPort((HANDLE)g_ListenState[i].s_list, g_hIOCP, i, 0);
			if(NULL == g_hIOCP)
				{
				DEBUGLOG_L(1, ("IOCP Creation failed (UDP), error: %d\n", GetLastError()));
				closesocket(g_ListenState[i].s_list);
				continue;
				}
			getnameinfo(pAddr->ai_addr, (socklen_t)pAddr->ai_addrlen, g_ListenState[i].hostid, sizeof(g_ListenState[i].hostid), NULL, 0, NI_NUMERICHOST);
			g_ListenState[i].op = IOCP_OP_AWAITING_BROADCAST;
			g_ListenState[i].buffer.buf = (CHAR*)VirtualAlloc(NULL, GCFOS_MAX_DATAGRAM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			g_ListenState[i].buffer.len = GCFOS_MAX_DATAGRAM_SIZE;
			g_ListenState[i].connectedToLen = sizeof(SOCKADDR);
			if(SOCKET_ERROR == WSARecvFrom(g_ListenState[i].s_list, &g_ListenState[i].buffer, 1, NULL, &dwFlags,
				&g_ListenState[i].connectedTo, &g_ListenState[i].connectedToLen, &g_ListenState[i].o, NULL))
				{
				if(WSAGetLastError() != WSA_IO_PENDING)
					{
					DEBUGLOG_L(1, ("WSARecvFrom for UDP failed, %u\n", WSAGetLastError()));
					closesocket(g_ListenState[i].s_list);
					continue;
					}
				}

			i++;
			}
		}
#endif
		

	freeaddrinfo(res);		
	res = NULL;

#ifdef _DEBUG
	//g_SysInfo.dwNumberOfProcessors = 1; // DEBUG ONLY
#endif//_DEBUG

	CreateDefaultUserIfNonePresent();
	for(i = 1; i <= (int) g_SysInfo.dwNumberOfProcessors; i++)
		{
		// Create one thread per CPU core
		hThread = (HANDLE)_beginthreadex(NULL, 0, GCFOS_Listener, (void *)(LONG_PTR)i, 0, NULL);
		CloseHandle(hThread); // Don't need the handle anymore -- thread will continue to run
		InterlockedIncrement(&g_ThreadsActive);
		}

	if(!g_bRedirectionMode)
		{
		_beginthreadex(NULL, 0, UpdateWorker, NULL, 0, NULL);
		InterlockedIncrement(&g_ThreadsActive);

		_beginthreadex(NULL, 0, MaintenanceWorker, NULL, 0, NULL);
		InterlockedIncrement(&g_ThreadsActive);

		_beginthreadex(NULL, 0, MigrateBlockStoreToSecondary, NULL, 0, NULL);
		InterlockedIncrement(&g_ThreadsActive);

		_beginthreadex(NULL, 0, ValidateBlocksWorker, NULL, 0, NULL);
		InterlockedIncrement(&g_ThreadsActive);
		}

	//VerifyLimboSync();
	if(g_bIsService)
		{
		g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(g_SvcStatusHandle, &g_ServiceStatus);
		WaitForSingleObject(g_ExitSignalled, INFINITE);
		}
	else
		{
		GCFOS_ConsoleHandler();
		}

	SetEvent(g_ExitSignalled);
	_tprintf_s(TEXT("Waiting for thread exit..\n"));

	while(g_ThreadsActive)
		{
		Sleep(100);
		}

CLOSE_DB:
//	UpdateManager.ExportList(GCFOS_DBNAME_UPDATE_SAVE, g_Update);
	_tprintf_s(TEXT("Closing databases..\n"));

	if(g_Limbo)
		{
		g_Limbo->close();
		delete g_Limbo;
		}
	if(g_Limbo2)
		{
		g_Limbo2->close();
		delete g_Limbo2;
		}
	if(g_Resident)
		{
		g_Resident->close();
		delete g_Resident;
		}
	if(g_Wanted)
		{
		g_Wanted->close();
		delete g_Wanted;
		}
	if(g_Update)
		{
		g_Update->close();
		delete g_Update;
		//DeleteFile(L"gcfosdb\\update");
		}
	if(g_Clients)
		{
		g_Clients->close();
		delete g_Clients;
		}
#ifdef ULTRABAC_CLOUD_USE
	if(g_BannedIPs)
		{
		g_BannedIPs->close();
		delete g_BannedIPs;
		}
#else
	if(g_Clients2)
		{
		g_Clients2->close();
		delete g_Clients2;
		}
#endif//ULTRABAC_CLOUD_USE
	if(g_Sessions)
		{
		g_Sessions->close();
		delete g_Sessions;
		g_Sessions = NULL;
		}

	if(g_ShutdownResetLSN)
		{
#if 0//only used on BDB implementations
		_tprintf_s(TEXT("Resetting LSNs..\n"));
	
#ifdef ULTRABAC_CLOUD_USE
		gcfosdb::lsn_reset(GCFOS_DBNAME_BANNED, 0);
#endif//ULTRABAC_CLOUD_USE
		gcfosdb::lsn_reset(GCFOS_DBNAME_CLIENTDB, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_RESIDENT, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_UPDATE, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_WANTED, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_LIMBO, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_LIMBO2, 0);
		gcfosdb::lsn_reset(GCFOS_DBNAME_SESSIONS, 0);
#endif GCFOS_LMDB
		}


CLEANUP:
	DEBUGLOG_L(1, ("Exiting..\n"));
	btree::btree_set<PVOID>::iterator connection;
	// the CloseConnection() will also enter g_csConnections
	// but we must enter it here now (and recursively enter it in CloseConnection)
	// as we cannot tolerate our iterator being messed with
	EnterCriticalSection(&g_csConnections);
	for(connection = g_ConnectState.begin(); connection != g_ConnectState.end(); connection = g_ConnectState.begin())
		{
		CloseConnection((PGCFOS_CONNECT_STATE)*connection);
		}
	LeaveCriticalSection(&g_csConnections);
	gcfosdb::CloseEnvironment();

	if(res != NULL)
		{
        freeaddrinfo(res);		
		}
	
	WSACleanup();

	Result = RegSetValueEx(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_ID, NULL, REG_DWORD, (LPBYTE)&g_blks_fileID, sizeof(DWORD));
	Result = RegSetValueEx(g_MyRegistry, GCFOS_REG_BLOCKS_FILE_OFFSET, NULL, REG_DWORD, (LPBYTE)&g_blks_out_offset, sizeof(DWORD));

	RegCloseKey(g_MyRegistry);
	if(g_bIsService)
		{
		fclose(g_DebugLog);
		}
	return 0;
	}

#ifdef ULTRABAC_CLOUD_USE

void BanIP(PGCFOS_CONNECT_STATE context)
	{
	GCFOS_BANNED_ENTRY			to_ban;

	memcpy(to_ban.ip_address, context->connectedToHost, GCFOS_MAX_IP_ADDR_LEN);
	// time will already be initialized from constructor
	g_BannedIPs->insert(&to_ban);
	DEBUGLOG_L(2, ("BanIP: %s now banned\n", to_ban.ip_address));
	}

bool IsBannedIP(PGCFOS_CONNECT_STATE context)
	{
	GCFOS_BANNED_ENTRY			to_check;
	int							rc;

	memcpy(to_check.ip_address, context->connectedToHost, GCFOS_MAX_IP_ADDR_LEN);
	rc = g_BannedIPs->find(&to_check);
	if(rc == 0)
		{
		// found a banned IP -- we could update the time here
		// I decided not to though as if it was a genuine client, there's a chance
		// it might never get through
		return true;
		}
	else
		return false;
	}

#endif//ULTRABAC_CLOUD_USE



   
       
   
     
   
 
 
 
             
    
 
     
