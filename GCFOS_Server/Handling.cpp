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

// Handling.cpp : Defines the routines for handling Limbo, Resident, Wanted lists


#include "stdafx.h"

#include "Project.h"
#include "Handling.h"

// ProcessUpdate is called by a background thread that processes a queue. In this
// way, it lags behind the "main" functions since it is not a "critical" process
// in the sense that client queries are not dependent on this process and therefore
// no latency will be added on queries or other client operations.
// When an update is triggered on the queue, this process will determine if the
// entry now contains enough entries to warrant it now being "wanted" (in which 
// case all the limbo entries are then deleted).  It also notices when limbo
// entries are too old and will delete them.
// This does mean that some stale entries can grow in the limbo list. This
// is handled by a periodic processing of all the limbo entries (ProcessLimboEntries)
// which will eliminate stale (old) entries, and migrate them to the unique-per-
// client lists which are then used by the clients for local-caching.

int ProcessUpdate(GCFOS_UPDATE_ENTRY *updateEntry, gcfosdbTxn *txn, PGCFOS_SRV_RESPONSE response)
{
	bool			deleting = false;
	GCFOS_UsefulTime timenow;
	UINT64			sizeOfWantedFiles = 0;
	gcfosdbCursor	*c_limbo;
	GCFOS_LIMBO_ENTRY limboEntry;
	GCFOS_LIMBO_2_ENTRY limbo2Entry;
	GCFOS_WANTED_ENTRY wantedEntry;
	UINT32			getflags;
	UINT32			clientCount;
	int				rc;

	// On entry, we know that this file is not yet resident OR wanted -- so
	// we just want to delete records for clients that have expired (too old)
	// or, if there's enough entries for this hash, add a record to the wanted
	// list

	if(g_Limbo->createCursor(&c_limbo, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) != 0)
		{
		DEBUGLOG_L(1, ("ProcessUpdate: failed to get limbo cursor\n"));
		return -1;
		}

	getflags = gcfosdb_SET_RANGE;
	memcpy(limboEntry.SHA1, updateEntry->SHA1, GCFOS_SHA1_LEN);
	limboEntry.size = updateEntry->size;
	limboEntry.client = 0;
	clientCount = 0; // reset count

	while(true)
		{
		rc = g_Limbo->get(c_limbo, (PUCHAR)&limboEntry, getflags | gcfosdb_READ_UNCOMMITTED, txn);
		if(rc != 0)
			{
			if(rc == gcfosdb_NOTFOUND)
				{
				rc = 0; // indicate success
				break; // we're all done here
				}
			DEBUGLOG_L(1, ("ProcessUpdate: Unexpected error:%d from c_limbo\n", rc));
			break;
			}

		if(memcmp(&limboEntry.SHA1, &updateEntry->SHA1, GCFOS_SHA1_LEN) != 0 || limboEntry.size != updateEntry->size)
			{
			// no more entries for this hash
			rc = 0; // indicate success
			break;
			}

		getflags = gcfosdb_NEXT;
		clientCount++;

		if(deleting)
			{
			rc = g_Limbo->erase(c_limbo);
			if(rc != 0)
				{
				DEBUGLOG_L(1, ("ProcessUpdate: erase on c_limbo failed %d\n", rc));
				break;
				}
			else
				{
				// erase secondary key
				limbo2Entry.client = limboEntry.client;
				limbo2Entry.size = limboEntry.size;
				memcpy(limbo2Entry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);

				rc = g_Limbo2->erase(&limbo2Entry, txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("ProcessUpdate: erase on limbo2 failed %d\n", rc));
					break;
					}
				}
			}
		else
			{
			if(clientCount >= g_GCFOS_RESIDENCY_THRESHOLD)
				{
				// delete any other entries for this hash -- they're unnecessary
				// as we've already decided we want this file (the earlier entries
				// will be deleted because the next time through they will either
				// be wanted or resident)
				deleting = true;

				// Now insert record into our Wanted set
				memcpy(&wantedEntry.SHA1, &updateEntry->SHA1, GCFOS_SHA1_LEN);
				wantedEntry.size = updateEntry->size;
				rc = g_Wanted->insert(&wantedEntry, txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("ProcessUpdate: Unexpected error:%d inserting into wanted\n", rc));
					break;
					}
				if(response != NULL)
					{
					*response = GCFOS_SRV_RESP_WANTED;
					}
				// Reposition cursor to beginning of the 
				// entries with the matching hash -- this will force the deletion of those entries
				// that signalled the inclusion -- they're no longer needed in the "limbo" db as they
				// are now wanted
				limboEntry.client = 0;
				getflags = gcfosdb_SET_RANGE;
				}
			else if(timenow.Diff(limboEntry.whenAdded) > GCFOS_RETENTION_DURATION)
				{
				// This entry too old to be kept in Limbo?
				rc = g_Limbo->erase(c_limbo);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("ProcessUpdate: erase(2) on c_limbo failed %d\n", rc));
					break;
					}
				else
					{
					// erase secondary key
					limbo2Entry.client = limboEntry.client;
					limbo2Entry.size = limboEntry.size;
					memcpy(limbo2Entry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);

					rc = g_Limbo2->erase(&limbo2Entry, txn);
					if(rc != 0)
						{
						DEBUGLOG_L(1, ("ProcessUpdate: erase(2) on limbo2 failed %d\n", rc));
						break;
						}
					}
				// Note that although it has been deleted, it is still counted, so that
				// even if there are several old records deleted, it could still trigger
				// the file as being wanted.
				
				
				
				//TODO: Handle the migration of this old entry to local-unique entry for each client


				}
			}
		}

	g_Limbo->closeCursor(c_limbo);
	return rc;
}

void ProcessLimboEntries()
	{
	UINT32			recordsRead = 0;
	gcfosdbCursor	*c_limbo;
	GCFOS_LIMBO_2_ENTRY limbo2Entry;
	GCFOS_LIMBO_ENTRY limboEntry;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	GCFOS_UsefulTime timenow;
	GCFOS_CLIENTID	cur_client;
	int				rc;
	UINT64			tot_size, client_size;
	UINT64			tot_recs = 0;
	Hash_FileManager<GCFOS_LOCAL_ENTRY> hfm;
	GCFOS_LOCAL_ENTRY newentry;
	std::string		LCUD_filename;

	DEBUGLOG_L(2, ("ProcessLimboEntries: Entry\n"));

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("ProcessLimboEntries: failed to begin txn\n"));
		return;
		}

	if(g_Limbo2->createCursor(&c_limbo, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) != 0)
		{
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("ProcessLimboEntries: failed to get limbo cursor\n"));
		return;
		}

	getflags = gcfosdb_FIRST;
	tot_size = 0;
	hfm.InitializeSet();
	client_size = 0;
	cur_client = 0;
	recordsRead = 0;
	while(true)
		{
		rc = g_Limbo2->get(c_limbo, (PUCHAR)&limbo2Entry, getflags | gcfosdb_READ_UNCOMMITTED, txn);
		limboEntry.client = limbo2Entry.client;
		limboEntry.size = limbo2Entry.size;
		memcpy(limboEntry.SHA1, limbo2Entry.SHA1, GCFOS_SHA1_LEN);
		limboEntry.whenAdded = limbo2Entry.whenAdded;
		getflags = gcfosdb_NEXT;
		if(rc != 0 || limbo2Entry.client != cur_client)
			{
			if(cur_client > 0)
				{
				tot_recs += recordsRead;
				tot_size += client_size;
				DEBUGLOG_L(3, ("ProcessLimboEntries: Client:%u Read:%u (%u GB) Unique:%u\n", cur_client, recordsRead, (UINT32)(client_size >> 30LL), (UINT)hfm.Size(true)));
				if(hfm.Size(true) > 0)
					{
					g_Limbo2->closeCursor(c_limbo);
					// We have to migrate the old entries to LCUD db now
					if(hfm.Save(cur_client, txn) == false)
						{
						gcfosdb::AbortTxn(txn);
						}
					else
						{
						rc = gcfosdb::CommitTxn(txn);
						if(rc != 0)
							{
							DEBUGLOG_L(1, ("ProcessLimboEntries: failed to commit txn, %d\n", rc));
							}
						}
					if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
						{
						DEBUGLOG_L(1, ("ProcessLimboEntries: failed to begin txn(2)\n"));
						return;
						}
					rc = g_Limbo2->createCursor(&c_limbo, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn);
					if(rc != 0)
						{
						gcfosdb::AbortTxn(txn);
						DEBUGLOG_L(1, ("ProcessLimboEntries: failed to get limbo cursor, %d\n", rc));
						return;
						}
					getflags = gcfosdb_SET_RANGE;
					}
				}
			hfm.InitializeSet();
			client_size = 0;
			cur_client = limbo2Entry.client;
			recordsRead = 0;
			hfm.Load(cur_client);
			if(getflags == gcfosdb_SET_RANGE)
				{
				// because the txn and cursor have been re-created
				// we must get the same data from the cursor again
				continue;
				}
			if(rc != 0)
				break;
			}

		if(timenow.Diff(limboEntry.whenAdded) > GCFOS_RETENTION_DURATION)
			{
			// We have located a record too old -- this is a file/hash to be considered "unique"
			// to this particular client. Store the record in the in-memory db, for later writing
			// and merging into this client's unique database (stored in the cloud)
			memcpy(newentry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
			newentry.size = limbo2Entry.size;
			if(!hfm.Insert(newentry))
				{
				DEBUGLOG_L(1, ("ProcessLimboEntries: insert into hfm failed\n"));
				}
			rc = g_Limbo->erase(&limboEntry, txn);
			if(rc != 0)
				{
				DEBUGLOG_L(1, ("ProcessLimboEntries: Delete failed on limbo(%d)\n", rc));
				}
			rc = g_Limbo2->erase(c_limbo);
			if(rc != 0)
				{
				DEBUGLOG_L(1, ("ProcessLimboEntries: Delete failed on limbo2(%d)\n", rc));
				}
			}

		recordsRead++;
		client_size += limboEntry.size;
		}

	gcfosdb::closeCursor(c_limbo);
	gcfosdb::CommitTxn(txn);

	_tprintf(_T("ProcessLimboEntries: Complete. Summary: Total records = %I64u, total size = %u GB\n"), tot_recs, (uint32_t)(tot_size >> 30));
	}

void DeleteIncompleteSessionRecords()
	{
	// this deletes incomplete sessions, for example if GCFOS server would to exit abnormally it would leave
	// all open-sessions in an incomplete state. Locate all these records and delete them, using the end
	// time of un-set to locate them. This is only ever called at initialization, and not during normal
	// processing.
	gcfosdbCursor	*c_sessions;
	GCFOS_SESSION_ENTRY session;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	int				rc;
	UINT32			count = 0;

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("DeleteIncompleteSessionRecords: failed to begin txn\n"));
		return;
		}

	rc = g_Sessions->createCursor(&c_sessions, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("DeleteIncompleteSessionRecords: failed to create cursor (%d)\n", rc));
		return;
		}

	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Sessions->get(c_sessions, (PUCHAR)&session, getflags | gcfosdb_READ_UNCOMMITTED, txn);
		if(rc != 0)
			{
			if(rc == gcfosdb_LOCK_DEADLOCK)
				{
				if(c_sessions)
					{
					gcfosdb::closeCursor(c_sessions);
					c_sessions = NULL;
					}
				if(txn)
					{
					gcfosdb::AbortTxn(txn);
					txn = NULL;
					}
				if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
					{
					DEBUGLOG_L(1, ("DeleteIncompleteSessionRecords: failed to begin txn for recovering from deadlock\n"));
					break;
					}
				getflags = gcfosdb_FIRST;
				continue; // retry
				}
			if(rc == gcfosdb_NOTFOUND)
				break;
			DEBUGLOG_L(1, ("DeleteIncompleteSessionRecords: failed to get on cursor (%d)\n", rc));
			break;
			}
		if(session.end.GetUsefulValue() == 0)
			{
			// this is an incomplete session, delete it
			g_Sessions->erase(c_sessions);
			count++;
			}
		getflags = gcfosdb_NEXT;
		}

	gcfosdb::closeCursor(c_sessions);
	gcfosdb::CommitTxn(txn);

	printf("DeleteIncompleteSessionRecords deleted %u records\n", count);
	}

bool AddSessionRecord(PGCFOS_CONNECT_STATE context)
	{
	GCFOS_SESSION_ENTRY			entry;
	int							rc;

	if(context->session_record > 0)
		{
		if(context->count_queries == 0)
			{
			return true; // we've already recorded the start of this session
			}
		// We are changing context, so we'll be writing two (or more)
		// records.  Flush the existing record
		UpdateSessionRecord(context, GCFOS_SESSION_END_REASON::SWITCH_CONTEXT);
		}

	entry.clientid = context->client;
	memcpy(&entry.connectedTo, &context->connectedTo, sizeof(SOCKADDR));
	rc = g_Sessions->insert(&entry, NULL, 0, gcfosdb_APPEND);
	if(rc == 0)
		{
		context->session_record = entry.recno;
		}
	else
		{
		DEBUGLOG_L(1, ("AddSessionRecord: Failed to insert session record (%d)\n", rc));
		return false;
		}

	return true;
	}

bool UpdateSessionRecord(PGCFOS_CONNECT_STATE context, GCFOS_SESSION_END_REASON reason)
	{
	int							rc;
	GCFOS_SESSION_ENTRY			entry;

	entry.recno = context->session_record;
	if(entry.recno == 0)
		return true; // no record to update

	rc = g_Sessions->find(&entry);
	if(rc == 0)
		{
		entry.end.ObtainTimeNow();
		entry.donations = context->count_donations;
		entry.end_reason = reason;
		entry.limbo_results = context->count_limbo_results;
		entry.queries = context->count_queries;
		entry.resident_hits = context->count_resident_hits;
		entry.retrieves = context->count_retrieves;
		// convert KB to MB, round UP if more than 512 (0x200)
		entry.retrieve_MB = (UINT32)((context->count_retrieve_KB + 0x200) >> (UINT64)10);
		entry.clientid = context->client;
		entry.blks_queried = context->count_blks_queried;
		entry.blks_stored = context->count_blks_stored;
		entry.blks_retrieved = context->count_blks_retrieved;
		rc = g_Sessions->insert(&entry);
		if(rc != 0)
			{
			DEBUGLOG_L(1, ("UpdateSessionRecord: Failed to update session record (%d)\n", rc));
			return false;
			}
		}
	else
		{
		DEBUGLOG_L(1, ("UpdateSessionRecord: Failed to locate session record (%d)\n", rc));
		return false;
		}

	return true;
	}

void ReportSessionActivity()
	{
	gcfosdbCursor	*c_sessions;
	GCFOS_SESSION_ENTRY session;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	int				rc;
	char			hostname[32] = { 0 };
	UINT32			session_count = 0;
	time_t			starttime;

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("ReportSessionActivity: failed to begin txn\n"));
		return;
		}

	rc = g_Sessions->createCursor(&c_sessions, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("ReportSessionActivity: failed to create cursor (%d)\n", rc));
		return;
		}

	printf("Session activity report:\n");
	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Sessions->get(c_sessions, (PUCHAR)&session, getflags | gcfosdb_READ_UNCOMMITTED, txn);
		if(rc != 0)
			{
			if(rc == gcfosdb_LOCK_DEADLOCK)
				{
				if(c_sessions)
					{
					gcfosdb::closeCursor(c_sessions);
					c_sessions = NULL;
					}
				if(txn)
					{
					gcfosdb::AbortTxn(txn);
					txn = NULL;
					}
				if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
					{
					DEBUGLOG_L(1, ("ReportSessionActivity: failed to begin txn for recovering from deadlock\n"));
					break;
					}
				getflags = gcfosdb_FIRST;
				continue; // retry
				}
			if(rc == gcfosdb_NOTFOUND)
				break;
			DEBUGLOG_L(1, ("ReportSessionActivity: failed to get on cursor (%d)\n", rc));
			break;
			}

		getnameinfo(&session.connectedTo, sizeof(SOCKADDR), hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST);
		session_count++;
		session.start.GetTime(&starttime);
		PrintTime(NULL, false, &starttime);
		printf("%s,%u,", hostname, session.clientid);
		if(session.end_reason != STILL_CONNECTED)
			{
			printf("queries=%u, resident=%u, limbo=%u, donations=%u",
				session.queries, session.resident_hits, session.limbo_results, session.donations);
			}
		if(session.retrieves > 0)
			{
			printf(", retrieves=%u (%u MB)", session.retrieves, session.retrieve_MB);
			}
		if(session.blks_queried > 0)
			{
			printf(", blks Q=%I64u (%u MB)", session.blks_queried, (UINT32)((session.blks_queried * (UINT64)GCFOS_BLOCK_SIZE)>>20LL));
			}
		if(session.blks_stored > 0)
			{
			printf(", blks stored=%I64u (%u MB)", session.blks_stored, (UINT32)((session.blks_stored * (UINT64)GCFOS_BLOCK_SIZE)>>20LL));
			}
		if(session.blks_retrieved > 0)
			{
			printf(", blk retrieves=%I64u (%u MB)", session.blks_retrieved, (UINT32)((session.blks_retrieved * (UINT64)GCFOS_BLOCK_SIZE)>>20LL));
			}
		if(session.end.GetUsefulValue() > 0)
			{
			printf(", duration=%u sec", session.end.Diff(session.start));
			}	
		switch(session.end_reason)
			{
			case STILL_CONNECTED:
				printf(", connected");
				break;
			case TIMEOUT:
				printf(", timeout");
				break;
			case FORCED:
				printf(", aborted");
				break;
			case SWITCH_CONTEXT: // don't think it matters to print anything different when switching
			case NORMAL:
			default:
				break;
			}
		printf("\n");
		getflags = gcfosdb_NEXT;
		}
	printf("Report complete, %u sessions printed\n", session_count);
	gcfosdb::closeCursor(c_sessions);
	gcfosdb::CommitTxn(txn);
	}

#if 0
// This routine is no longer used as its functionality is now implemented by ProcessUpdate()
// and ProcessLimboEntries().

void ScanLimboListForCandidates()
{
	Ipp8u			LastSHA1[GCFOS_SHA1_LEN];
	UINT32			clientCount = 0;
	bool			deleting = false;
	UINT32			deleted = 0;
	UINT32			wanted = 0;
	UINT32			recordsRead = 0;
	GCFOS_UsefulTime timenow;
	UINT64			sizeOfWantedFiles = 0;
	gcfosdbCursor	*c_limbo;
	GCFOS_LIMBO_ENTRY limboEntry;
	GCFOS_RESIDENT_ENTRY residentEntry;
	GCFOS_WANTED_ENTRY wantedEntry;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	int				rc;

	memset(&LastSHA1, 0xff, sizeof(LastSHA1));

	DEBUGLOG_L(2, ("Enter ScanLimboListForCandidates\n"));

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to begin txn\n"));
		return;
		}

	if(g_Limbo->createCursor(&c_limbo, DB_CURSOR_BULK | DB_READ_UNCOMMITTED, txn) != 0)
		{
		DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to get limbo cursor\n"));
		return;
		}

	getflags = DB_FIRST;

	while(true)
		{
		rc = g_Limbo->get(c_limbo, (PUCHAR)&limboEntry, getflags | DB_READ_UNCOMMITTED, txn);
		if(rc != 0)
			{
			if(rc == DB_LOCK_DEADLOCK)
				{
ScanLimboListForCandidates_deadlock:
				if(c_limbo)
					{
					c_limbo->close();
					c_limbo = NULL;
					}
				if(txn)
					{
					gcfosdb::AbortTxn(txn);
					txn = NULL;
					}
				if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
					{
					DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to begin txn for recovering from deadlock\n"));
					break;
					}
				// now re-open a new cursor, starting again for this SHA1 hash
				if(g_Limbo->createCursor(&c_limbo, DB_CURSOR_BULK | DB_READ_UNCOMMITTED, txn) != 0)
					{
					DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to get NEW limbo cursor\n"));
					break;
					}
				// indicate we have to re-position this cursor
				getflags = DB_SET_RANGE;
				limboEntry.client = 0;
				recordsRead -= (clientCount + 1); // Reduce records-read because we will re-read them
				clientCount = 0; // reset count
				}
			if(rc == DB_NOTFOUND)
				{
				break; // we're all done here
				}
			DEBUGLOG_L(1, ("ScanLimboListForCandidates: Unexpected error:%d from c_limbo\n", rc));
			break;
			}

		recordsRead++;

		if(memcmp(&LastSHA1, &limboEntry.SHA1, GCFOS_SHA1_LEN) != 0)
			{
			// This marks the start of a new hash in the input file
			if(getflags == DB_NEXT)
				{
				// this code is here so that the transactions can be kept short -- one new
				// transaction for every SHA1 key encountered
				if(txn != NULL)
					{
					// explicitly close cursor (this would've been done by commit anyway)
					if(c_limbo)
						{
						c_limbo->close();
						c_limbo = NULL;
						}
					gcfosdb::CommitTxn(txn, 0);
					txn = NULL;
					}

				if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
					{
					DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to begin NEW txn\n"));
					break;
					}

				if(g_Limbo->createCursor(&c_limbo, DB_CURSOR_BULK | DB_READ_UNCOMMITTED, txn) != 0)
					{
					DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to get re-open limbo cursor\n"));
					break;
					}
				getflags = DB_SET_RANGE;
				recordsRead--;
				continue; // re-get the same record but with the new cursor
				}

			// Check to see if this file is already resident
			memcpy(residentEntry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
			residentEntry.size = limboEntry.size;
			if(g_Resident->find(&residentEntry, txn) == 0)
				{
				// this entry is already resident -- delete this one and subsequent ones
				deleting = true;
				}
			else
				{
				// it's not resident, so check to see if this is already wanted
				memcpy(wantedEntry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
				wantedEntry.size = limboEntry.size;
				if(g_Wanted->find(&wantedEntry, txn) == 0)
					{
					// this entry is already wanted -- delete this one and subsequent ones
					deleting = true;
					}
				else
					{
					deleting = false;
					}
				}
			memcpy(LastSHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
			
			// reset the count
			clientCount = 0;
			}
		else
			{
			// hash has not changed since new hash discovered
			// are we deleting these entries (because they're already wanted?)
			// Nothing to do, fall through (we may need to delete the first entry)
			}

		getflags = DB_NEXT;

		clientCount++;
		if(deleting)
			{
			if(g_Limbo->erase(c_limbo) == DB_LOCK_DEADLOCK)
				goto ScanLimboListForCandidates_deadlock;
			deleted++;
			}
		else
			{
			if(clientCount >= GCFOS_RESIDENCY_THRESHOLD)
				{
				// delete any other entries for this hash -- they're unnecessary
				// as we've already decided we want this file (the earlier entries
				// will be deleted because the next time through they will either
				// be wanted or resident)
				deleting = true;

				memcpy(wantedEntry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
				wantedEntry.size = limboEntry.size;

				sizeOfWantedFiles += wantedEntry.size;

				// Now insert record into our Wanted set
				g_Wanted->insert(&wantedEntry, txn);
				wanted++;
				// Reposition cursor to beginning of the 
				// entries with the matching hash -- this will force the deletion of those entries
				// that signalled the inclusion -- they're no longer needed in the "limbo" db as they
				// are now wanted
				limboEntry.client = 0;
				c_limbo->close();
				c_limbo = NULL;
				if(g_Limbo->createCursor(&c_limbo, DB_CURSOR_BULK | DB_READ_UNCOMMITTED, txn) != 0)
					{
					DEBUGLOG_L(1, ("ScanLimboListForCandidates: failed to get NEW limbo cursor\n"));
					break;
					}
				getflags = DB_SET_RANGE;
				recordsRead -= clientCount; // Reduce records-read because we will re-read them
				}
			else if(timenow.Diff(limboEntry.whenAdded) > GCFOS_RETENTION_DURATION)
				{
				// This entry too old to be kept in Limbo?
				g_Limbo->erase(c_limbo);
				deleted++;
				// Note that although it has been deleted, it is still counted, so that
				// even if there are several old records deleted, it could still trigger
				// the file as being wanted.
				
				
				
				//TODO: Handle the migration of this old entry to local-unique entry for each client


				}
			}
		}

	c_limbo->close();
	if(txn != NULL)
		{
		gcfosdb::CommitTxn(txn, 0);
		}

	DEBUGLOG_L(2, ("LimboList processing complete\n"));
	DEBUGLOG_L(2, ("%u Records read\n", recordsRead));
	DEBUGLOG_L(2, ("%u Records removed from Limbo\n", deleted));
	DEBUGLOG_L(2, ("%u Records moved to wanted status\n", wanted));
	DEBUGLOG_L(2, ("Now Resident: %u, Limbo: %u, Wanted: %u\n", g_Resident->size(), g_Limbo->size(), g_Wanted->size()));
	DEBUGLOG_L(2, ("Total size of files added to WantedList: %u GB\n", (UINT32)(sizeOfWantedFiles >> 30)));


	DEBUGLOG_L(2, ("Leaving ScanLimboListForCandidates\n"));
}
#endif   

#pragma managed(push, off)
unsigned __stdcall ValidateBlocksWorker(void * param)
	{
	VerifyRecentBlockFiles();
	InterlockedDecrement(&g_ThreadsActive);
	return 0;
	}
#pragma managed(pop)

unsigned __stdcall MigrateBlockStoreToSecondary(void * param)
	{
	UINT32									i;
	INT										idx;
	UINT32									dirid, component;
	TCHAR									szFilePath[MAX_PATH];
	System::IO::FileStream					^fs;
	System::IO::MemoryStream				^ms;
	System::String							^s_filepath;
	System::IO::FileInfo					^fi;
	System::String							^objpath;
	System::String							^dir;
	UINT32									lastdirid = UINT32_MAX;
	UINT32									migrated = 0;
	GCFOS_UsefulTime						lastupdatetime;
	UINT32									curoffset;
	UINT32									LastPosition = 0;
	UINT32									BytesCopied;
	bool									bEntireMigration;

	System::Collections::Generic::List<System::String ^> ^filelist = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;

	if(g_Repo2 == NULL || System::Object::ReferenceEquals(g_SecondaryBlockStoreLocation, nullptr))
		{
		DEBUGLOG_L(4, ("MigrateBlockStoreToSecondary: Not configured for secondary block store\n"));
		goto MigrateBlockStoreToSecondary_cleanup;
		}

	// first, do a sync/validation/migration of all existing block data to secondary location

	DEBUGLOG_L(3, ("MigrateBlockStoreToSecondary: Beginning sync\n"));

	for(i = 0; i < g_blks_fileID; i++)
		{
		if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
			{
			break;
			}
		dirid = i / GCFOS_BLOCKSTORE_FILES_PER_DIR;
		component = i % GCFOS_BLOCKSTORE_FILES_PER_DIR;
		if(lastdirid != dirid)
			{
			_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_OBJECT_DIR_NAMING_FMT, dirid);
			dir = gcnew System::String(szFilePath);
			if(!g_Repo2->GetList(dir, filelist, sizes, g_SecondaryBlockStoreLocation))
				{
				break;
				}
			lastdirid = dirid;
			}

		_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, dirid, component);
		s_filepath = gcnew System::String(szFilePath);
		_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_OBJECT_NAMING_FMT, dirid, component);
		objpath = gcnew System::String(szFilePath);
		try {
			fi = gcnew System::IO::FileInfo(s_filepath);
			idx = filelist->IndexOf(objpath);
			if(idx != -1 && sizes[idx] == fi->Length)
				{
				continue; // file already exists and is correct size
				}
			fs = gcnew System::IO::FileStream(s_filepath, System::IO::FileMode::Open, System::IO::FileAccess::Read);
			if(!g_Repo2->Put(objpath, fs, g_SecondaryBlockStoreLocation))
				{
				DEBUGLOG_L(1, ("MigrateBlockStoreToSecondary: Failed to sync %s - aborting\n", CStringA(objpath)));
				goto MigrateBlockStoreToSecondary_cleanup;
				}
			DEBUGLOG_L(5, ("MigrateBlockStoreToSecondary: Synced %s successfully\n", CStringA(objpath)));
			migrated++;
			fs->Close();
			}
		catch(...)
			{
			break; // we're done -- file does not exist or could not be copied
			}
		}
	DEBUGLOG_L(3, ("MigrateBlockStoreToSecondary: %u copied\n", migrated));

	// "i" represents the current in-progress file that we're writing (might be behind g_blks_fileID)
	// especially during busy write periods

	// We migrate(copy) the existing file (that is currently being written to by another thread).
	// Then, we will re-copy the file when one of the following is true:
	//    - The other thread has written/closed the existing file
	//    - A maximum time period has expired (I imagine around 30 minutes or so being reasonable)
	//      (or) a minimum amount of data has been written BUT the file has not been written to within a minute(or so)

	if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
		goto MigrateBlockStoreToSecondary_cleanup;

	// determine "curoffset" by examining object size (if exists) 
	dirid = i / GCFOS_BLOCKSTORE_FILES_PER_DIR;
	component = i % GCFOS_BLOCKSTORE_FILES_PER_DIR;
	_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_OBJECT_NAMING_FMT, dirid, component);
	objpath = gcnew System::String(szFilePath);
	try {
		g_Repo2->GetList(objpath, filelist, sizes, NULL, g_SecondaryBlockStoreLocation);
		if(filelist[0]->Equals(objpath))
			{
			curoffset = sizes[0];
			DEBUGLOG_L(4, ("MigrateBlockStoreToSecondary: Current size of %s is %u\n", CStringA(objpath), curoffset));
			}
		else
			curoffset = 0;
		}
	catch(...)
		{
		curoffset = 0;
		}

	while(true)
		{
		if(i < g_blks_fileID
		|| ((g_blks_out_offset - curoffset) / 0x100000 > g_BlockStoreSecondaryRepoMinDataChange_MB && LastPosition == g_blks_out_offset)
		|| ((g_blks_out_offset - curoffset) > 0 && (UINT32)GCFOS_UsefulTime().Diff(lastupdatetime) > g_BlockStoreSecondaryRepoMaxTime_Sec))
			{
			dirid = i / GCFOS_BLOCKSTORE_FILES_PER_DIR;
			component = i % GCFOS_BLOCKSTORE_FILES_PER_DIR;
			_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, dirid, component);
			s_filepath = gcnew System::String(szFilePath);
			_stprintf_s(szFilePath, MAX_PATH, GCFOS_BLOCKS_OBJECT_NAMING_FMT, dirid, component);
			objpath = gcnew System::String(szFilePath);
			try {
				// we have to be careful here -- the stream indicated at fs is being extended by other threads, so we cannot assume its size will stay
				// the same. Let's get a snapshot of the size at a particular moment and copy that amount
				fs = gcnew System::IO::FileStream(s_filepath, System::IO::FileMode::Open, System::IO::FileAccess::Read, System::IO::FileShare::ReadWrite);
				BytesCopied = (UINT32)fs->Length;
				ms = gcnew System::IO::MemoryStream(BytesCopied);
				fs->CopyTo(ms, BytesCopied);
				
				if(i < g_blks_fileID && fs->Length == ms->Length)
					bEntireMigration = true; // we copied the entire file (and a new one is now being used by other thread)
				else
					bEntireMigration = false;

				fs->Close();
				BytesCopied = (UINT32)ms->Length;
				ms->Position = 0;
				if(!g_Repo2->Put(objpath, ms, g_SecondaryBlockStoreLocation))
					{
					DEBUGLOG_L(1, ("MigrateBlockStoreToSecondary: Failed to store %s\n", CStringA(objpath)));
					}
				else
					{
					migrated++;
					if(bEntireMigration)
						{
						// we have finished a complete file, go on to next one now
						DEBUGLOG_L(4, ("MigrateBlockStoreToSecondary: Migrated %s successfully\n", CStringA(objpath)));
						i++;
						curoffset = 0;
						}
					else
						{
						DEBUGLOG_L(4, ("MigrateBlockStoreToSecondary: %s partially migrated successfully (%u)\n", CStringA(objpath), BytesCopied));
						curoffset = BytesCopied;
						}
					}
				lastupdatetime.ObtainTimeNow();
				delete ms;

				}
			catch(...)
				{
				DEBUGLOG_L(1, ("MigrateBlockStoreToSecondary: General exception attempting to store %s\n", CStringA(objpath)));
				break; // we're done -- file does not exist or could not be copied
				}
			}

		LastPosition = g_blks_out_offset;
	
		// wait a minute before inspecting 
		if(WaitForSingleObject(g_ExitSignalled, 60 * 1000) == WAIT_OBJECT_0)
			break;
		}


MigrateBlockStoreToSecondary_cleanup:
	DEBUGLOG_L(4, ("MigrateBlockStoreToSecondary: Exiting (%u uploaded)\n", migrated));
	InterlockedDecrement(&g_ThreadsActive);
	return 0;
	}

void DumpSessionsToLogFiles()
	{
	GCFOS_SESSION_ENTRY						session_rec;
	gcfosdbCursor							*c_sessions;
	gcfosdbTxn								*txn;
	UINT32									getflags;
	int										rc;
	UINT32									count = 0;
	HANDLE									hLogFile = INVALID_HANDLE_VALUE;
	time_t									rec_time;
	struct tm								timeinfo_last;
	struct tm								timeinfo_rec;
	TCHAR									szLogFileName[32];
	DWORD									dwWritten;
	char									szHeader[256] = "Time,Duration,Client#,ConnectedTo,Note,Donations,Queries,Resident Hits,In Limbo,Retrieve MB,Retrieves";
	char									szFormatStr[128] = "%02u:%02u:%02u,%u,%u,%s,%s,%u,%u,%u,%u,%u,%u";
	DWORD									dwHeader_Len;
	char									szRecord[256];
	DWORD									reclen;
#ifndef ULTRABAC_CLOUD_USE
	CStringA								strA_clientname;
	GCFOS_CLIENT_ENTRY						client_rec;
#endif//ULTRABAC_CLOUD_USE
	CStringA								strA_reason;
	char									ipAddress[INET_ADDRSTRLEN];

	DEBUGLOG_L(5, ("DumpSessionsToLogFiles: Entry\n"));

#ifndef ULTRABAC_CLOUD_USE
	strcat(szHeader, ",ClientName");
	strcat(szFormatStr, ",%s");
	if(g_bDedupeBlocks)
		{
		strcat(szHeader, ",Blocks Queried,Blocks Stored,Blocks Retrieved\n");
		strcat(szFormatStr, ",%I64u,%I64u,%I64u");
		}
#endif//ULTRABAC_CLOUD_USE
	strcat(szHeader, "\n");
	dwHeader_Len = (DWORD)strlen(szHeader);
	strcat(szFormatStr, "\n"); // end of preparation of formatting string

	CreateDirectory(L"Logs", NULL);
	timeinfo_last.tm_mday = 0;

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed to begin txn\n"));
		return;
		}

	rc = g_Sessions->createCursor(&c_sessions, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed to create cursor (%d)\n", rc));
		return;
		}

	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Sessions->get(c_sessions, (PUCHAR)&session_rec, getflags | gcfosdb_READ_UNCOMMITTED, txn);
		if(rc != 0)
			{
			if(rc == gcfosdb_LOCK_DEADLOCK)
				{
				if(c_sessions)
					{
					gcfosdb::closeCursor(c_sessions);
					c_sessions = NULL;
					}
				if(txn)
					{
					gcfosdb::AbortTxn(txn);
					txn = NULL;
					}
				if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
					{
					DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed to begin txn for recovering from deadlock\n"));
					break;
					}
				getflags = gcfosdb_FIRST;
				continue; // retry
				}
			if(rc == gcfosdb_NOTFOUND)
				break;
			DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed to get on cursor (%d)\n", rc));
			break;
			}
		getflags = gcfosdb_NEXT;
		if(session_rec.end.GetUsefulValue() == 0)
			{
			// this is an incomplete session, ignore it
			continue;
			}
		session_rec.start.GetTime(&rec_time);
		gmtime_s(&timeinfo_rec, &rec_time);
		if(timeinfo_rec.tm_mday != timeinfo_last.tm_mday)
			{
			// date has changed, open the new log file
			if(hLogFile != INVALID_HANDLE_VALUE)
				{
				CloseHandle(hLogFile);
				hLogFile = INVALID_HANDLE_VALUE;
				}
			_stprintf_s(szLogFileName, CHARCOUNT(szLogFileName), L"logs\\log_%02u-%02u-%02u.csv", timeinfo_rec.tm_year % 100, timeinfo_rec.tm_mon + 1, timeinfo_rec.tm_mday);
			hLogFile = CreateFile(szLogFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
			if(hLogFile == INVALID_HANDLE_VALUE)
				{
				DEBUGLOG_L(1, ("DumpSessionsToLogFiles: unable to open '%S', error: %u\n", szLogFileName, GetLastError()));
				break;
				}
			if(GetLastError() == ERROR_ALREADY_EXISTS)
				{
				SetFilePointer(hLogFile, 0, NULL, FILE_END); // append to end
				}
			else
				{
				// Created a new log file, write the header line (titles for columns)
				if(!WriteFile(hLogFile, &szHeader, dwHeader_Len, &dwWritten, NULL) || dwWritten != dwHeader_Len)
					{
					DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed writing to '%S', error: %u\n", szLogFileName, GetLastError()));
					break;
					}
				}
			}

#ifndef ULTRABAC_CLOUD_USE
		client_rec.clientid = session_rec.clientid;
		if(g_Clients->find(&client_rec, txn) == 0)
			{
			strA_clientname = client_rec.szName;
			}
		else
			{
			strA_clientname = "<unknown>";
			}
#endif//ULTRABAC_CLOUD_USE

		switch(session_rec.end_reason)
			{
			case NORMAL:
				strA_reason = "";
				break;
			case TIMEOUT:
				strA_reason = "timeout";
				break;
			case FORCED:
				strA_reason = "forced disconnect";
				break;
			case SWITCH_CONTEXT:
				strA_reason = "switched";
				break;
			default:
				strA_reason = "<unknown>";
				break;
			}

		if(0 != getnameinfo(&session_rec.connectedTo, sizeof(SOCKADDR), ipAddress, sizeof(ipAddress), NULL, 0, NI_NUMERICHOST))
			{
			strcpy(ipAddress, "<unknown>");
			}

		// "Time,Duration,Client#,ConnectedTo,Note,Donations,Queries,Resident Hits,In Limbo,Retrieve MB,Retrieves[,ClientName][,Blocks Queried,Blocks Stored,Blocks Retrieved]\n
		// %02u:%02u:%02u,%u,%u,%s,%s,%u,%u,%u,%u,%u[,%s][,%I64u,%I64u,%I64u]
#ifdef ULTRABAC_CLOUD_USE
		sprintf_s(szRecord, CHARCOUNT(szRecord), szFormatStr,
			timeinfo_rec.tm_hour, timeinfo_rec.tm_min, timeinfo_rec.tm_sec, //time
			session_rec.end.Diff(session_rec.start),
			session_rec.clientid,
			ipAddress,
			strA_reason,
			session_rec.donations,
			session_rec.queries,
			session_rec.resident_hits,
			session_rec.limbo_results,
			session_rec.retrieve_MB,
			session_rec.retrieves);
#else
		if(g_bDedupeBlocks)
			{
			sprintf_s(szRecord, CHARCOUNT(szRecord), szFormatStr,
				timeinfo_rec.tm_hour, timeinfo_rec.tm_min, timeinfo_rec.tm_sec, //time
				session_rec.end.Diff(session_rec.start),
				session_rec.clientid,
				ipAddress,
				strA_reason,
				session_rec.donations,
				session_rec.queries,
				session_rec.resident_hits,
				session_rec.limbo_results,
				session_rec.retrieve_MB,
				session_rec.retrieves,
				strA_clientname,
				session_rec.blks_queried,
				session_rec.blks_stored,
				session_rec.blks_retrieved);
			}
		else
			{
			sprintf_s(szRecord, CHARCOUNT(szRecord), szFormatStr,
				timeinfo_rec.tm_hour, timeinfo_rec.tm_min, timeinfo_rec.tm_sec, //time
				session_rec.end.Diff(session_rec.start),
				session_rec.clientid,
				ipAddress,
				strA_reason,
				session_rec.donations,
				session_rec.queries,
				session_rec.resident_hits,
				session_rec.limbo_results,
				session_rec.retrieve_MB,
				session_rec.retrieves,
				strA_clientname);
			}
#endif//ULTRABAC_CLOUD_USE
		reclen = (DWORD)strlen(szRecord);
		if(!WriteFile(hLogFile, &szRecord, reclen, &dwWritten, NULL) || dwWritten != reclen)
			{
			DEBUGLOG_L(1, ("DumpSessionsToLogFiles: failed writing to '%S', error: %u\n", szLogFileName, GetLastError()));
			break;
			}

		g_Sessions->erase(c_sessions);
		count++;
		}

	DEBUGLOG_L(5, ("DumpSessionsToLogFiles: wrote a total of %u records\n", count));

	if(c_sessions != NULL)
		{
		gcfosdb::closeCursor(c_sessions);
		}
	if(txn != NULL)
		{
		gcfosdb::CommitTxn(txn);
		}
	if(hLogFile != INVALID_HANDLE_VALUE)
		{
		CloseHandle(hLogFile);
		}
	}
   
     
   
 
 
 
             
    
 
     
