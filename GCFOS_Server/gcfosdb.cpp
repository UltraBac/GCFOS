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
#include <Project.h>

// gcfosdb Functions (helper class)

// this is the LMDB implementation

#pragma managed(push, off)

// define storage for gcfosdb statics
MDB_env* gcfosdb::g_LMDB_env = NULL;
UINT64 gcfosdb::m_env_size;
GCFOS_UsefulTime gcfosdb::LastChangeTime;
bool gcfosdb::m_bChangedSinceSync = false;

__inline void * gcfosdb_memcpy(void *d, const void *s, size_t c)
	{
    BYTE *pS = (BYTE *) s;
    BYTE *pD = (BYTE *) d;
    BYTE *pE = (BYTE *) (((BYTE *)s) + c);

    while (pS != pE)
        *(pD++) = *(pS++);

    return d;
	}
		
int gcfosdb::CreateEnvironment(LPCSTR pszDir/* = NULL*/)
	{
	MDB_envinfo envinfo;
	if(pszDir == NULL)
		{
		pszDir = ".\\gcfosdb";
		}

	int rc;
	rc = mdb_env_create(&g_LMDB_env);
	if(rc != 0)
		return rc;
	rc = mdb_env_set_maxdbs(g_LMDB_env, 10); // maximum of 10 named databases
	if(rc != 0)
		return rc;
	m_env_size = (UINT64)g_dwInitialEnvSize *(INT64)0x100000;
	rc = mdb_env_set_mapsize(g_LMDB_env, m_env_size);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("unable to set db size %d\n", rc));
		return rc;
		}

	CreateDirectoryA(pszDir, NULL);
	rc = mdb_env_open(g_LMDB_env, pszDir, MDB_NOTLS | MDB_NOSYNC | MDB_WRITEMAP, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("unable to open db env %d\n", rc));
		return rc;
		}
	mdb_env_info(g_LMDB_env, &envinfo);
	m_env_size = envinfo.me_mapsize;

	DEBUGLOG_L(4, ("DB Environment size: %I64x\n", m_env_size));
	return rc;
	}

int	gcfosdb::CloseEnvironment()
	{
	if(g_LMDB_env == NULL)
		return 0;

	DEBUGLOG_L(4, ("Closing environment\n"));
	Checkpoint();
	mdb_env_close(g_LMDB_env);
	g_LMDB_env = NULL;
	return 0;
	}

int	gcfosdb::BeginTxn(MDB_txn *parent, MDB_txn **result, uint32_t flags)
	{
	return mdb_txn_begin(g_LMDB_env, parent, flags, result);
	}

int	gcfosdb::CommitTxn(MDB_txn *txn)
	{
	return mdb_txn_commit(txn);
	}

int	gcfosdb::AbortTxn(MDB_txn *txn)
	{
	mdb_txn_abort(txn);
	return 0;
	}

int	gcfosdb::Checkpoint()
	{
	int rc;
	rc = mdb_env_sync(g_LMDB_env, 1);
	m_bChangedSinceSync = false;
	return rc;
	}


bool gcfosdb::verify(const char *tablename)
	{
	return true;
	}

bool gcfosdb::open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, int32_t flags /* = -1*/, int dbtype, bool bCompact /*= false*/)
	{
	MDB_txn			*txn;
	int				rc;
	MDB_cursor		*cursor;
	MDB_val			Key, Value;

	if(flags < 0)
		flags = MDB_CREATE;
	else
		flags |= MDB_CREATE;

	if(dbtype == gcfosdb_RECNO)
		{
		flags |= MDB_INTEGERKEY;
		}

	rc = mdb_txn_begin(g_LMDB_env, NULL, 0, &txn);
	if(rc != 0)
		return false;

	rc = mdb_dbi_open(txn, tablename, flags, &t);
	if(rc != 0)
		{
		mdb_txn_abort(txn);
		return false;
		}

/////////////////////////////////	if(_stricmp(tablename, GCFOS_DBNAME_BLOCKS) == 0)                    { mdb_drop(txn, t, 0); }

	if(dbtype == gcfosdb_RECNO)
		{
		assert(k_len == sizeof(UINT32));
		// get last record number and store it
		next_recno = 1;
		rc = mdb_cursor_open(txn, t, &cursor);
		if(rc == 0)
			{
			rc = mdb_cursor_get(cursor, &Key, &Value, MDB_LAST);
			if(rc == 0)
				{
				next_recno = 1 + (*(PUINT32)Key.mv_data);
				}
			}
		}
	else
		{
		next_recno = 0; // indicate that this is not a RECNO type of table
		}

	rc = mdb_txn_commit(txn);
	key_offset = k_off;
	key_len = k_len;
	data_offset = d_off;
	data_len = d_len;

	return (rc == 0);
	}

int gcfosdb::close()
	{

	// LMDB documentation says not to close; can be problematic
	// so just invalidate the dbi value
	t = (MDB_dbi)-1; // invalid value
	return 0;
	}

int gcfosdb::ResizeLMDB(MDB_txn **txn)
	{
	int							rc;

	mdb_txn_abort(*txn);
	DEBUGLOG_L(3, ("Expanding db size\n"));
	m_env_size += (UINT64)g_dwGrowEnvSize * 0x100000LL;
	rc = mdb_env_set_mapsize(g_LMDB_env, m_env_size);
	if(rc != 0)
		{
		DEBUGLOG_L(3, ("Failed to expand db size %d\n", rc));
		mdb_txn_abort(*txn);
		return rc;
		}
	LastChangeTime.ObtainTimeNow();
	m_bChangedSinceSync = true;
	rc = mdb_txn_begin(g_LMDB_env, NULL, 0, txn);
	return rc;
	}


int gcfosdb::insert(LPVOID p, gcfosdbTxn *txn /* = NULL*/, int extra_data /* = 0*/, int flags /* = -1 */)
	{
	MDB_val			Key, Value;
	MDB_txn			*newtxn = NULL;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	assert(extra_data == 0);

	if(flags == -1)
		flags = 0;

	if(txn == NULL)
		{
		rc = mdb_txn_begin(g_LMDB_env, NULL, 0, &newtxn);
		if(rc != 0)
			return rc;
		}

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len + extra_data;

	if(next_recno > 0 && *(PUINT32)Key.mv_data == 0)
		{
		gcfosdb_memcpy(pb + key_offset, &next_recno, sizeof(UINT32));
		next_recno++;
		}

	rc = mdb_put(txn ? txn : newtxn, t, &Key, &Value, flags);
	if(rc != 0)
		{
		if(newtxn != NULL)
			{
			mdb_txn_abort(newtxn);
			}
		return rc;
		}

	if(txn == NULL)
		{
		rc = mdb_txn_commit(newtxn);
		}
	LastChangeTime.ObtainTimeNow();
	m_bChangedSinceSync = true;
	SetEvent(hNewRecordAvailable);
	return rc;
	}

int gcfosdb::erase(gcfosdbCursor *cursor)
	{
	LastChangeTime.ObtainTimeNow();
	m_bChangedSinceSync = true;
	return mdb_cursor_del(cursor, 0); 
	}

int gcfosdb::erase(PVOID p, gcfosdbTxn *txn /* = NULL */)
	{
	MDB_val			Key, Value;
	MDB_txn			*newtxn = NULL;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	if(txn == NULL)
		{
		rc = mdb_txn_begin(g_LMDB_env, newtxn, 0, &newtxn);
		if(rc != 0)
			return rc;
		}

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	rc = mdb_del(txn ? txn : newtxn, t, &Key, &Value);
	if(newtxn != NULL)
		{
		rc = mdb_txn_commit(newtxn);
		}
	m_bChangedSinceSync = true;
	LastChangeTime.ObtainTimeNow();
	return rc;
	}


int gcfosdb::find(LPVOID p, gcfosdbTxn *txn /* = NULL*/, LPVOID *data_only /* = NULL*/, PUINT32 extra_len/* = NULL*/, int flags /* = -1*/)
	{
	MDB_val			Key, Value;
	MDB_txn			*newtxn = NULL;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	if(txn == NULL)
		{
		rc = mdb_txn_begin(g_LMDB_env, txn, gcfosdb_RDONLY, &newtxn);
		if(rc != 0)
			return rc;
		}

	assert(data_only == NULL);

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	rc = mdb_get(txn ? txn : newtxn, t, &Key, &Value);
	if(rc == 0)
		{
		gcfosdb_memcpy(pb + data_offset, Value.mv_data, data_len);
		if(data_only != NULL)
			{
			assert(txn != NULL);

			//CAUTION: This pointer returned is valid ONLY for the data region it points to
			//         and only UNTIL the txn is committed/aborted __ USE WITH CARE!
			*data_only = (LPBYTE)Value.mv_data;
			if(extra_len != NULL)
				{
				*extra_len = (UINT32)Value.mv_size - data_len;
				}
			}
		}
	if(newtxn != NULL)
		{
		mdb_txn_abort(newtxn);//read-only, so abort
		}
	return rc;
	}

int gcfosdb::createCursor(gcfosdbCursor **cursor, UINT32 flags, gcfosdbTxn *txn /* = NULL*/)
	{
	return mdb_cursor_open(txn, t, cursor);
	}

int gcfosdb::closeCursor(gcfosdbCursor *cursor)
	{
	mdb_cursor_close(cursor);
	return 0;
	}

int gcfosdb::get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags, gcfosdbTxn *txn /* = NULL*/)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	rc = mdb_cursor_get(cursor, &Key, &Value, (MDB_cursor_op)flags);
	if(rc == 0)
		{
		gcfosdb_memcpy(pb + key_offset, Key.mv_data, key_len);
		gcfosdb_memcpy(pb + data_offset, Value.mv_data, data_len);
		}
	return rc;
	}

int gcfosdb::put(gcfosdbCursor *cursor, PVOID p, UINT32 flags/* = 0*/)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	rc = mdb_cursor_put(cursor, &Key, &Value, flags);
	m_bChangedSinceSync = true;
	LastChangeTime.ObtainTimeNow();
	return rc;
	}

int gcfosdb::getNext(gcfosdbCursor *cursor, PVOID p)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE pb = (LPBYTE)p;

	rc = mdb_cursor_get(cursor, &Key, &Value, MDB_NEXT);
	if(rc == 0)
		{
		gcfosdb_memcpy(pb + key_offset, Key.mv_data, key_len);
		gcfosdb_memcpy(pb + data_offset, Value.mv_data, data_len);
		}

	return rc;
	}

UINT64 gcfosdb::size()
	{
	MDB_stat		stats;
	int				rc;
	MDB_txn			*txn;

	rc = mdb_txn_begin(g_LMDB_env, NULL, 0, &txn);
	if(rc != 0)
		return 0;

	rc = mdb_stat(txn, t, &stats);
	mdb_txn_abort(txn);

	return ((UINT64)(stats.ms_branch_pages + stats.ms_overflow_pages + stats.ms_leaf_pages) * (UINT64)stats.ms_psize);
	}

void gcfosdb::PrintDBStats()
	{
	MDB_stat		stats;
	int				rc;
	MDB_txn			*txn;
	UINT32			sizeKB;

	rc = mdb_txn_begin(g_LMDB_env, NULL, 0, &txn);
	if(rc != 0)
		return;

	rc = mdb_stat(txn, t, &stats);
	sizeKB = UINT32(((UINT64)(stats.ms_branch_pages + stats.ms_overflow_pages + stats.ms_leaf_pages) * (UINT64)stats.ms_psize) >> (UINT64)10);
	if(rc == 0)
		{
		_tprintf_s(L"Items:%I64d, Size:%u KB, Depth:%u, Branch:%I64d, Leaf:%I64d, O/f:%I64d\n", stats.ms_entries, sizeKB, stats.ms_depth, stats.ms_branch_pages, stats.ms_leaf_pages, stats.ms_overflow_pages);
		}

	mdb_txn_abort(txn);
	return;
	}
#pragma managed(pop)

