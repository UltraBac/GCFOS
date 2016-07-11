#include "stdafx.h"

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

// gcfosdb Functions (helper class)

// this is the LMDB implementation

// Stolen from GCFOS_Server, modified for use with client


// define storage for gcfosdb statics
MDB_env* gcfosdb::g_LMDB_env = NULL;
UINT64 gcfosdb::m_env_size = 0;
UINT32 gcfosdb::m_refcount = 0;
Locker gcfosdb::m_locker;
gcfosdb* gcfosdb::m_Root = NULL;
char* gcfosdb::m_EnvPath = NULL;
bool gcfosdb::m_BlockStoreEnabled = false;

void gcfosdb::AddEntryToChain()
	{
	gcfosdb* next;
	if(m_Root == NULL)
		{
		m_Root = this;
		return;
		}
	next = m_Root;
	while(next->m_Next != NULL)
		{
		next = next->m_Next;
		}
	next->m_Next = this;
	return;
	}

int gcfosdb::CreateEnvironment(LPCSTR path)
	{
	MDB_envinfo envinfo;
	int rc;

	if(g_LMDB_env != NULL)
		{
		assert(m_refcount > 0);
		m_refcount++;
		return 0;
		}

	if(!CreateDirectoryA(path, NULL))
		{
		if(GetLastError() != ERROR_ALREADY_EXISTS)
			{
			DEBUGLOG(("gcfosdb::CreateEnvironment problem with path %s, %u\n", path, GetLastError()));
			return EINVAL;
			}
		}
	if(m_env_size == 0)
		{
		if(m_BlockStoreEnabled)
			{
			m_env_size = (UINT64)1024 * 0x100000LL; // 1GB
			}
		else
			{
			m_env_size = (UINT64)768 * 0x100000LL;
			}

#ifdef _DEBUG
		m_env_size = (UINT64)512 * 0x100000LL; // make small to force frequent db resizing ops
#endif
		}

	while(true)
		{
		rc = mdb_env_create(&g_LMDB_env);
		if(rc != 0)
			return rc;
		rc = mdb_env_set_maxdbs(g_LMDB_env, 10); // maximum of 10 named databases
		if(rc != 0)
			{
			mdb_env_close(g_LMDB_env);
			g_LMDB_env = NULL;
			return rc;
			}
		mdb_env_set_mapsize(g_LMDB_env, (mdb_size_t)m_env_size);
		if(rc != 0)
			{
			DEBUGLOG(("unable to set db size %I64u, %d\n", m_env_size, rc));
			mdb_env_close(g_LMDB_env);
			g_LMDB_env = NULL;
			return rc;
			}

		rc = mdb_env_open(g_LMDB_env, path, MDB_NOTLS | MDB_NOSYNC | MDB_WRITEMAP, 0664);
		if(rc != 0)
			{
			if(rc == ERROR_USER_MAPPED_FILE)
				{
				mdb_env_close(g_LMDB_env);
				g_LMDB_env = NULL;
				m_env_size = 0;
				continue;
				}
			if(rc != 0)
				{
				DEBUGLOG(("unable to open db env %d\n", rc));
				mdb_env_close(g_LMDB_env);
				g_LMDB_env = NULL;
				return rc;
				}
			}
		break;
		}
	m_refcount = 1;
	mdb_env_info(g_LMDB_env, &envinfo);
	m_env_size = envinfo.me_mapsize;
	if(m_EnvPath == NULL)
		{
		m_EnvPath = new char[strlen(path + 1)];
		strcpy_s(m_EnvPath, strlen(path) + 1, path);
		}

	DEBUGLOG(("CreateEnvironment - DB Environment size: %I64x\n", m_env_size));
	return rc;
	}

int	gcfosdb::CloseEnvironment()
	{
	m_locker.Write();
	if(m_refcount == 0)
		{
		assert(g_LMDB_env == NULL);
		DEBUGLOG(("GCFOS_Client::gcfosdb::CloseEnvironment -- refcount=0\n"));
		m_locker.WriteEnd();
		return 0;
		}
	m_refcount--;
	if(m_refcount == 0)
		{
		DEBUGLOG(("GCFOS_Client::gcfosdb::CloseEnvironment\n"));
		Checkpoint();
		mdb_env_close(g_LMDB_env);
		g_LMDB_env = NULL;
		}
	m_locker.WriteEnd();
	return 0;
	}

int	gcfosdb::BeginTxn(MDB_txn **txn, uint32_t flags /* = 0*/, bool bNoLock /* = false*/)
	{
	int		rc;

	if(!bNoLock)
		{
		m_locker.Read();
		}
	rc = mdb_txn_begin(g_LMDB_env, NULL, flags, txn);
	if(rc != 0)
		{
		if(rc == MDB_MAP_RESIZED)
			{
			// According to docs we have to just "accept" new env size by setting new map size to 0
			rc = mdb_env_set_mapsize(g_LMDB_env, 0);
			if(rc == 0)
				{
				rc = mdb_txn_begin(g_LMDB_env, NULL, flags, txn);
				if(rc != 0)
					{
					DEBUGLOG(("gcfosdb::BeginTxn error %d (after resize)\n", rc));
					}
				}
			else
				{
				DEBUGLOG(("gcfosdb::BeginTxn set mapsize error %d\n", rc));
				}
			}
		else
			{
			DEBUGLOG(("gcfosdb::BeginTxn error %d\n", rc));
			}
		}
	if(rc != 0)
		{
		// Ordinarily we want to leave the lock held -- until the txn is committed
		if(!bNoLock)
			{
			m_locker.ReadEnd();
			}
		}
	return rc;
	}

int	gcfosdb::CommitTxn(MDB_txn **txn)
	{
	int rc;

	assert(txn != NULL);

	rc = mdb_txn_commit(*txn);
	if(rc == MDB_MAP_FULL)
		{
		// ReadEnd will be called by resize (the txn abort)
		ResizeLMDB(txn);
		}
	else
		{
		m_locker.ReadEnd();
		}
	return rc;
	}

int	gcfosdb::AbortTxn(MDB_txn *txn)
	{
	if (txn == NULL)
		{
		DEBUGLOG(("Attempted to Abort non-existent txn\n"));
		return 0;
		}

	mdb_txn_abort(txn);
	m_locker.ReadEnd();
	return 0;
	}

int	gcfosdb::Checkpoint()
	{
	return mdb_env_sync(g_LMDB_env, 1);
	}


bool gcfosdb::open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, int32_t flags /* = -1*/, int dbtype /* = 0*/)
	{
	int				rc;
	MDB_cursor		*cursor;
	MDB_val			Key, Value;
	MDB_txn			*txn;

	if(flags < 0)
		flags = MDB_CREATE;
	else
		flags |= MDB_CREATE;

	if(dbtype == gcfosdb_RECNO)
		{
		flags |= MDB_INTEGERKEY;
		}

	// remember values for reopen()
	m_dbflags = flags;
	m_dbtype = dbtype;

	rc = BeginTxn(&txn);
	if(rc != 0)
		return false;

	rc = mdb_dbi_open(txn, tablename, m_dbflags, &t);
	if(rc != 0)
		{
		AbortTxn(txn);
		return false;
		}

	if(m_dbtype == gcfosdb_RECNO)
		{
		assert(key_len == sizeof(UINT32));
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
			mdb_cursor_close(cursor);
			}
		}
	else
		{
		next_recno = 0; // indicate that this is not a RECNO type of table
		}

	rc = CommitTxn(&txn);
	if(rc == 0)
		{
		key_offset = k_off;
		key_len = k_len;
		data_offset = d_off;
		data_len = d_len;
		AddEntryToChain();
		m_pszFilename = new char[strlen(tablename) + 1];
		strcpy_s(m_pszFilename, strlen(tablename) + 1, tablename);
		}

	return (rc == 0);
	}

bool gcfosdb::reopen()
	{
	int				rc;
	MDB_cursor		*cursor;
	MDB_val			Key, Value;
	MDB_txn			*txn;

	rc = BeginTxn(&txn);
	if(rc != 0)
		return false;

	rc = mdb_dbi_open(txn, m_pszFilename, m_dbflags, &t);
	if(rc != 0)
		{
		AbortTxn(txn);
		return false;
		}

	if(m_dbtype == gcfosdb_RECNO)
		{
		assert(key_len == sizeof(UINT32));
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
			mdb_cursor_close(cursor);
			}
		}
	else
		{
		next_recno = 0; // indicate that this is not a RECNO type of table
		}

	rc = CommitTxn(&txn);

	return (rc == 0);
	}

bool gcfosdb::reopen_all()
	{
	gcfosdb* cur = m_Root;

	while(cur != NULL)
		{
		if(!cur->reopen())
			return false;

		cur = cur->m_Next;
		}
	return true;
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

	// abort NOT called
	m_locker.ReadEnd(); //usually called by abort
	*txn = NULL;
	DEBUGLOG(("Closing env for resize\n"));
	CloseEnvironment();
	m_locker.Write();
#ifdef _DEBUG
	m_env_size += (UINT64)256 * 0x100000LL; // Usually 256, force many resizes with small number
#else
	m_env_size += (UINT64)256 * 0x100000LL; // 256MB expansion size
#endif
	DEBUGLOG(("Expanding db size to %I64x\n", m_env_size));
	CreateEnvironment(m_EnvPath);
	reopen_all();
	m_locker.WriteEnd();
	m_locker.Read();
	// This routine is always called with a txn in-progress
	// this needs to be re-started now
	rc = mdb_txn_begin(g_LMDB_env, NULL, 0, txn);
	if(rc != 0)
		{
		DEBUGLOG(("gcfosdb::ResizeLMDB - BeginTxn error %d\n", rc));
		m_locker.ReadEnd();
		}
	return rc;
	}


int gcfosdb::insert(LPVOID p, MDB_txn **txn /* = NULL*/, int extra_data /* = 0*/, bool bAutoRetry /*= true*/, int flags /* = 0 */)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE pb = (LPBYTE)p;
	MDB_txn			*newtxn = NULL;

	if(txn != NULL)
		{
		assert(*txn != NULL);
		}
	else
		{
		rc = mdb_txn_begin(g_LMDB_env, NULL, 0, &newtxn);
		if(rc != 0)
			{
			return rc;
			}
		}

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len + extra_data;

	if(next_recno > 0 && *(PUINT32)Key.mv_data == 0)
		{
		memcpy(pb + key_offset, &next_recno, sizeof(UINT32));
		next_recno++;
		}

	rc = mdb_put(newtxn == NULL ? *txn : newtxn, t, &Key, &Value, flags);
	if(rc == MDB_MAP_FULL)
		{
		ResizeLMDB(newtxn == NULL ? txn : &newtxn);
		if(bAutoRetry)
			{
			rc = mdb_put(newtxn == NULL ? *txn : newtxn, t, &Key, &Value, flags);
			}
		if(newtxn == NULL)
			{
			return rc;
			}
		}

	if(newtxn != NULL)
		{
		rc = gcfosdb::CommitTxn(&newtxn);
		if(rc != 0)
			{
			if(rc == MDB_MAP_FULL)
				{
				ResizeLMDB(&newtxn);
				if(bAutoRetry)
					{
					rc = mdb_put(newtxn, t, &Key, &Value, flags);
					if(rc != 0)
						{
						gcfosdb::AbortTxn(newtxn);
						return rc;
						}
					}
				else
					{
					gcfosdb::AbortTxn(newtxn);
					return rc;
					}
				}
			else
				{
				gcfosdb::AbortTxn(newtxn);
				return rc;
				}
			}
		return rc;
		}

	return rc;
	}

int gcfosdb::erase(gcfosdbCursor *cursor)
	{
	return mdb_cursor_del(cursor, 0); 
	}

int gcfosdb::erase(PVOID p, MDB_txn **txn, bool bAutoRetry /*= true*/)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE			pb = (LPBYTE)p;

	assert(*txn != NULL);

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	rc = mdb_del(*txn, t, &Key, &Value);
	if(rc == MDB_MAP_FULL)
		{
		ResizeLMDB(txn);
		if(bAutoRetry == true)
			{
			rc = mdb_del(*txn, t, &Key, &Value);
			}
		}

	return rc;
	}

int gcfosdb::find(LPVOID p, MDB_txn *txn /*=NULL*/, PUINT32 size_override /* = NULL*/, LPBYTE *data_ref /*=NULL*/)
	{
	MDB_val			Key, Value;
	int				rc;
	LPBYTE			pb = (LPBYTE)p;
	MDB_txn			*newtxn = NULL;
	ssize_t			bytestocopy;

	Key.mv_data = pb + key_offset;
	Key.mv_size = key_len;
	Value.mv_data = pb + key_len;
	Value.mv_size = data_len;

	if(txn == NULL)
		{
		rc = BeginTxn(&newtxn, MDB_RDONLY);
		if(rc != 0)
			return rc;
		}

	rc = mdb_get(newtxn == NULL ? txn : newtxn, t, &Key, &Value);
	if(rc == 0)
		{
		memcpy(pb + key_offset, Key.mv_data, key_len);
		if(size_override == NULL)
			{
			bytestocopy = data_len;
			}
		else
			{
			if((Value.mv_size - data_len) < *size_override)
				{
				bytestocopy = Value.mv_size;
				}
			else
				{
				bytestocopy = *size_override + data_len;
				}
			*size_override = (UINT32)Value.mv_size - data_len;
			}
		memcpy(pb + data_offset, Value.mv_data, bytestocopy);
		if((LONG_PTR)Value.mv_size < bytestocopy)
			{
			memset(pb + data_offset + Value.mv_size, 0, data_len - Value.mv_size);
			}
		if(data_ref != NULL)
			{
			*data_ref = (LPBYTE)Value.mv_data;
			}
		}
	if(newtxn != NULL)
		{
		AbortTxn(newtxn);
		}
	return rc;
	}

int gcfosdb::createCursor(gcfosdbCursor **cursor, MDB_txn *txn, UINT32 flags)
	{
	return mdb_cursor_open(txn, t, cursor);
	}

int gcfosdb::closeCursor(gcfosdbCursor *cursor)
	{
	mdb_cursor_close(cursor);
	return 0;
	}

int gcfosdb::get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags)
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
		memcpy(pb + key_offset, Key.mv_data, key_len);
		memcpy(pb + data_offset, Value.mv_data, data_len);
		}
	return rc;
	}


int gcfosdb::getNext(gcfosdbCursor *cursor, PVOID entry)
	{
	MDB_val			Key, Value;
	int				rc;

	rc = mdb_cursor_get(cursor, &Key, &Value, MDB_NEXT);
	if(rc == 0)
		{
		memcpy((LPBYTE)entry + key_offset, Key.mv_data, key_len);
		memcpy((LPBYTE)entry + data_offset, Value.mv_data, data_len);
		}
	return rc;
	}

UINT64 gcfosdb::size()
	{
	MDB_stat		stats;
	int				rc;
	MDB_txn			*txn;

	rc = BeginTxn(&txn, MDB_RDONLY);
	if(rc != 0)
		return 0;

	rc = mdb_stat(txn, t, &stats);
	AbortTxn(txn);

	return (stats.ms_entries);
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
		_tprintf_s(_T("Items:%d, Size:%u KB, Depth:%u, Branch:%d, Leaf:%d, O/f:%d\n"), (int)stats.ms_entries, sizeKB, stats.ms_depth, (int)stats.ms_branch_pages, (int)stats.ms_leaf_pages, (int)stats.ms_overflow_pages);
		}

	mdb_txn_abort(txn);
	return;
	}

bool gcfosdb::drop(const char *tablename)
	{
	int				rc;
	MDB_dbi			db;
	MDB_txn			*txn;

	rc = BeginTxn(&txn);
	if(rc != 0)
		{
		DEBUGLOG(("gcfosdb::drop failed to get txn for %s, %d\n", rc, tablename));
		return false;
		}

	while(true)
		{
		// db has to be re-opened in case of failure (of drop or commit)

		rc = mdb_open(txn, tablename, 0, &db);
		if(rc != 0)
			{
			AbortTxn(txn);
			if(rc != MDB_NOTFOUND)
				{
				DEBUGLOG(("gcfosdb::drop open %s failed, %d\n", tablename, rc));
				return false;
				}
			return true; // db does not exist, success! (well, sort of)
			}

		rc = mdb_drop(txn, db, 1);
		if(rc == MDB_MAP_FULL)
			{
			if(ResizeLMDB(&txn) == 0)
				{
				continue; // try drop again
				}
			else
				{
				DEBUGLOG(("gcfosdb::drop failed to expand env, %d\n", rc));
				AbortTxn(txn);
				return false;
				}
			}
		if(rc != 0)
			{
			DEBUGLOG(("gcfosdb::drop failed to drop %s, %d\n", tablename, rc));
			AbortTxn(txn);
			return false;
			}

		rc = CommitTxn(&txn);
		if(rc == MDB_MAP_FULL)
			{
			if(ResizeLMDB(&txn) == 0)
				{
				continue; // try drop again
				}
			else
				{
				DEBUGLOG(("gcfosdb::drop failed to expand env, %d\n", rc));
				AbortTxn(txn);
				return false;
				}
			}
		break;
		}

	if(rc != 0)
		{
		DEBUGLOG(("gcfosdb::drop failed to commit for %s, %d\n", tablename, rc));
		return false;
		}

	return true;
	}
