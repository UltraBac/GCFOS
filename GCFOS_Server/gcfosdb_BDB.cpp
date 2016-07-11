#include "stdafx.h"
#include "GCFOS_Server.h"

// gcfosdb Functions (helper class)

// Berkeley DB implementation (BDB) -- no longer used, replaced by LMDB

// define storage for gcfosdb statics
DbEnv* gcfosdb::g_Env = NULL;

int gcfosdb::CreateEnvironment() { 
	g_Env = new DbEnv(DB_CXX_NO_EXCEPTIONS);
	if(g_Env == NULL)
		return -1;

	g_Env->set_error_stream(&std::cerr);
	g_Env->set_lk_detect(DB_LOCK_DEFAULT);
	if(g_Env->open("gcfosdb", DB_CREATE | DB_THREAD | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_TXN | DB_REGISTER | DB_RECOVER | DB_INIT_MPOOL, 0) != 0)
		{
		return -1;
		}
	return 0;
	}

int	gcfosdb::CloseEnvironment()
	{
	int rc = 0;
	if(g_Env)
		{
		rc = g_Env->close(DB_FORCESYNC);	
		delete g_Env;
		g_Env = NULL;
		}
	return rc;
	}

int	gcfosdb::BeginTxn(DbTxn *parent, DbTxn **result, uint32_t flags)
	{
	return g_Env->txn_begin(parent, result, flags);
	}

int	gcfosdb::CommitTxn(DbTxn *txn, uint32_t flags)
	{
	return txn->commit(flags);
	}

int	gcfosdb::AbortTxn(DbTxn *txn)
	{
	return txn->abort();
	}

int	gcfosdb::Checkpoint() {
	if(g_Env->txn_checkpoint(10 /* kbyte of data in log minimum*/, 1 /* 1 minute minimum age */, 0 /* flags*/) != 0)
		{
		return -1;
		}

	g_Env->log_archive(NULL, DB_ARCH_REMOVE);
	return 0;
	}

int gcfosdb::lsn_reset(LPCSTR name, uint32_t flags)
	{
	return g_Env->lsn_reset(name, flags);
	}

bool gcfosdb::verify(const char *tablename)
	{
	int rc;
	t = new Db(g_Env, DB_CXX_NO_EXCEPTIONS);
	if(t == NULL)
		return false;

	DEBUGLOG_L(2, ("verifying %s\n", tablename));
	rc =  t->verify(tablename, NULL, NULL, 0);
	DEBUGLOG_L(2, ("verify status: %d\n", rc));
	delete t;
	return (rc == 0);
	}

bool gcfosdb::open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, uint32_t flags /* = -1*/, int dbtype, bool bCompact /*= false*/)
	{
	if(flags == -1)
		flags = 0;
	if(dbtype == 0)
		dbtype = DB_BTREE;

	gcfosdbTxn *dbtxn = NULL;
	if(g_VerifyOpens == true)
		verify(tablename);

	t = new Db(g_Env, DB_CXX_NO_EXCEPTIONS);
	if(t == NULL)
		return false;

	if(g_Env->txn_begin(NULL, &dbtxn, 0) != 0 || dbtxn == NULL)
		return false;

	if(dbtype == DB_QUEUE)
		{
		t->set_re_len(d_len);
		}

	if(flags)
		{
		t->set_flags(flags);
		}

	// note: DB_THREAD not needed here because environment has it set already
	if(t->open(dbtxn, tablename, NULL, (DBTYPE)dbtype, DB_CREATE | DB_READ_UNCOMMITTED /*| DB_AUTO_COMMIT*/, 0) != 0)
		{
		delete t;
		t = NULL;
		gcfosdb::AbortTxn(dbtxn);
		return false;
		}

	gcfosdb::CommitTxn(dbtxn, 0);
	dbtxn = NULL;

	key_offset = k_off;
	key_len = k_len;
	data_offset = d_off;
	data_len = d_len;

	return true;
	}

int gcfosdb::associate(gcfosdb *primary, BDB_CALLBACK_FUNC callback, uint32_t flags/* = 0*/)
	{
	gcfosdbTxn			*dbtxn = NULL;
	int					rc;

	if(primary->t == NULL || t == NULL)
		return -1;

	rc = g_Env->txn_begin(NULL, &dbtxn, 0);
	if(rc != 0)
		return rc;

	rc = primary->t->associate(dbtxn, t, callback, flags);

	gcfosdb::CommitTxn(dbtxn, 0);

	return rc;
	}


int gcfosdb::close()
	{
	if(t)
		{
		return t->close(DB_FORCESYNC);
		}
	return 0;
	}


int gcfosdb::insert(LPVOID p, gcfosdbTxn *txn /* = NULL*/, int flags /* = -1 */)
	{
	LPBYTE pb = (LPBYTE)p;
	gcfosdbTxn *newtxn = NULL;
	int rtn = -1;

	if(flags == -1) // default
		flags = DB_OVERWRITE_DUP;

	Dbt Key(pb + key_offset, key_len), Value(pb + key_len, data_len);
	Key.set_flags(DB_DBT_USERMEM);
	Key.set_ulen(key_len);

	Value.set_flags(DB_DBT_USERMEM);
	Value.set_ulen(data_len);

	while(true)
		{
		if(txn == NULL)
			{
			if(g_Env->txn_begin(txn, &newtxn, 0) != 0)
				{
				// failed to get a new txn
				DEBUGLOG_L(1, ("gcfosdb::insert failed to get new txn\n"));
				return false;
				}
			}
		else
			{
			newtxn = txn;
			}
		rtn = t->put(newtxn, &Key, &Value, flags);
		if(rtn == DB_LOCK_DEADLOCK)
			{
			if(txn == NULL)
				{
				return rtn;
				}
			gcfosdb::AbortTxn(newtxn);
			newtxn = NULL;
			waitRandomBit();
			continue; // try command again
			}
		if(txn == NULL)
			{
			gcfosdb::CommitTxn(newtxn, 0);
			}
		SetEvent(hNewRecordAvailable);
		break;
		}

	return rtn;
	}

int gcfosdb::erase(gcfosdbCursor *cursor)
	{
	return cursor->del(0);
	}

int gcfosdb::erase(PVOID p, gcfosdbTxn *txn /* = NULL */)
	{
	int rtn = -1;
	LPBYTE pb = (LPBYTE)p;
	gcfosdbTxn *newtxn = NULL;

	Dbt Key(pb + key_offset, key_len);
	Key.set_flags(DB_DBT_USERMEM);
	Key.set_ulen(key_len);

	if(txn != NULL)
		{
		rtn = t->del(txn, &Key, 0);
		}
	else
		{
		while(true)
			{
			if(g_Env->txn_begin(txn, &newtxn, 0) != 0)
				{
				// failed to get a new txn
				DEBUGLOG_L(1, ("gcfosdb::erase failed to get new txn\n"));
				return false;
				}
			rtn = t->del(newtxn, &Key, 0);
			if(rtn == DB_LOCK_DEADLOCK)
				{
				gcfosdb::AbortTxn(newtxn);
				waitRandomBit();
				continue; // try command again
				}
			gcfosdb::CommitTxn(newtxn, 0);
			break;
			}
		}

	return rtn;
	}


int gcfosdb::find(LPVOID p, gcfosdbTxn *txn /* = NULL*/, int flags /* = -1*/)
	{
	if(flags == -1)
		flags = DB_READ_UNCOMMITTED;

	gcfosdbTxn *newtxn = NULL;
	int rtn = -1;

	LPBYTE pb = (LPBYTE)p;
	Dbt Key(pb + key_offset, key_len), Value(pb + key_len, data_len);
	Key.set_flags(DB_DBT_USERMEM);
	Key.set_ulen(key_len);

	Value.set_flags(DB_DBT_USERMEM);
	Value.set_ulen(data_len);

	if(txn != NULL)
		{
		return t->get(txn, &Key, &Value, flags);
		}

	while(true)
		{
		if(g_Env->txn_begin(txn, &newtxn, 0) != 0)
			{
			// failed to get a new txn
			break;
			}
		rtn = t->get(newtxn, &Key, &Value, flags);
		if(rtn == DB_LOCK_DEADLOCK)
			{
			gcfosdb::AbortTxn(newtxn);
			waitRandomBit();
			continue; // try command again
			}
		gcfosdb::CommitTxn(newtxn, 0);
		break;
		}

	return rtn;
	}

int gcfosdb::createCursor(gcfosdbCursor **cursor, UINT32 flags, gcfosdbTxn *txn /* = NULL*/)
	{
	return t->cursor(txn, cursor, flags);
	}

int gcfosdb::closeCursor(gcfosdbCursor *cursor)
	{
	return cursor->close();
	}

int gcfosdb::get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags, gcfosdbTxn *txn /* = NULL*/)
	{
	LPBYTE pb = (LPBYTE)p;
	Dbt Key(pb + key_offset, key_len), Value(pb + key_len, data_len);
	Key.set_flags(DB_DBT_USERMEM);
	Key.set_ulen(key_len);

	Value.set_flags(DB_DBT_USERMEM);
	Value.set_ulen(data_len);

	return cursor->get(&Key, &Value, flags);
	}

int gcfosdb::pget(gcfosdbCursor *cursor, LPVOID secondary, LPVOID primary, gcfosdb *primdb, UINT32 flags, gcfosdbTxn *txn /* = NULL*/)
	{
	LPBYTE p_sec = (LPBYTE)secondary;
	LPBYTE p_prim = (LPBYTE)primary;

	Dbt Key(p_sec + key_offset, key_len), Data(p_prim + primdb->key_len, primdb->data_len);
	Dbt PKey(p_prim + primdb->key_offset, primdb->key_len);
	Key.set_flags(DB_DBT_USERMEM);
	Key.set_ulen(key_len);
	PKey.set_flags(DB_DBT_USERMEM);
	PKey.set_ulen(primdb->key_len);
	Data.set_flags(DB_DBT_USERMEM);
	Data.set_ulen(primdb->data_len);

	if(cursor == NULL)
		return t->pget(txn, &Key, &PKey, &Data, flags);

	return cursor->pget(&Key, &PKey, &Data, flags);
	}

int gcfosdb::getNext(gcfosdbCursor *cursor, PUCHAR entry)
	{
	Dbt Key, Value;

	memset(&Key, 0, sizeof(Dbt));
	memset(&Value, 0, sizeof(Dbt));
	int rtn;

	rtn = cursor->get(&Key, &Value, DB_NEXT | DB_READ_UNCOMMITTED);
	if(rtn != 0)
		{
		return rtn;
		}

	memcpy(entry + key_offset, Key.get_data(), key_len);
	if(data_len)
		{
		memcpy(entry + data_offset, Value.get_data(), data_len);
		}

	return 0;
	}

UINT64 gcfosdb::size()
	{
	DB_BTREE_STAT	*stats = NULL;
	UINT32			rtn = 0;
	
	if(t->stat(NULL, &stats, DB_FAST_STAT | DB_READ_UNCOMMITTED) != 0 || stats == NULL)
		{
		_tprintf_s(TEXT("gcfosdb::size - stat() call failed\n"));
		return 0;
		}

	rtn = stats->bt_nkeys;
	free(stats);
	return rtn;
	}

void gcfosdb::PrintDBStats()
	{
	DB_BTREE_STAT	*stats = NULL;
	DB_QUEUE_STAT	*q_stat;
	DBTYPE			type;

	t->stat(NULL, &stats, DB_READ_UNCOMMITTED);

	if(stats == NULL)
		{
		_tprintf_s(TEXT("stat() call failed\n"));
		return;
		}
	t->get_type(&type);
	switch(type)
		{
		case DB_BTREE:
			_tprintf_s(L"Keys:%u,"
					   L"Page:%u(%u),"
					   L"Lvl:%u,"
					   L"Free:%u,"
					   L"Empty:%u,"
					   L"#Leaf:%u\n",
					   stats->bt_nkeys, stats->bt_pagecnt, stats->bt_pagesize, 
					   stats->bt_levels, stats->bt_free, stats->bt_empty_pg,
					   stats->bt_leaf_pg);
			break;
		case DB_QUEUE:
		case DB_RECNO:
			q_stat = (DB_QUEUE_STAT *)stats;
			_tprintf_s(L"Keys:%u,"
					   L"Page:%u(%u),"
					   L"Len:%u,"
					   L"Cur:%u,"
					   L"First:%u\n",
					   q_stat->qs_nkeys, q_stat->qs_pages, q_stat->qs_pagesize, 
					   q_stat->qs_re_len, q_stat->qs_cur_recno, q_stat->qs_first_recno );
			break;
		default:
			_tprintf_s(TEXT("PrintDBStats - unsupported db type\n"));
			break;
		}

	free(stats);

	return;
	}

int Limbo_2_Callback(Db *secondary, const Dbt *key, const Dbt *data, Dbt *result)
	{
	// Point the "result" to the CLIENT field in the original "primary" db
	PGCFOS_LIMBO_ENTRY			p = (PGCFOS_LIMBO_ENTRY)key->get_const_DBT()->data;

	memset(result, 0, sizeof(Dbt));
	result->get_DBT()->data = (PVOID)&p->client;
	result->get_DBT()->size = sizeof(GCFOS_CLIENTID);
	return 0;
	}

int Clientdb_2_Callback(Db *secondary, const Dbt *key, const Dbt *data, Dbt *result)
	{
	// we are accessing the DATA area, but BDB separates this into two non-consecutive
	// regions addressed by DBT structures. We have to calculate the value of p
	// by adjusting it from the "data" parameter, and make it point to the start
	// of the (not-present) key. This means p cannot be dereferenced to point to the
	// key (clientid), but we are not accessing that anyway.
	PGCFOS_CLIENT_ENTRY			p = (PGCFOS_CLIENT_ENTRY)((LPBYTE)data->get_const_DBT()->data - FIELD_OFFSET(GCFOS_CLIENT_ENTRY, sharedkey));

	memset(result, 0, sizeof(Dbt));
	result->get_DBT()->data = (PVOID)&p->szName;
	result->get_DBT()->size = GCFOS_COMPUTER_NAME_LENGTH * sizeof(TCHAR);
	return 0;
	}
