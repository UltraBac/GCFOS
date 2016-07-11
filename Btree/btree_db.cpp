#include "stdafx.h"

// Static initializers

bool btree_db::open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, unsigned int flags /*= MDB_CREATE*/)
	{
	key_offset = k_off;
	key_len = k_len;
	data_offset = d_off;
	data_len = d_len;

	return true;
	}

int btree_db::get(MDB_cursor *cursor, LPVOID p, UINT32 flags, MDB_txn *txn /*= NULL*/)
	{
	return 0;
	}

int btree_db::getNext(MDB_cursor *cursor, LPVOID p)
	{
	return 0;
	}

int btree_db::insert(LPVOID p, MDB_txn *txn /*= NULL*/, int flags /*= 0*/)
	{
	LPBYTE		pb;

	pb = (LPBYTE)p;


	return 0;
	}

int btree_db::erase(MDB_cursor *cursor)
	{
	return 0;
	}

int btree_db::erase(PVOID p, MDB_txn *txn /*= NULL*/)
	{
	return 0;
	}

int btree_db::find(LPVOID p, MDB_txn *txn /*= NULL*/, int flags /*= 0*/)
	{
	LPBYTE		pb;
	int			rc;

	pb = (LPBYTE)p;

	key.mv_data = pb + key_offset;
	key.mv_size = key_len;
	data.mv_data = pb + data_offset;
	data.mv_size = key_len;

	return 0;
	}

int btree_db::close()
	{
	return 0;
	}

int btree_db::createCursor(MDB_cursor **cursor, UINT32 flags, MDB_txn *txn /*= NULL*/)
	{
	return 0;
	}
