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

typedef MDB_txn gcfosdbTxn;
typedef MDB_cursor gcfosdbCursor;
#define gcfosdb_CURSOR_BULK 0
#define gcfosdb_READ_UNCOMMITTED 0
#define gcfosdb_LOCK_DEADLOCK -1
#define gcfosdb_NOTFOUND MDB_NOTFOUND
#define gcfosdb_NEXT MDB_NEXT
#define gcfosdb_SET_RANGE MDB_SET_RANGE
#define gcfosdb_FIRST MDB_FIRST
#define gcfosdb_APPEND 0
#define gcfosdb_NOOVERWRITE MDB_NOOVERWRITE
#define gcfosdb_DUP MDB_DUPSORT // LMDB doesn't have an unsorted duplicates-allowed flag, so if dups are allowed they're always sorted
#define gcfosdb_DUPSORT MDB_DUPSORT
#define gcfosdb_QUEUE -2
#define gcfosdb_RECNO -3
#define gcfosdb_CONSUME 0
#define gcfosdb_LAST MDB_LAST
#define gcfosdb_KEYEXIST MDB_KEYEXIST
#define gcfosdb_RDONLY MDB_RDONLY

// forward ref
class GCFOS_UsefulTime;


class gcfosdb
	{
	private:
		UINT32			key_offset;
		UINT32			key_len;
		UINT32			data_offset;
		UINT32			data_len;
		UINT32			next_recno;
		static MDB_env	*g_LMDB_env;
		MDB_dbi			t;
		static UINT64	m_env_size;
		static bool		m_bChangedSinceSync;

	public:
		static int		CreateEnvironment(LPCSTR pszDir = NULL);
		static int		CloseEnvironment();
		static int		BeginTxn(MDB_txn *parent, MDB_txn **result, uint32_t flags);
		static int		CommitTxn(MDB_txn *txn);
		static int		AbortTxn(MDB_txn *txn);
		static int		Checkpoint();
		static int		ResizeLMDB(MDB_txn **txn);
		static bool		HasDbChanged() { return m_bChangedSinceSync; }
		static GCFOS_UsefulTime	LastChangeTime;
		HANDLE			hNewRecordAvailable; // event set when record inserted (auto-reset)

		gcfosdb() {
			key_offset = 0;
			key_len = 0;
			data_offset = 0;
			data_len = 0;
			t = NULL;
			next_recno = 0; // this indicates that the default table is NOT a "recno" table
			hNewRecordAvailable = CreateEvent(NULL, FALSE, FALSE, NULL);
			m_bChangedSinceSync = false;
			}
		~gcfosdb() {
			}
		UINT32 data_end() { return data_len; }
		int insert(LPVOID p, gcfosdbTxn *txn = NULL, int extra_data = 0, int flags = -1);
		int erase(gcfosdbCursor *cursor);
		int erase(PVOID p, gcfosdbTxn *txn = NULL);
		int find(LPVOID p, gcfosdbTxn *txn = NULL, LPVOID *data_only = NULL, PUINT32 extra_len = NULL, int flags = -1);
		bool verify(const char *tablename);
		bool open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, int32_t flags = -1, int dbtype = 0, bool bCompact = false);
		void PrintDBStats();
		int close();
		int createCursor(gcfosdbCursor **cursor, UINT32 flags, gcfosdbTxn *txn = NULL);
		static int closeCursor(gcfosdbCursor *cursor);
		int get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags, gcfosdbTxn *txn = NULL);
		int getNext(gcfosdbCursor *cursor, PVOID p);
		int put(gcfosdbCursor *cursor, PVOID p, UINT32 flags = 0);
		UINT64 size();
	};

