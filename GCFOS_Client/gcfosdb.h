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

class gcfosdb
	{
	private:
		UINT32			key_offset; // start of the "key" (indexed part or record)
		UINT32			key_len;	// length of key
		UINT32			data_offset;// start of the data portion (non-indexed)
		UINT32			data_len;	// length of data portion (may be zero when entire record is key)
		UINT32			next_recno;	// only used when this is a "recno" type of table
		static MDB_env	*g_LMDB_env;// shared environment
		static UINT32	m_refcount;	// reference count for number of times the env is shared
		MDB_dbi			t;			// the table identifer (ordinal) for this database
		static UINT64	m_env_size; // current size of environment
		static Locker	m_locker;	// This is a read/write locker for transactions to ensure that a resize(remap) is not attempted when there are open txns
		// Following are variables maintained in order re-open database (after automatic resize)
		int				m_dbtype;   // gcfosdb_RECNO or 0
		int				m_dbflags;  // MDB_CREATE | MDB_INTEGERKEY etc
		char*			m_pszFilename; // original filename when opened
		static gcfosdb* m_Root;     // first entry in chain of linked gcfosdb
		gcfosdb*		m_Next;     // next entry for this one (or NULL)
		static char*	m_EnvPath;  // saved environment path
		static bool		m_BlockStoreEnabled; // Set by caller to indicate that the EXTENDED local block cache will be used (make environment bigger)
		void			AddEntryToChain();
		bool			reopen();
		static bool		reopen_all();

	public:
		static int		CreateEnvironment(LPCSTR path);
		static bool		EnvironmentInitialized() { return g_LMDB_env != NULL; }
		static int		CloseEnvironment();
		static int		BeginTxn(MDB_txn **txn, uint32_t flags = 0, bool bNoLock = false);
		static int		CommitTxn(MDB_txn **txn);
		static int		AbortTxn(MDB_txn *txn);
		static int		Checkpoint();
		static int		ResizeLMDB(MDB_txn **txn);

		gcfosdb() {
			key_offset = 0;
			key_len = 0;
			data_offset = 0;
			data_len = 0;
			t = NULL;
			next_recno = 0; // this indicates that the default table is NOT a "recno" table
			m_dbtype = 0;
			m_dbflags = 0;
			m_Next = NULL;
			m_pszFilename = NULL;
			}
		~gcfosdb() {
			delete[] m_pszFilename;
			}
		UINT32 GetKeyLen() { return key_len; }
		UINT32 GetKeyStart() { return key_offset; }
		UINT32 GetDataLen() { return data_len; }
		UINT32 GetDataStart() { return data_offset; }
		UINT32 GetRecSize() { return data_len + key_len; }
		static void setBlockCacheEnabled(bool BlockStoreEnabled) { m_BlockStoreEnabled = BlockStoreEnabled; }
		int insert(LPVOID p, MDB_txn **txn = NULL, int extra_data = 0, bool bAutoRetry = true, int flags = 0);
		int erase(gcfosdbCursor *cursor);
		int erase(PVOID p, MDB_txn **txn=NULL, bool bAutoRetry = true);
		int find(LPVOID p, MDB_txn *txn=NULL, PUINT32 size_override = NULL, LPBYTE *data_ref = NULL);
		bool open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, int32_t flags = -1, int dbtype = 0);
		void PrintDBStats();
		int close();
		int createCursor(gcfosdbCursor **cursor, MDB_txn *txn, UINT32 flags);
		static int closeCursor(gcfosdbCursor *cursor);
		int get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags);
		int getNext(gcfosdbCursor *cursor, PVOID p);
		UINT64 size();
		static bool drop(const char *tablename);
	};

