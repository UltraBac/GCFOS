typedef DbTxn gcfosdbTxn;
typedef Dbc gcfosdbCursor;
typedef int (*BDB_CALLBACK_FUNC)(Db *secondary, const Dbt *key, const Dbt *data, Dbt *result);
#define gcfosdb_CURSOR_BULK DB_CURSOR_BULK 
#define gcfosdb_READ_UNCOMMITTED DB_READ_UNCOMMITTED
#define gcfosdb_LOCK_DEADLOCK DB_LOCK_DEADLOCK
#define gcfosdb_NOTFOUND DB_NOTFOUND
#define gcfosdb_NEXT DB_NEXT
#define gcfosdb_SET_RANGE DB_SET_RANGE
#define gcfosdb_FIRST DB_FIRST
#define gcfosdb_APPEND DB_APPEND
#define gcfosdb_NOOVERWRITE DB_NOOVERWRITE
#define gcfosdb_DUP DB_DUP
#define gcfosdb_DUPSORT DB_DUPSORT
#define gcfosdb_QUEUE DB_QUEUE
#define gcfosdb_RECNO DB_RECNO
#define gcfosdb_CONSUME DB_CONSUME
#define gcfosdb_LAST DB_LAST
#define gcfosdb_KEYEXIST DB_KEYEXIST

class gcfosdb
	{
	private:
		UINT32			key_offset;
		UINT32			key_len;
		UINT32			data_offset;
		UINT32			data_len;
		UINT32			next_recno;
		static DbEnv	*g_Env;
		Db				*t;

	public:
		static int		CreateEnvironment();
		static int		CloseEnvironment();
		static int		BeginTxn(DbTxn *parent, DbTxn **result, uint32_t flags);
		static int		CommitTxn(DbTxn *txn, uint32_t flags);
		static int		AbortTxn(DbTxn *txn);
		static int      lsn_reset(LPCSTR name, uint32_t flags);
		static int		Checkpoint();
		Db* getDb() { return t; };
		HANDLE			hNewRecordAvailable; // event set when record inserted (auto-reset)

		gcfosdb() {
			key_offset = 0;
			key_len = 0;
			data_offset = 0;
			data_len = 0;
			t = NULL;
			next_recno = 0; // this indicates that the default table is NOT a "recno" table
			hNewRecordAvailable = CreateEvent(NULL, FALSE, FALSE, NULL);
			}
		~gcfosdb() {
			if(t != NULL)
				{
				t->close(0);
				delete t;
				}
			}
		int insert(LPVOID p, gcfosdbTxn *txn = NULL, int flags = -1);
		int erase(gcfosdbCursor *cursor);
		int erase(PVOID p, gcfosdbTxn *txn = NULL);
		int find(LPVOID p, gcfosdbTxn *txn = NULL, int flags = -1);
		bool verify(const char *tablename);
		bool open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, uint32_t flags = -1, int dbtype = 0, bool bCompact = false);
		void PrintDBStats();
		int close();
		int createCursor(gcfosdbCursor **cursor, UINT32 flags, gcfosdbTxn *txn = NULL);
		static int closeCursor(gcfosdbCursor *cursor);
		int get(gcfosdbCursor *cursor, LPVOID p, UINT32 flags, gcfosdbTxn *txn = NULL);
		int getNext(gcfosdbCursor *cursor, PUCHAR p);
		int pget(gcfosdbCursor *cursor, LPVOID secondary, LPVOID primary, gcfosdb *primdb, UINT32 flags, gcfosdbTxn *txn = NULL);
		UINT64 size();
		int associate(gcfosdb *primary, BDB_CALLBACK_FUNC callback, uint32_t flags = 0);
	};

int Limbo_2_Callback(Db *secondary, const Dbt *key, const Dbt *data, Dbt *result);
int Clientdb_2_Callback(Db *secondary, const Dbt *key, const Dbt *data, Dbt *result);
