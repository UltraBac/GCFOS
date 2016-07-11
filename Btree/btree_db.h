class GCFOS_CLIENT_API btree_db
	{
	private:
		UINT32			key_offset;
		UINT32			key_len;
		UINT32			data_offset;
		UINT32			data_len;

	friend GCFOS_PRIVATE_MEMBERS;
	friend GCFOS_Client;

	public:
		static bool InitializeEnvironment(LPCSTR); // Must be called to initialize environment, ONCE -- before any tables are opened

		btree_db() {
			key_offset = 0;
			key_len = 0;
			data_offset = 0;
			data_len = 0;
			}
		~btree_db() {
			}
		int insert(LPVOID p, MDB_txn *txn = NULL, int flags = 0);
		int erase(MDB_cursor *cursor);
		int erase(PVOID p, MDB_txn *txn = NULL);
		int find(LPVOID p, MDB_txn *txn = NULL, int flags = 0);
		bool open(const char *tablename, UINT32 k_off, UINT32 k_len, UINT32 d_off, UINT32 d_len, unsigned int flags = MDB_CREATE);
		int close();
		int createCursor(MDB_cursor **cursor, UINT32 flags, MDB_txn *txn = NULL);
		int get(MDB_cursor *cursor, LPVOID p, UINT32 flags, MDB_txn *txn = NULL);
		int getNext(MDB_cursor *cursor, LPVOID p);
		UINT32 size();
	};
