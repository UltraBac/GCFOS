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

// Even release builds have "debug" output
#define DEBUGLOG(__x) DEBUGLOG_L(3, __x)
#define DEBUGLOG_L(__l, __x) { if(g_debugLvl >= __l) { GCFOSDebugLog __x; } }

#define GCFOS_RETENTION_DURATION				(INT32)(60*60*24* g_GCFOS_RETENTION_DURATION_DAYS) /*Number of days expressed in seconds*/

#define GCFOS_REPOSITORY_BUCKET "gcfos-repository"
#define GCFOS_LCUD_LOCAL_DEFAULT "c:\\gcfos-lcud" // local client-unique db
#define GCFOS_LCUD_REPO_DEFAULT "gcfos-lcud" // local client-unique db
#define GCFOS_REPO_DEFAULT_ENDPOINT "http://s3.amazonaws.com"

#define CHARCOUNT(__x) (sizeof(__x) / sizeof(TCHAR))

// forward declaration
class GCFOS_CONNECT_STATE;
typedef GCFOS_CONNECT_STATE *PGCFOS_CONNECT_STATE;


template <class T>
class DB_FileManager {

public:
	bool DB_FileManager<T>::ExportList(const std::string &filename, gcfosdb *db)
		{
		std::ofstream			output(filename, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
		UINT32					count = 0;
		gcfosdbCursor			*cursor;
		bool					rtn = true;
		T						entry;
		gcfosdbTxn				*txn;
		int						rc;

		if(!output.is_open())
			{
			std::cout << "Failed to open: " << filename << " for writing" << std::endl;
			return false;
			}

		rc = gcfosdb::BeginTxn(NULL, &txn, gcfosdb_RDONLY);
		if(rc != 0)
			{
			std::cout << "Failed to begin transaction " << rc << std::endl;
			return false;
			}

		std::cout << "Writing..." << filename;
		if(db->createCursor(&cursor, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) == 0)
			{
			while(db->getNext(cursor, (PUCHAR)&entry) == 0)
				{
				output << entry;
				count++;
				}
			gcfosdb::closeCursor(cursor);
			cursor = NULL;
			}
		else
			rtn = false;

		output.close();
		gcfosdb::CommitTxn(txn);
		std::cout << " - " << count << " records" << std::endl;
		return rtn;
		}

	bool DB_FileManager<T>::ImportList(const std::string &filename, gcfosdb *db, int flags = 0)
		{
		std::ifstream			input(filename, std::ofstream::binary);
		UINT64					count = 0;
		bool					rtn = true;
		T						entry;
		gcfosdbTxn				*txn;
		int						rc;
		UINT64					cp = 0, lc = 0;

		if(!input.is_open())
			{
			return false;
			}

		rc = gcfosdb::BeginTxn(NULL, &txn, 0);
		if(rc != 0)
			{
			std::cout << "Error during start txn :" << rc << std::endl;
			return false;
			}

		std::cout << "Loading " << filename << std::endl;
		while(true)
			{
			input >> entry;
			if(!input.good())
				break;
			if(flags != 0)
				rc = db->insert(&entry, txn, 0, flags);
			else
				rc = db->insert(&entry, txn);
			if(rc != 0)
				{
				if(rc == MDB_MAP_FULL)
					{
					gcfosdb::ResizeLMDB(&txn);
					input.seekg(cp, input.beg);
					count = lc;
					continue;
					}
				std::cout << "Error during insert :" << rc << std::endl;
				rtn = false;
				break;
				}
			count++;
			if(count % 100000 == 0)
				{
				rc = gcfosdb::CommitTxn(txn);
				if(rc != 0)
					{
					if(rc == MDB_MAP_FULL)
						{
						gcfosdb::ResizeLMDB(&txn);
						input.seekg(cp, input.beg);
						count = lc;
						continue;
						}
					std::cout << "Error during commit :" << rc << std::endl;
					rtn = false;
					break;
					}
				rc = gcfosdb::BeginTxn(NULL, &txn, 0);
				if(rc != 0)
					{
					std::cout << "Error during start new txn :" << rc << std::endl;
					rtn = false;
					break;
					}
				cp = input.tellg();
				lc = count;
				}
			}

		input.close();
		rc = gcfosdb::CommitTxn(txn);
		if(rc != 0)
			{
			std::cout << "Error during final commit :" << rc << std::endl;
			rtn = false;
			}
		std::cout << "Load completed, count:" << count << std::endl;
		return rtn;
		}
	};

#define LCUD_FILE_PATH_FMT _T("%s\\%05u")
const int LCUD_FILE_PATH_LEN = 96;

#pragma managed(push, on)
template <class T>
class Hash_FileManager {
	// A class to efficiently manage the storage of hashes in sequential order
	// NOTE: All functions must be included in header file because otherwise
	// a link-error will result.
public:
	void InitializeSet()
		{
		m_new.clear();
		m_base.clear();
		}

	bool LoadOneFile(LPCTSTR filename)
		{
		std::ifstream			input;
		T						entry;
		UINT32					recordsRead = 0;

		memset(&entry, 0, sizeof(entry));
		input.open(filename, std::ifstream::binary);
		DEBUGLOG_L(5, ("Hash_FileManager::Opening %S\n", filename));
		if(input.is_open() == false)
			{
			return false;
			}

		while(true)
			{
			input.read((char *)&entry, sizeof(entry));
			if(!input.good())
				break;
			m_base.insert(entry);
			recordsRead++;
			}
		input.close();
		DEBUGLOG_L(4, ("Hash_FileManager::Load, read %u records, size = %u\n", recordsRead, m_base.size()));
		return true;
		}

	bool LoadRange(GCFOS_CLIENTID cur_client, UINT32 start_seq)
		{
		UINT32					seq;
		TCHAR					LCUD_filename[LCUD_FILE_PATH_LEN];
		bool					rtn = false;

		for(seq = start_seq+1; ; seq++)
			{
			_stprintf_s(LCUD_filename, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\%u"), g_LCUD_LocationLocal, cur_client, seq);
			if(!LoadOneFile(LCUD_filename))
				break;
			rtn = true; // we successfully loaded at least one file
			}
		return rtn;
		}

	bool Load(GCFOS_CLIENTID cur_client)
		{
		TCHAR									szObjectname[16];
		TCHAR									LCUD_filename[LCUD_FILE_PATH_LEN];
		System::String							^LCUD_filename_S;
		System::String							^objectname_S;
		System::IO::Stream						^Stream;

		m_base.clear();

		// Load the BASE (the "0" file)
		_stprintf_s(LCUD_filename, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\0"), g_LCUD_LocationLocal, cur_client);
		if(LoadOneFile(LCUD_filename) == false)
			{
			if(g_LCUD_Repo == NULL)
				{
				DEBUGLOG_L(3, ("Hash_FileManager::Load no repository configured for failed load of %S\n", LCUD_filename));
				return false;
				}
			// fetch from repository
			_stprintf_s(szObjectname, CHARCOUNT(szObjectname), _T("%010u"), cur_client);
			objectname_S = gcnew System::String(szObjectname);
			LCUD_filename_S = gcnew System::String(LCUD_filename);

			if(g_LCUD_Repo->GetObject(objectname_S, Stream, false, gcnew System::String(g_LCUD_Location)))
				{
				try {
					System::IO::FileStream ^myfile = gcnew System::IO::FileStream(LCUD_filename_S, System::IO::FileMode::Create);
					Stream->CopyTo(myfile);
					myfile->Close();
					}
				catch(...)
					{
					}

				// attempt load again now that it's been retrieved
				if(!LoadOneFile(LCUD_filename))
					{
					return false;
					}
				}
			}

		return true;
		}

	bool Save(GCFOS_CLIENTID cur_client, gcfosdbTxn *txn)
		{
		btree::btree_set<T>::iterator iter;
		std::ofstream			output;
		TCHAR					LCUD_filename[LCUD_FILE_PATH_LEN];
		System::String			^objectname_S;
		TCHAR					szObjectname[16];
		bool					rtn = true;
		GCFOS_CLIENT_ENTRY		clientrec;
		int						rc;
		UINT32					newrecs = 0;
		System::IO::FileStream  ^fs;

		clientrec.clientid = cur_client;
		rc = g_Clients->find(&clientrec, txn);
		if(rc != 0)
			{
			DEBUGLOG_L(2, ("Hash_FileManager::Save, client %u, unable to start locate record, error %d\n", cur_client, rc));
			return true;
			// return true so that the limbo records for this non-existant client will be deleted
			}

		if(m_base.size() == 0 )
			{
			// this is a special case -- this is a brand-new client so we will put all records into the
			// base "0" file and not increment the sequence number
			DEBUGLOG_L(3, ("Hash_FileManager::Save, client %u -- new client, no existing base\n", cur_client));
			clientrec.lcud_seq = 0;
			}
		else
			{
			clientrec.lcud_seq++;
			}

		// make sure sub-dir exists first
		_stprintf_s(LCUD_filename, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT, g_LCUD_LocationLocal, cur_client);
		CreateDirectory(LCUD_filename, NULL);
		_stprintf_s(LCUD_filename, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\%u"), g_LCUD_LocationLocal, cur_client, clientrec.lcud_seq);

		output.open(LCUD_filename, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
		if(output.fail())
			{
			DEBUGLOG_L(2, ("Hash_FileManager::Save, client %u, unable to start create file, state %u\n", cur_client, output.rdstate()));
			return false;
			}

		for(iter = m_new.begin(); iter != m_new.end(); iter++)
			{
			if(m_base.find(*iter) == m_base.end())
				{
				// Only record new entries not found in base
				// as the file we are writing is a "delta" file
				output.write((LPCSTR)std::addressof(*iter), sizeof(T));
				newrecs++;
				}
			}

		DEBUGLOG_L(3, ("Hash_FileManager::Save, client %u, new records discovered = %u\n", cur_client, newrecs));
		output.close();
		if(newrecs > 0)
			{
			// there are some new records, update the client-db with the new seq#
			// commit the transaction
			g_Clients->insert(&clientrec, txn);
			}
		else
			{
			// no point updating client, there are no updates
			m_new.clear();
			m_base.clear();
			DeleteFile(LCUD_filename); // no point keeping this file
			return true;
			}

		// Now merge new into base and create new base file

		for(iter = m_new.begin(); iter != m_new.end(); iter++)
			{
			m_base.insert(*iter);
			}
		m_new.clear(); // not needed anymore

		if(clientrec.lcud_seq > 0)
			{
			// now write new base
			_stprintf_s(LCUD_filename, LCUD_FILE_PATH_LEN, LCUD_FILE_PATH_FMT _T("\\0"), g_LCUD_LocationLocal, cur_client);

			output.open(LCUD_filename, std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
			if(output.fail())
				{
				DEBUGLOG_L(2, ("Hash_FileManager::Save, client %u, unable to start create new base, state %u\n", cur_client, output.rdstate()));
				return false;
				}

			newrecs = 0;
			for(iter = m_base.begin(); iter != m_base.end(); iter++)
				{
				output.write((LPCSTR)std::addressof(*iter), sizeof(T));
				newrecs++;
				}

			DEBUGLOG_L(3, ("Hash_FileManager::Save, client %u, new base entries = %u\n", cur_client, newrecs));
			output.close();
			}

		if(g_LCUD_Repo != NULL)
			{
			_stprintf_s(szObjectname, CHARCOUNT(szObjectname), _T("%010u"), cur_client);
			objectname_S = gcnew System::String(szObjectname);
			try {
				fs = gcnew System::IO::FileStream(gcnew System::String(LCUD_filename), System::IO::FileMode::Open);
				if(!g_LCUD_Repo->Put(objectname_S, fs, gcnew System::String(g_LCUD_Location)))
					{
					System::Console::WriteLine("Hash_FileManager: Error during PutObject {0}", objectname_S);
					// undo the buffer changes to force re-send of this object needed
					rtn = false;
					}
				fs->Close();
				}
			catch(...)
				{
				System::Console::WriteLine("Hash_FileManager: save exception for {0}", objectname_S);
				rtn = false;
				}
			}

		return rtn;
		}
		
	bool Insert(T item)
		{
		std::pair<btree::btree_set<T>::iterator,bool> ret;
		ret = m_new.insert(item);
		return ret.second;
		}
	size_t Size(bool bNew = false)
		{
		if(bNew)
			return m_new.size();
		else
			return m_base.size();
		}

	void PackToMemory(PGCFOS_CONNECT_STATE context)
		{
		T					findentry;
		LPBYTE				p = (LPBYTE)(context->buffer.buf);
		btree::btree_set<T>::iterator iter;

		context->outputOffset = 0;
		context->remaining = GCFOS_BUFSIZE;

		if(context->offset == 0)
			{
			iter = m_base.begin();
			*(PUINT64)(context->buffer.buf) = m_base.size();
			p += sizeof(UINT64);
			context->remaining -= sizeof(UINT64);
			}
		else
			{
			memcpy(findentry.SHA1, context->SHA1, GCFOS_SHA1_LEN);
			findentry.size = context->size;
			iter = m_base.find(findentry);
			_ASSERTE(iter != m_base.end());
			iter++;
			}

		while(iter != m_base.end())
			{
			memcpy(p, &iter->SHA1, sizeof(T));
			context->remaining -= sizeof(T);
			context->offset++;
			if(context->remaining > sizeof(T))
				{
				p += sizeof(T);
				iter++;
				continue;
				}
			else
				{
				context->size = iter->size;
				memcpy(context->SHA1, p, GCFOS_SHA1_LEN);
				break;
				}
			}
		return;
		}

private:
	btree::btree_set<T> m_base;
	btree::btree_set<T> m_new;
	};
#pragma managed(pop)

#ifndef _UNICODE
#define tobin tobin_A
#define tohex tohex_A
#else
#define tobin tobin_W
#define tohex tohex_W
#endif

void tohex_A(LPBYTE p, size_t len, char* out, bool reverse = false);
void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse = false);

void tobin_A(LPSTR in, size_t len, LPBYTE p, bool reverse = false);
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse = false);

void GCFOS_ConsoleHandler();
void waitRandomBit();
bool CheckpointDB();
void PrintTime(FILE* logfile = NULL, bool printLF = false, time_t *tm_use = NULL);
LSTATUS SetRegEntryWithDefault(HKEY hKey, LPCTSTR ValueName, LPVOID Value, DWORD dwReqType, DWORD dwReqLen, LPVOID Default);
void DumpActiveUserSessions();
void AnalyzeBlockRecords();
void GCFOSDebugLog(LPCSTR formatstr, ...);
bool RequestConfirmationOnAction(LPCSTR pszAction);
void VerifyRecentBlockFiles();
void RebuildBlockDatabaseFromStore();




   
       
   
     
   
 
 
 
             
    
 
     
