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

#include "stdafx.h"

#include "Project.h"
#include "conio.h"
#include "Handling.h"

#pragma managed(push, off)

std::istream& operator>> (std::istream& in, GCFOS_LIMBO_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_LIMBO_ENTRY));
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_LIMBO_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_LIMBO_ENTRY));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_RESIDENT_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_RESIDENT_ENTRY));
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_RESIDENT_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_RESIDENT_ENTRY));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_WANTED_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_WANTED_ENTRY));
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_WANTED_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_WANTED_ENTRY));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_CLIENT_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_CLIENT_ENTRY));
	_tcsupr(entry.szName);
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_CLIENT_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_CLIENT_ENTRY));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_SESSION_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_SESSION_ENTRY));
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_SESSION_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_SESSION_ENTRY));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_UPDATE_ENTRY& entry)
	{
	// This is unusual compared to other methods -- it does not read/write the entire record
	in.read(((char*)&entry) + FIELD_OFFSET(GCFOS_UPDATE_ENTRY, SHA1), sizeof(GCFOS_UPDATE_ENTRY) - FIELD_OFFSET(GCFOS_UPDATE_ENTRY, SHA1));
	entry.rec = 0;
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_UPDATE_ENTRY& entry)
	{
	// This is unusual compared to other methods -- it does not read/write the entire record
	out.write(((char*)&entry) + FIELD_OFFSET(GCFOS_UPDATE_ENTRY, SHA1), sizeof(GCFOS_UPDATE_ENTRY) - FIELD_OFFSET(GCFOS_UPDATE_ENTRY, SHA1));
	return out;
	}

std::istream& operator>> (std::istream& in, GCFOS_BLOCK_ENTRY& entry)
	{
	in.read((char*)&entry, sizeof(GCFOS_BLOCK_ENTRY));
	return in;
	}

std::ostream& operator<< (std::ostream& out, const GCFOS_BLOCK_ENTRY& entry)
	{
	out.write((char*)&entry, sizeof(GCFOS_BLOCK_ENTRY));
	return out;
	}

void waitRandomBit()
	{
	int wait = rand() % 0xf + 1; // get random number between 1 and 16
	wait = wait * 10; // Wait 10ms per random number
	// wait between 10 and 160ms 
	Sleep(wait);
	}

#pragma managed(push, on)

void VerifyAllResidentFiles()
	{
	// This function is for DEBUG/SANITY-CHECKING purposes and should rarely be used in production
	// It will enumerate through the resident db and then check that the corresponding
	// objects are present on S3
	gcfosdbCursor							*cursor;
	GCFOS_RESIDENT_ENTRY					entry;
	gcfosdbTxn								*txn;
	int										rc;
	UINT64									count = 0;
	System::String							^myprefix;
	char									hexstr[(GCFOS_SHA1_LEN * 2)+1];
	UINT32									objCount;
	int										errors = 0;
	System::Collections::Generic::List<System::String ^> ^names = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;

	std::cout << "VerifyAllResidentFiles: Entry" << std::endl;
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		std::cout << "VerifyAllResidentFiles: Unable to start txn: " << rc << std::endl;
		return;
		}

	rc = g_Resident->createCursor(&cursor, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn);
	if(rc != 0)
		{
		gcfosdb::AbortTxn(txn);
		std::cout << "VerifyAllResidentFiles: Unable to create cursor: " << rc << std::endl;
		return;
		}

	while(g_Resident->getNext(cursor, (PUCHAR)&entry) == 0)
		{
		tohex_A(entry.SHA1, GCFOS_SHA1_LEN, hexstr);
		myprefix =  gcnew System::String(hexstr);
		sprintf_s(hexstr, 9, "%08x", entry.size);
		System::String ^sizehex = gcnew System::String(hexstr);
		myprefix += "-";
		myprefix += sizehex;
		myprefix += "/";

		objCount = 0;
		if(g_Repo->GetList(myprefix, names, sizes, g_Repo2))
			{
			objCount = names->Count;
			}
		else
			{
			System::Console::WriteLine("VerifyAllResidentFiles: Error during ListObjects {0}", myprefix);
			errors++;
			}
		if(objCount == GCFOS_OBJECT_COUNT_FOR_ENTRY(entry.size) + 1)
			{
			count++;
			}
		else
			{
			System::Console::WriteLine("VerifyAllResidentFiles: Expected {0} objects found for {1}, but found {2}",
				GCFOS_OBJECT_COUNT_FOR_ENTRY(entry.size) + 1, myprefix, objCount);
			errors++;
			}
		if(errors > 20)
			{
			std::cout << "VerifyAllResidentFiles: too many errors, aborting verification" << std::endl;
			break;
			}
		}
	gcfosdb::closeCursor(cursor);
	cursor = NULL;
	gcfosdb::CommitTxn(txn);
	std::cout << "VerifyAllResidentFiles: Records verified: " << count << ", errors: " << errors << std::endl;
	}

#pragma managed(pop)

void GCFOS_Statistics()
	{	
	_tprintf_s(TEXT("\nLimbo stats\n"));
	g_Limbo->PrintDBStats();

	_tprintf_s(TEXT("\nLimbo2 stats\n"));
	g_Limbo2->PrintDBStats();

	_tprintf_s(TEXT("\nResident stats\n"));
	g_Resident->PrintDBStats();
	
	_tprintf_s(TEXT("\nWanted stats\n"));
	g_Wanted->PrintDBStats();

	_tprintf_s(TEXT("\nUpdate stats\n"));
	g_Update->PrintDBStats();

	_tprintf_s(TEXT("\nClient stats\n"));
	g_Clients->PrintDBStats();

#ifdef ULTRABAC_CLOUD_USE
	_tprintf_s(TEXT("\nBanned IP stats\n"));
	g_BannedIPs->PrintDBStats();
#else
	_tprintf_s(TEXT("\nClient2 stats\n"));
	g_Clients2->PrintDBStats();
#endif//ULTRABAC_CLOUD_USE

	_tprintf_s(TEXT("\nSessions stats\n"));
	g_Sessions->PrintDBStats();

	if(g_bDedupeBlocks)
		{
		_tprintf_s(TEXT("\nBlocks stats\n"));
		g_Blocks->PrintDBStats();
		}
	return;
	}

void GCFOS_Dump()
	{
	DB_FileManager<GCFOS_LIMBO_ENTRY> LimboManager;
	DB_FileManager<GCFOS_RESIDENT_ENTRY> ResidentManager;
	DB_FileManager<GCFOS_WANTED_ENTRY> WantedManager;
	DB_FileManager<GCFOS_CLIENT_ENTRY> ClientManager;
	DB_FileManager<GCFOS_BLOCK_ENTRY> BlocksManager;

	if(!RequestConfirmationOnAction("DUMP all database files to bin files"))
		return;

	ClientManager.ExportList("ClientList.bin", g_Clients);
	LimboManager.ExportList("LimboList.bin", g_Limbo);
	ResidentManager.ExportList("ResidentList.bin", g_Resident);
	WantedManager.ExportList("WantedList.bin", g_Wanted);
	BlocksManager.ExportList("Blocks.bin", g_Blocks);
	}

bool RequestConfirmationOnAction(LPCSTR pszAction)
	{
	CHAR		szResponse[5];

	printf("Are you sure you wish to %s ?\n", pszAction);
	printf("Enter 'yes' to proceed: ");
	fflush(stdout);
	fflush(stdin);
	if(fgets(szResponse, 5, stdin) != NULL)
		{
		szResponse[3] = 0;
		if(_stricmp(szResponse, "yes") == 0)
			{
			return true;
			}
		}

	printf("Aborting action\n");
	return false;
	}

void GCFOS_Load()
	{
	gcfosdbTxn						*txn;
	GCFOS_LIMBO_ENTRY				limboEntry;
	GCFOS_LIMBO_2_ENTRY				limbo2Entry;
#ifndef ULTRABAC_CLOUD_USE
	GCFOS_CLIENT_ENTRY				clientEntry;
	GCFOS_CLIENT_2_ENTRY			client2Entry;
#endif//ULTRABAC_CLOUD_USE

	if(!RequestConfirmationOnAction("load all database files from bin files"))
		return;

	int								rc;
	gcfosdbCursor					*cursor;
	int								getflags = 0;
	UINT64							recordsadded = 0;
	int								insert_flags = MDB_APPEND;

	DB_FileManager<GCFOS_LIMBO_ENTRY> LimboManager;
	DB_FileManager<GCFOS_RESIDENT_ENTRY> ResidentManager;
	DB_FileManager<GCFOS_WANTED_ENTRY> WantedManager;
	DB_FileManager<GCFOS_CLIENT_ENTRY> ClientManager;
	DB_FileManager<GCFOS_BLOCK_ENTRY> BlocksManager;

	ClientManager.ImportList("ClientList.bin", g_Clients, insert_flags);
	LimboManager.ImportList("LimboList.bin", g_Limbo, insert_flags);
	ResidentManager.ImportList("ResidentList.bin", g_Resident, insert_flags);
	WantedManager.ImportList("WantedList.bin", g_Wanted, insert_flags);
	BlocksManager.ImportList("Blocks.bin", g_Blocks, insert_flags);

	_tprintf(L"Migrating records to limbo2\n");
	// copy limbo records to limbo2
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		_tprintf(L"GCFOS_Load: Unable to begin txn %d\n", rc);
		return;
		}

restart_load:
	rc = g_Limbo->createCursor(&cursor, 0, txn);
	if(rc != 0)
		{
		_tprintf(L"GCFOS_Load: Unable to create limbo cursor %d\n", rc);
		gcfosdb::AbortTxn(txn);
		return;
		}
	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Limbo->get(cursor, &limboEntry, getflags, txn);
		if(rc != 0)
			break;
		limbo2Entry.client = limboEntry.client;
		limbo2Entry.size = limboEntry.size;
		memcpy(limbo2Entry.SHA1, limboEntry.SHA1, GCFOS_SHA1_LEN);
		limbo2Entry.whenAdded = limboEntry.whenAdded;
		rc = g_Limbo2->insert(&limbo2Entry, txn);
		if(rc == MDB_MAP_FULL)
			{
			gcfosdb::ResizeLMDB(&txn);
			goto restart_load;
			}
		if(rc != 0)
			{
			_tprintf(L"GCFOS_Load: Error inserting to limbo2: %d\n", rc);
			break;
			}
		recordsadded++;
		getflags = gcfosdb_NEXT;
		}
	gcfosdb::CommitTxn(txn);
	_tprintf(L"Finished migrating %I64u records to limbo2\n", recordsadded);


#ifndef ULTRABAC_CLOUD_USE
	_tprintf(L"Migrating records to client2\n");
	// copy limbo records to limbo2
	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		_tprintf(L"GCFOS_Load: Unable to begin txn2 %d\n", rc);
		return;
		}
	
	rc = g_Clients->createCursor(&cursor, 0, txn);
	if(rc != 0)
		{
		_tprintf(L"GCFOS_Load: Unable to create client cursor %d\n", rc);
		gcfosdb::AbortTxn(txn);
		return;
		}
	getflags = gcfosdb_FIRST;
	while(true)
		{
		rc = g_Clients->get(cursor, &clientEntry, getflags, txn);
		if(rc != 0)
			break;
		memcpy(client2Entry.szName, clientEntry.szName, GCFOS_COMPUTER_NAME_BYTES);
		client2Entry.clientid = clientEntry.clientid;
		rc = g_Clients2->insert(&client2Entry, txn);
		if(rc != 0)
			{
			_tprintf(L"GCFOS_Load: Error inserting %u:%s to clients2: %d\n", client2Entry.clientid, client2Entry.szName, rc);
			}
		getflags = gcfosdb_NEXT;
		}
	rc = gcfosdb::CommitTxn(txn);
	if(rc != 0)
		{
		_tprintf(L"Error committing txn, %d\n", rc);
		}
	_tprintf(L"Finished migrating records to clients2\n");
#endif//ULTRABAC_CLOUD_USE
	}

bool CheckpointDB()
	{
	return (gcfosdb::Checkpoint() == 0);
	}

void MigrateRecodsFromResidentToWanted()
	{
	_tprintf_s(TEXT("DISABLED\n"));
#if 0
	GCFOS_RESIDENT_ENTRY	residentEntry;
	GCFOS_WANTED_ENTRY		wantedEntry;
	gcfosdbCursor			*cursor;
	gcfosdbTxn				*txn;
	int						rc;

	int mykey;
	int movedrecords = 0;

	_tprintf_s(TEXT("This command moves all records from resident to wanted, and deletes all records\n"));
	_tprintf_s(TEXT("in wanted in the process. This is irreversible and will result in the requests\n"));
	_tprintf_s(TEXT("for all files being re-made.\nThis command should only be used during testing\n"));
	_tprintf_s(TEXT("\nAre you sure you wish to continue:"));
	mykey = _getch();
	if(mykey != 'y')
		return;

	_tprintf_s(TEXT("\nMigrating records...\n"));

	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("Failed getting txn %d\n", rc));
		return;
		}

	if(g_Resident->createCursor(&cursor, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) == 0)
		{
		while(g_Resident->getNext(cursor, (PUCHAR)&residentEntry) == 0)
			{
			movedrecords++;
			memcpy(wantedEntry.SHA1, residentEntry.SHA1, GCFOS_SHA1_LEN);
			wantedEntry.size = residentEntry.size;
			g_Wanted->insert(&residentEntry, txn);
			cursor->del(0);
			}
		cursor->close();
		cursor = NULL;
		}
	_tprintf_s(TEXT("%u records migrated...\n"), movedrecords);
	gcfosdb::CommitTxn(txn, 0);
#endif
	}

void GCFOS_ShowDBInfo()
	{
	UINT32			recordsRead = 0;
	gcfosdbCursor	*c_limbo;
	GCFOS_LIMBO_2_ENTRY limbo2Entry;
	GCFOS_LIMBO_ENTRY limboEntry;
	gcfosdbTxn		*txn = NULL;
	UINT32			getflags;
	GCFOS_CLIENTID	cur_client = 0;
	int				rc;
	UINT64			tot_size, client_size;
	UINT64			tot_recs = 0;

	_tprintf_s(TEXT("Examining limbo db\n\n"));

	if(gcfosdb::BeginTxn(NULL, &txn, 0) != 0 || txn == NULL)
		{
		DEBUGLOG_L(1, ("GCFOS_ShowDBInfo: failed to begin txn\n"));
		return;
		}

	if(g_Limbo2->createCursor(&c_limbo, gcfosdb_CURSOR_BULK | gcfosdb_READ_UNCOMMITTED, txn) != 0)
		{
		gcfosdb::AbortTxn(txn);
		DEBUGLOG_L(1, ("GCFOS_ShowDBInfo: failed to get limbo cursor\n"));
		return;
		}

	getflags = gcfosdb_FIRST;
	tot_size = 0;
	client_size = 0;
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
				_tprintf(_T("Client %u: Total records = %u, total size = %u GB\n"), cur_client, recordsRead, (uint32_t)(client_size >> 30LL));
				tot_recs += recordsRead;
				tot_size += client_size;
				}
			client_size = 0;
			cur_client = limbo2Entry.client;
			recordsRead = 0;
			}
		if(rc == 0)
			{
			recordsRead++;
			client_size += limboEntry.size;
			}
		else
			{
			break;
			}
		}

	gcfosdb::closeCursor(c_limbo);
	gcfosdb::CommitTxn(txn);

	_tprintf(_T("Complete. Summary: Total records = %I64u, total size = %u GB\n"), tot_recs, (uint32_t)(tot_size >> 30LL));
	}

void GCFOS_ConsoleHandler()
	{
	int mykey;

	_tprintf_s(TEXT("Press '?' for help on commands\n"));

	while(true)
		{
		mykey = _getch();

		if(g_bRedirectionMode)
			{
			if(mykey != 'x')
				{
				_tprintf_s(TEXT("Redirection mode -- only valid command is 'x' to exit\n"));
				continue;
				}
			break; // exit
			}

		switch(mykey)
			{
			case '?':
				_tprintf_s(TEXT("'1 - 5' - set debug level (1=lowest)\n"));
				_tprintf_s(TEXT("'c' - manual checkpoint\n"));
				_tprintf_s(TEXT("'i' - show information on database files\n"));
				_tprintf_s(TEXT("'s' - show statistics\n"));
				_tprintf_s(TEXT("'d' - dump lists to files\n"));
				_tprintf_s(TEXT("'l' - load lists from files\n"));
				_tprintf_s(TEXT("'p' - process LimboList\n"));
				_tprintf_s(TEXT("'t' - transfer records from resident to wanted DEBUG ONLY\n"));
				_tprintf_s(TEXT("'u' - show current active user sessions\n"));
				_tprintf_s(TEXT("'r' - report session activity\n"));
				_tprintf_s(TEXT("'a' - analyze all block records (aging info)\n"));
				_tprintf_s(TEXT("'v' - verify all resident files (may take a long time)\n"));
				_tprintf_s(TEXT("'b' - Rebuild entire block store database from source files (LONG)\n"));
				_tprintf_s(TEXT("'x' - exit\n"));
				break;

			case 'a':
				AnalyzeBlockRecords();
				break;

			case 'b':
				RebuildBlockDatabaseFromStore();
				break;

			case 'c':
				if(g_bRedirectionMode)
					{
					_tprintf_s(TEXT("Invalid selection -- in redirection mode\n"));
					break;
					}

				_tprintf_s(TEXT("Checkpointing db\n"));
				if(CheckpointDB())
					_tprintf_s(TEXT("Checkpoint successful\n"));
				else
					_tprintf_s(TEXT("Checkpoint failed\n"));

				break;

			case 'i':
				if(g_bRedirectionMode)
					{
					_tprintf_s(TEXT("Invalid selection -- in redirection mode\n"));
					break;
					}
				GCFOS_ShowDBInfo();
				break;

			case 's': // statistics
				GCFOS_Statistics();
				break;

			case 'd': // dump
				GCFOS_Dump();
				break;

			case 'l': // load
				GCFOS_Load();
				break;

			case 'p': // process LimboList
				ProcessLimboEntries();
				break;

			case 'X':
				g_ShutdownResetLSN = true;
			case 'x':
				return;

			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
				g_debugLvl = mykey - '0';
				_tprintf_s(TEXT("Debug level now %u\n"), g_debugLvl);
				break;

			case 't':
				MigrateRecodsFromResidentToWanted();
				break;

			case 'u':
				DumpActiveUserSessions();
				break;

			case 'v':
				VerifyAllResidentFiles();
				break;

			case 'r':
				ReportSessionActivity();
				break;

			default:
				_tprintf_s(TEXT("Unknown command\n"));
				break;
			}
		}
	
	}


void tohex_A(LPBYTE p, size_t len, char* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = p + len - 1;
		}
	else
		{
		in = p;
		}

	while(len--)
		{
		sprintf_s(out, 3, "%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}

void tobin_A(LPBYTE in, size_t len, UCHAR *p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}
}

// Unicode versions

void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = (LPBYTE)p + len - 1;
		}
	else
		{
		in = (LPBYTE)p;
		}

	while(len--)
		{
		swprintf_s(out, 3, L"%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}
   
       
   
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (BYTE)(*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (BYTE)(*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}

}

void GCFOSDebugLog(LPCSTR formatstr, ...)
	{
	EnterCriticalSection(&g_csDebug);

	PrintTime(g_DebugLog);
	va_list argptr;
	va_start(argptr, formatstr);
	vfprintf(g_DebugLog, formatstr, argptr);
	va_end(argptr);
	LeaveCriticalSection(&g_csDebug);
	}

void PrintTime(FILE *file /* = NULL*/, bool printLF/* = false*/, time_t *tm_use)
	{
	CHAR			timestr[40];
	time_t			timenow;
	struct tm		timeinfo;

	if(tm_use == NULL)
		{
		time(&timenow);
		tm_use = &timenow;
		}

	localtime_s(&timeinfo, tm_use);

	strftime(timestr, sizeof(timestr), "%x %X ", &timeinfo);
	if(file == NULL)
		{
		printf(timestr);
		if(printLF)
			printf("\n");
		}
	else
		{
		fprintf(file, timestr);
		if(printLF)
			fprintf(file, "\n");
		}
	}

LSTATUS SetRegEntryWithDefault(HKEY hKey, LPCTSTR ValueName, LPVOID Value, DWORD dwReqType, DWORD dwReqLen, LPVOID Default)
	{
	DWORD dwType;
	DWORD dwLen = dwReqLen;
	LSTATUS Result;

	Result = RegQueryValueEx(hKey, ValueName, 0, &dwType, (LPBYTE)Value, &dwLen);
	if(Result == ERROR_FILE_NOT_FOUND)
		{
		if(Default == NULL)
			return Result; // no default provided -- return error

		if(dwReqType == REG_SZ)
			{
			dwReqLen = (DWORD)(_tcslen((LPCTSTR)Default) + 1) * sizeof(TCHAR);
			}
		memcpy(Value, Default, dwReqLen);
		Result = RegSetValueEx(hKey, ValueName, 0, dwReqType, (LPBYTE)Value, dwReqLen);
		switch(dwReqType)
			{
			case REG_DWORD:
				DEBUGLOG_L(1, ("Setting %S to default (%u)\n", ValueName, *(LPDWORD)Default));
				break;
			case REG_SZ:
				DEBUGLOG_L(1, ("Setting %S to default (%S)\n", ValueName, (LPCTSTR)Default));
				break;
			}
		}
	else if(ERROR_SUCCESS != Result || dwType != dwReqType)
		{
		DEBUGLOG_L(1, ("Failed to query registry key at %S, error %d\n", CStringA(ValueName), Result));
		if(Result == 0)
			return ERROR_INVALID_PARAMETER;
		else
			return Result;
		}
	return ERROR_SUCCESS;
	}

void DumpActiveUserSessions()
	{
	UINT					active = 0;
	UINT					i;
	btree::btree_set<PVOID>::iterator iter;
	PGCFOS_CONNECT_STATE	context;
	gcfosdbTxn				*txn = NULL;
	int						rc;
	GCFOS_CLIENT_ENTRY		client;

	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(2, ("DumpActiveUserSessions: Unable to get txn %d\n", rc));
		return;
		}

#ifndef ULTRABAC_CLOUD_USE
	gcfosdbCursor			*c_clients;

#if 0//When enabled, resets the seq of all clients!
	if(g_debugLvl >= 5 && g_Clients->createCursor(&c_clients, 0, txn) == 0)
		{
		i = 0;
		rc = g_Clients->get(c_clients, &client, gcfosdb_FIRST, txn);
		while(rc == 0)
			{
			client.lcud_seq = 0;
			rc = g_Clients->put(c_clients, &client, MDB_CURRENT);
			if(rc != 0)
				{
				DEBUGLOG_L(2, ("DumpActiveUserSessions: put failed %d\n", rc));
				break;
				}
			i++;
			rc = g_Clients->get(c_clients, &client, gcfosdb_NEXT, txn);
			}
		DEBUGLOG_L(2, ("DumpActiveUserSessions: %u clients reset seq to 0\n", i));
		gcfosdb::closeCursor(c_clients);
		}
#endif

	if(g_debugLvl >= 5)
		{
		if(g_Clients->createCursor(&c_clients, 0, txn) == 0)
			{
			rc = g_Clients->get(c_clients, &client, gcfosdb_FIRST, txn);
			_tprintf(TEXT("Clients:\n"));
			while(rc == 0)
				{
				_tprintf(TEXT("%u: %s %u\n"), client.clientid, client.szName, client.lcud_seq);
				rc = g_Clients->get(c_clients, &client, gcfosdb_NEXT, txn);
				}
			gcfosdb::closeCursor(c_clients);
			}
		}
#endif

	EnterCriticalSection(&g_csConnections);
	for(i = 0, iter = g_ConnectState.begin(); iter != g_ConnectState.end(); iter++, i++)
		{
		context = (PGCFOS_CONNECT_STATE)*iter;
		if(context->status == STATE_CONNECTED)
			{
			memset(&client, 0, sizeof(client));
			client.clientid = context->client;
			g_Clients->find(&client, txn);
			active++;
#ifdef ULTRABAC_CLOUD_USE
			_tprintf(TEXT("%u: Connected to %s, seq:%u, queries: %u, resident: %u, donated: %u, retrieved: %u, limbo: %u"),
				context->client,
				(LPCTSTR)CString(context->connectedToHost),
				client.lcud_seq,
				context->count_queries, 
				context->count_resident_hits, 
				context->count_donations, 
				context->count_retrieves, 
				context->count_limbo_results);
#else
			_tprintf(TEXT("%u(%s): Connected to %s"), context->client, client.szName, (LPCTSTR)CString(context->connectedToHost));
			_tprintf(TEXT(", seq:%u, queries: %u, resident: %u, donated: %u, retrieved: %u, limbo: %u, blk q:%u, blk stored:%u, blk_retr:%u"), 
				client.lcud_seq, context->count_queries, context->count_resident_hits, context->count_donations, context->count_retrieves, context->count_limbo_results, context->count_blks_queried, context->count_blks_stored,
				context->count_blks_retrieved);
#endif
			if(context->activityTimer != GCFOS_INITIAL_ACTIVITY_VALUE)
				{
				_tprintf(TEXT(", inactive %u secs"), (GCFOS_INITIAL_ACTIVITY_VALUE - context->activityTimer) * GCFOS_MAINTENANCE_PERIOD);
				}
			_tprintf(L"\n");
			}
		}
	LeaveCriticalSection(&g_csConnections);
	rc = gcfosdb::CommitTxn(txn);
	if(rc != 0)
		{
		DEBUGLOG_L(2, ("DumpActiveUserSessions: Unable to commit txn %d\n", rc));
		}

	_tprintf(TEXT("Complete. %u active sessions found (%u total)\n"), active, i);
	}

GCFOS_CONNECT_STATE::GCFOS_CONNECT_STATE()
	{
	InitializeConnectionState(INVALID_SOCKET, IOCP_OP_ACCEPT, STATE_ACCEPT);
// Default constructor
	}

GCFOS_CONNECT_STATE::GCFOS_CONNECT_STATE(SOCKET in_s, IOCP_OP_TYPE in_op, GCFOS_CONNECT_STATUS in_state)
	{
	InitializeConnectionState(in_s, in_op, in_state);
	}

#pragma managed(push, on)

void GCFOS_CONNECT_STATE::InitializeConnectionState(SOCKET in_s, IOCP_OP_TYPE in_op, GCFOS_CONNECT_STATUS in_state)
	{
	InterlockedIncrement(&g_SessionsOpen);
	buffer.buf = (CHAR*)VirtualAlloc(NULL, GCFOS_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(buffer.buf == NULL)
		{
		DEBUGLOG_L(1, ("GCFOS_CONNECT_STATE() -- VirtualAlloc FAILED %u\n", GetLastError()));
		}
	buffer.len = GCFOS_BUFSIZE;
	op = in_op;
	s_acc = in_s;
	status = in_state;
	activityTimer = GCFOS_INITIAL_ACTIVITY_VALUE;
	client = 0;
	bHdr = false;
	bCompressed = false;
	InError = false;
	hdr.blocksize = 0;
	remaining = 0;
	ContextForCalculatedHash = NULL;
	size = 0;
	inputBuffer = NULL;
	CurBlock = 0;
	memset(BlockSizes, 0, sizeof(BlockSizes));
	memset(&o, 0, sizeof(o));
	memset(&connectedTo, 0, sizeof(connectedTo));
	memset(&connectedToHost, 0, sizeof(connectedToHost));
	connectedToLen = 0;
	decompressedBuffer = NULL;
	outputOffset = 0;
	offset = 0;
	time = 0;
#ifdef ULTRABAC_CLOUD_USE
	challenge = NULL;
#endif
	od = NULL;
	pLCUD = NULL;
	iBlocksExpected = 0;
	count_donations = 0;
	count_queries = 0;
	count_resident_hits = 0;
	count_limbo_results = 0;
	count_retrieves = 0;
	count_retrieve_KB = 0;
	count_blks_queried = 0;
	count_blks_stored = 0;
	count_blks_retrieved = 0;
	session_record = 0;
	object_buffer = nullptr;
	}

GCFOS_CONNECT_STATE::~GCFOS_CONNECT_STATE()
	{
	if(inputBuffer)
		{
		VirtualFree(inputBuffer, 0, MEM_RELEASE);
		inputBuffer = NULL;
		}
	if(decompressedBuffer)
		{
		VirtualFree(decompressedBuffer, 0, MEM_RELEASE);
		decompressedBuffer = NULL;
		}
	if(buffer.buf)
		{
		VirtualFree(buffer.buf, 0, MEM_RELEASE);
		buffer.buf = NULL;
		}
	if(s_acc != INVALID_SOCKET)
		{
		closesocket(s_acc);
		s_acc = INVALID_SOCKET;
		}
	if(od != NULL)
		{
		if(od->sizes != NULL)
			{
			delete [] od->sizes;
			}
		delete od;
		od = NULL;
		}
	if(pLCUD != NULL)
		{
		delete pLCUD;
		pLCUD = NULL;
		}
	if(ContextForCalculatedHash != NULL)
		{
		delete[] (Ipp8u*)ContextForCalculatedHash;
		ContextForCalculatedHash = NULL;
		}
#ifdef ULTRABAC_CLOUD_USE
	if(challenge != NULL)
		{
		delete challenge;
		challenge = NULL;
		}
#endif//ULTRABAC_CLOUD_USE
	status = STATE_NOT_CONNECTED;
	client = 0;
	InterlockedDecrement(&g_SessionsOpen);
	// not possible to delete a gcroot, by going out-of-scope it should be marked for GC
	object_buffer = nullptr;
	}
#pragma managed(pop)

void AnalyzeBlockRecords()
	{
	const int analyze_interval = 7;
	const int analyze_interval_count = 20;
	const bool analyze_update_recs = false;
	UINT64 Counts[analyze_interval_count];

	UINT64 recs = 0;
	gcfosdbCursor *c_blocks;
	gcfosdbTxn *txn;
	int rc;
	GCFOS_BLOCK_ENTRY entry;
	GCFOS_UsefulTime timenow;
	int i, j;
	UINT16 age;
	UINT32 updated = 0;
	UINT32 deleted = 0;

	_tprintf_s(TEXT("AnalyzeBlockRecords: Entry\n"));
	memset(Counts, 0, sizeof(Counts));

	if(!RequestConfirmationOnAction("analyze all block records for aging info"))
		return;

	if(!g_bDedupeBlocks)
		{
		_tprintf_s(TEXT("AnalyzeBlockRecords: Dedupe blocks not enabled\n"));
		return;
		}
	if(!g_bEnableBlocksPurging)
		{
		_tprintf_s(TEXT("AnalyzeBlockRecords: Block purging not enabled\n"));
		return;
		}

	rc = gcfosdb::BeginTxn(NULL, &txn, (analyze_update_recs ? 0 : MDB_RDONLY));
	rc = g_Blocks->createCursor(&c_blocks, 0, txn);
	rc = g_Blocks->get(c_blocks, &entry, gcfosdb_FIRST, txn);
	rc = g_Blocks->getNext(c_blocks, &entry);// skip "locator" record
	while(rc == 0)
		{
/*
		if(entry.fileno >= 3443 && entry.fileno <= 3446)
			{
			g_Blocks->erase(c_blocks);
			deleted++;
			rc = g_Blocks->getNext(c_blocks, &entry);
			continue;
			}
*/

		if(analyze_update_recs && entry.last_ref == 0)
			{
			entry.last_ref = timenow.AsDays();
			g_Blocks->put(c_blocks, &entry, MDB_CURRENT);
			updated++;
			}
		age = timenow.AsDays() - entry.last_ref;
		recs++;
		if(recs % 100000 == 0)
			{
			printf("Processing record %I64u             \r", recs);
			rc = g_Blocks->closeCursor(c_blocks);
			if(analyze_update_recs)
				{
				rc = gcfosdb::CommitTxn(txn);
				if(rc != 0)
					{
					DEBUGLOG_L(1, ("Error committing txn: %d\n", rc));
					}
				}
			else
				{
				gcfosdb::AbortTxn(txn);
				}
			rc = gcfosdb::BeginTxn(NULL, &txn, (analyze_update_recs ? 0 : MDB_RDONLY));
			rc = g_Blocks->createCursor(&c_blocks, 0, txn);
			// reposition cursor
			rc = g_Blocks->get(c_blocks, &entry, gcfosdb_SET_RANGE, txn);
			}
		i = min(age / analyze_interval, (analyze_interval_count - 1));
		Counts[i]++;
		rc = g_Blocks->getNext(c_blocks, &entry);
		}
	printf("\n");
	if(rc != gcfosdb_NOTFOUND)
		{
		DEBUGLOG_L(1, ("Error reading blocksdb: %d\n", rc));
		}
	rc = g_Blocks->closeCursor(c_blocks);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("Error closing cursor: %d\n", rc));
		}
	rc = gcfosdb::CommitTxn(txn);
	if(rc != 0)
		{
		DEBUGLOG_L(1, ("Error committing txn: %d\n", rc));
		}
	_tprintf_s(TEXT("AnalyzeBlockRecords: Read %I64u records (%u updated, %u deleted)\n"), recs, updated, deleted);
	for(j = 0; j < analyze_interval_count; j++)
		{
		printf("%u  -   %I64u (%0.1f %%)\n", j * analyze_interval, Counts[j], (double)Counts[j] *100.0f /(double)recs);
		}
	return;
	}


#pragma managed(push, off)

bool ProcessSingleBlockStoreFile(HANDLE hFile, LPBYTE pCompressedBuffer, LPBYTE pUncompressedBuffer, UINT32 fileno, UINT32 *pBytesRead, UINT32 *pBlocksAdded, UINT32 *pBlocksNew)
	{
	UINT16						uCompressedSize;
	DWORD						dwLen;
	IppStatus					iDecompressionStatus;
	UINT32						uncompsize;
	UINT32						BytesRead;
	int							ctxsize;
	IppsHashState				*hashstate;
	LPBYTE						pHashBuffer;
	GCFOS_BLOCK_ENTRY			blockEntry;
	GCFOS_UsefulTime			timenow;
	UINT32						BlocksAdded, BlocksNew;
	UINT32						thisoffset;
	int							rc;
	gcfosdbTxn					*txn;
	bool						bRestarted = false;
	bool						bRtn = false;
	DWORD						dwRestart = 0;

	ippsHashGetSize(&ctxsize);
	hashstate = (IppsHashState*)( _malloca(ctxsize));

	// constant values in BlockEntry:
	blockEntry.fileno = fileno;
	blockEntry.last_ref = timenow.AsDays();

	BlocksAdded = 0;
	BlocksNew = 0;
	BytesRead = 0;

	*pBytesRead = 0;
	*pBlocksAdded = 0;
	*pBlocksNew = 0;

	rc = gcfosdb::BeginTxn(NULL, &txn, 0);
	if(rc != 0)
		{
		DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Unable to begin txn: %d\n", rc));
		CloseHandle(hFile);
		return false;
		}

	while(true)
		{
		thisoffset = BytesRead;
		if(!ReadFile(hFile, &uCompressedSize, sizeof(UINT16), &dwLen, NULL) || dwLen != sizeof(UINT16))
			{
			if(GetLastError() != ERROR_SUCCESS)
				{
				DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: failed reading stream, %d\n", GetLastError()));
				rc = -1; // abort the txn
				}
			else
				{
				rc = gcfosdb::CommitTxn(txn);
				if(rc == MDB_MAP_FULL)
					{
					gcfosdb::ResizeLMDB(&txn);
					SetFilePointer(hFile, dwRestart, NULL, FILE_BEGIN);
					continue;
					}
				else if(rc == 0)
					{
					bRtn = true; // normal EOF
					}
				else
					{
					DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Unable to commit txn: %d\n", rc));
					}
				}
			break;
			}

		BytesRead += sizeof(UINT16);

		if(uCompressedSize > GCFOS_BLOCK_SIZE)
			{
			DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Invalid data length in stream: %u at offset %u\n", (UINT32)uCompressedSize, BytesRead));
			// commit what we have so-far
			gcfosdb::CommitTxn(txn);
			bRtn = true;
			break;
			}

		if(!ReadFile(hFile, pCompressedBuffer, uCompressedSize, &dwLen, NULL) || dwLen != uCompressedSize)
			{
			DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Read(2) failed %u, %d\n", dwLen, GetLastError()));
			rc = -1;
			break;
			}
		BytesRead += dwLen;
		if(uCompressedSize != GCFOS_BLOCK_SIZE)
			{
			uncompsize = GCFOS_BLOCK_SIZE;
			iDecompressionStatus = ippsDecodeLZOSafe_8u(pCompressedBuffer, uCompressedSize, pUncompressedBuffer, &uncompsize);
			if(iDecompressionStatus != ippStsNoErr || uncompsize != GCFOS_BLOCK_SIZE)
				{
				DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Decompression failed, error %d:%u\n", (UINT32)iDecompressionStatus, uCompressedSize));
				rc = -1; // abort the txn
				break;
				}
			}

		ippsHashInit(hashstate, IPP_ALG_HASH_SHA512_224);
		pHashBuffer = (uCompressedSize == GCFOS_BLOCK_SIZE ? pCompressedBuffer : pUncompressedBuffer);
		ippsHashUpdate(pHashBuffer, GCFOS_BLOCK_SIZE, hashstate);
		ippsHashFinal(blockEntry.hash, hashstate);
		blockEntry.offset = thisoffset;

		rc = g_Blocks->find(&blockEntry, txn);
		if(rc == 0)
			{
			// block already exists, no need to add
			continue;
			}

		rc = g_Blocks->insert(&blockEntry, txn);
		BlocksAdded++;
		if(rc == 0)
			{
			BlocksNew++;
			if(BlocksNew % 100 == 0)
				{
				rc = gcfosdb::CommitTxn(txn);
				if(rc == MDB_MAP_FULL)
					{
					gcfosdb::ResizeLMDB(&txn);
					SetFilePointer(hFile, dwRestart, NULL, FILE_BEGIN);
					continue;
					}
				else if(rc != 0)
					{
					DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Unable to commit intermediate txn: %d\n", rc));
					break;
					}
				else
					{
					dwRestart = BytesRead;
					rc = gcfosdb::BeginTxn(NULL, &txn, 0);
					if(rc != 0)
						{
						DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Unable to begin new txn: %d\n", rc));
						break;
						}
					}
				}
			}
		else
			{
			if(rc != gcfosdb_KEYEXIST)
				{
				DEBUGLOG_L(2, ("ProcessSingleBlockStoreFile: Unable to insert record into blocks db: %d\n", rc));
				break;
				}
			}
		}

	if(rc != 0)
		{
		gcfosdb::AbortTxn(txn);
		CloseHandle(hFile);
		return false;
		}
	*pBytesRead = BytesRead;
	*pBlocksAdded = BlocksAdded;
	*pBlocksNew = BlocksNew;
	CloseHandle(hFile);

	return bRtn;
	}

void VerifyRecentBlockFiles()
	{
	TCHAR									szCurrentFile[MAX_PATH];
	UINT32									BlocksAdded, BlocksNew;
	UINT32									BytesProcessedThisFile;
	LPBYTE									pCompressedBuffer, pUncompressedBuffer;
	UINT32									currId;
	HANDLE									hFile;

	pCompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pUncompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE_DECOMP, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	for(currId = g_blks_fileID; ; currId--)
		{
		_stprintf_s(szCurrentFile, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, currId / GCFOS_BLOCKSTORE_FILES_PER_DIR, currId % GCFOS_BLOCKSTORE_FILES_PER_DIR);
		hFile = CreateFile(szCurrentFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	
		if(hFile == INVALID_HANDLE_VALUE)
			{
			DEBUGLOG_L(1, ("VerifyRecentBlockFiles: Unable to open %S (%d)\n", szCurrentFile, GetLastError()));
			break;
			}

		if(!ProcessSingleBlockStoreFile(hFile, pCompressedBuffer, pUncompressedBuffer, currId, &BytesProcessedThisFile, &BlocksAdded, &BlocksNew))
			{
			DEBUGLOG_L(1, ("VerifyRecentBlockFiles: Unable to process %S, error %d\n", szCurrentFile, GetLastError()));
			break;
			}
		else
			{
			DEBUGLOG_L(4, ("VerifyRecentBlockFiles: Processed blocks file %u - total %u blocks (%u new)\n", currId, BlocksAdded, BlocksNew));
			}
			
		if(BlocksNew == 0)
			{
			DEBUGLOG_L(4, ("VerifyRecentBlockFiles: stopping, no new blocks discovered\n", BlocksAdded, szCurrentFile));
			break;
			}

		if(WaitForSingleObject(g_ExitSignalled, 0) == WAIT_OBJECT_0)
			{
			break; // we've been asked to globally stop
			}

		if(currId == 0)
			{
			break; // no more blocks files possible
			}
		}

	VirtualFree(pCompressedBuffer, 0, MEM_RELEASE);
	VirtualFree(pUncompressedBuffer, 0, MEM_RELEASE);
	}

#pragma managed(pop)

void RebuildBlockDatabaseFromStore()
	{
	TCHAR									szCurrentFile[MAX_PATH];
	HANDLE									hFile;
	UINT32									currId;
	LPBYTE									pCompressedBuffer, pUncompressedBuffer;
	UINT32									BytesProcessedThisFile;
	UINT64									TotalBytesProcessed = 0;
	UINT32									BlocksAdded, BlocksNew;
	UINT64									TotalBlocksAdded = 0, TotalBlocksNew = 0;

	if(!RequestConfirmationOnAction("rebuild block database"))
		return;

	pCompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pUncompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCK_SIZE_DECOMP, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if(pCompressedBuffer == NULL || pUncompressedBuffer == NULL)
		{
		_tprintf(TEXT("RebuildBlockDatabaseFromStore: Failed to get memory required, %d\n"), GetLastError());
		return;
		}

	for(currId = 0; ; currId++)
		{
		_stprintf_s(szCurrentFile, MAX_PATH, GCFOS_BLOCKS_FILE_NAMING_FMT, g_BlocksDir, currId / GCFOS_BLOCKSTORE_FILES_PER_DIR, currId % GCFOS_BLOCKSTORE_FILES_PER_DIR);
		hFile = CreateFile(szCurrentFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if(hFile == INVALID_HANDLE_VALUE)
			{
			if(RetrieveBlockFileFromSecondary("RebuildBlockDatabaseFromStore", currId))
				{
				hFile = CreateFile(szCurrentFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
				if(hFile == INVALID_HANDLE_VALUE)
					{
					_tprintf(TEXT("Unable to open %s, error %d\n"), szCurrentFile, GetLastError());
					break;
					}
				}
			else
				{
				break;
				}
			}
		if(!ProcessSingleBlockStoreFile(hFile, pCompressedBuffer, pUncompressedBuffer, currId, &BytesProcessedThisFile, &BlocksAdded, &BlocksNew))
			{
			_tprintf(TEXT("Error processing %s\n"), szCurrentFile);
			break;
			}
		// hFile is always closed by ProcessSingleBlockStoreFile()
		TotalBytesProcessed += BytesProcessedThisFile;
		TotalBlocksAdded += BlocksAdded;
		TotalBlocksNew += BlocksNew;
		_tprintf(TEXT("MB Processed: %u\r"), (UINT32)(TotalBytesProcessed >> 20LL));
		}

	_tprintf(TEXT("\nComplete. Bytes Processed: %I64u (%u GB) Blocks Added = %I64u (new = %I64u)\n"), TotalBytesProcessed, (UINT32)(TotalBytesProcessed >> 30LL), TotalBlocksAdded, TotalBlocksNew);
	VirtualFree(pCompressedBuffer, 0, MEM_RELEASE);
	VirtualFree(pUncompressedBuffer, 0, MEM_RELEASE);
	}
#pragma managed(pop)



     
   
 
 
 
             
    
 
     

