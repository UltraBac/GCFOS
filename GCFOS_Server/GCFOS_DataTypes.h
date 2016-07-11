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
#pragma managed(push, off)

typedef struct GCFOS_RESIDENT_ENTRY {
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;

	bool operator< ( const GCFOS_RESIDENT_ENTRY &comp) const
		{
		int rtn;

		rtn = memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN);
		if(rtn == 0)
			{
			rtn = size - comp.size;
			}
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_RESIDENT_ENTRY &comp) const
		{
		if(memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN) == 0
		&& size == comp.size)
			return true;
		else
			return false;
		}

	friend std::istream& operator>> (std::istream& in, GCFOS_RESIDENT_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_RESIDENT_ENTRY& entry);

	} *PGCFOS_RESIDENT_ENTRY;

typedef struct GCFOS_LIMBO_ENTRY {
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;
	GCFOS_CLIENTID	client;
	mutable GCFOS_UsefulTime whenAdded;

	bool operator< ( const GCFOS_LIMBO_ENTRY &comp) const
		{
		int rtn;

		rtn = memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN);
		if(rtn == 0)
			{
			rtn = size - comp.size;
			if(rtn == 0)
				{
				rtn = client - comp.client;
				}
			}
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_LIMBO_ENTRY &comp) const
		{
		if(memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN) == 0
		&& size == comp.size
		&& client == comp.client)
			return true;
		else
			return false;
		}

	friend std::istream& operator>> (std::istream& in, GCFOS_LIMBO_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_LIMBO_ENTRY& entry);

	} *PGCFOS_LIMBO_ENTRY;

typedef struct GCFOS_LIMBO_2_ENTRY {
	UINT32			client;
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;
	mutable GCFOS_UsefulTime whenAdded;

	bool operator< ( const GCFOS_LIMBO_ENTRY &comp) const
		{
		int rtn;

		rtn = client - comp.client;
		if(rtn == 0)
			{
			rtn = memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN);
			if(rtn == 0)
				{
				rtn = size - comp.size;
				}
			}
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_LIMBO_ENTRY &comp) const
		{
		if(memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN) == 0
		&& size == comp.size
		&& client == comp.client)
			return true;
		else
			return false;
		}
	} *PGCFOS_LIMBO_2_ENTRY;

typedef struct GCFOS_WANTED_ENTRY {
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;

	bool operator< ( const GCFOS_WANTED_ENTRY &comp) const
		{
		int rtn;

		rtn = memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN);
		if(rtn == 0)
			{
			rtn = size - comp.size;
			}
		if(rtn < 0)
			return true;
		else
			return false;
		}

	bool operator== ( const GCFOS_WANTED_ENTRY &comp) const
		{
		if(memcmp(&SHA1, &comp.SHA1, GCFOS_SHA1_LEN) == 0
		&& size == comp.size)
			return true;
		else
			return false;
		}

	friend std::istream& operator>> (std::istream& in, GCFOS_WANTED_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_WANTED_ENTRY& entry);

	} *PGCFOS_WANTED_ENTRY;

typedef struct GCFOS_UPDATE_ENTRY {
	UINT32			rec;
	Ipp8u			SHA1[GCFOS_SHA1_LEN];
	UINT32			size;

	friend std::istream& operator>> (std::istream& in, GCFOS_UPDATE_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_UPDATE_ENTRY& entry);
} *PGCFOS_UPDATE_ENTRY;

typedef struct GCFOS_CLIENT_ENTRY {
	UINT32			clientid;
	// follows data: (do not change "sharedkey" as start without modifying Clientdb_2_Callback()
	Ipp8u			sharedkey[32];
	UINT32			lcud_seq;
	TCHAR			szName[GCFOS_COMPUTER_NAME_LENGTH]; // computer name of client (used on "local" GCFOS installs)
	Ipp8u			future_expansion[284]; // must be last field

	friend std::istream& operator>> (std::istream& in, GCFOS_CLIENT_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_CLIENT_ENTRY& entry);

	} *PGCFOS_CLIENT_ENTRY;

typedef struct GCFOS_CLIENT_2_ENTRY {
	TCHAR			szName[GCFOS_COMPUTER_NAME_LENGTH]; // The FQ DNS name of the host that registered this client
	UINT32			clientid;

	bool operator< ( const GCFOS_CLIENT_2_ENTRY &comp) const
		{
		return (_tcsnicmp(szName, comp.szName, GCFOS_COMPUTER_NAME_LENGTH) < 0);
		}

	bool operator== ( const GCFOS_CLIENT_2_ENTRY &comp) const
		{
		return (0 == _tcsnicmp(szName, comp.szName, GCFOS_COMPUTER_NAME_LENGTH));
		}
	} *PGCFOS_CLIENT_2_ENTRY;

typedef struct GCFOS_BANNED_ENTRY {
	CHAR				ip_address[GCFOS_MAX_IP_ADDR_LEN];
	GCFOS_UsefulTime	time_banned;
	} *PGCFOS_BANNED_ENTRY;

typedef struct GCFOS_BLOCK_ENTRY {
	Ipp8u				hash[GCFOS_BLOCK_HASH_LEN];
	mutable UINT32		fileno;
	mutable UINT32		offset;
	mutable UINT16		last_ref;

	bool operator< ( const GCFOS_BLOCK_ENTRY &comp) const
		{
		return (memcmp(hash, comp.hash, GCFOS_BLOCK_HASH_LEN) < 0);
		}

	bool operator== ( const GCFOS_BLOCK_ENTRY &comp) const
		{
		return (0 == memcmp(hash, comp.hash, GCFOS_BLOCK_HASH_LEN));
		}

	friend std::istream& operator>> (std::istream& in, GCFOS_BLOCK_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_BLOCK_ENTRY& entry);

	} *PGCFOS_BLOCK_ENTRY;

typedef enum { STILL_CONNECTED, NORMAL, TIMEOUT, FORCED, SWITCH_CONTEXT } GCFOS_SESSION_END_REASON;

typedef struct GCFOS_SESSION_ENTRY {
	UINT32				recno;
	GCFOS_UsefulTime	start;//FIRST -- see db creation call if this field needs to be moved
	GCFOS_UsefulTime	end;
	UINT32				clientid;
	GCFOS_SESSION_END_REASON end_reason;
	UINT32				donations;
	UINT32				queries;
	UINT32				resident_hits;
	UINT32				limbo_results;
	SOCKADDR			connectedTo;
	UINT32				retrieve_MB;
	UINT32				retrieves;
	UINT64				blks_queried;
	UINT64				blks_stored;
	UINT64				blks_retrieved;
	BYTE				future_expansion[0x30];// must be last field

	GCFOS_SESSION_ENTRY() {
		end = GCFOS_UsefulTime(0);
		end_reason = STILL_CONNECTED;
		donations = 0;
		queries = 0;
		resident_hits = 0;
		limbo_results = 0;
		retrieves = 0;
		retrieve_MB = 0;
		blks_queried = 0;
		blks_stored = 0;
		blks_retrieved = 0;
		memset(&future_expansion, 0, sizeof(future_expansion));
		}
	friend std::istream& operator>> (std::istream& in, GCFOS_SESSION_ENTRY& entry);
	friend std::ostream& operator<< (std::ostream& out, const GCFOS_SESSION_ENTRY& entry);
	} *PGCFOS_SESSIONS_ENTRY;

#pragma managed(pop)
