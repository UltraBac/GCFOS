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
public ref class GCFOS_Client_Managed
	{

public:
	property System::String ^LastError {
		System::String^ get() { return m_LastError; }
		private: void set(System::String ^err) { m_LastError = err; } 
		}

	property bool LocalBlockCacheEnabled {
		bool get() { return m_LocalBlockCacheEnabled; }
		private: void set(bool val) { m_LocalBlockCacheEnabled = val; }
		}
	property bool BlockStoreEnabled {
		bool get() { return m_BlockStoreEnabled; }
		private: void set(bool val) { m_BlockStoreEnabled = val; }
		}
	property bool FileStoreEnabled {
		bool get() { return m_FileStoreEnabled; }
		private: void set(bool val) { m_FileStoreEnabled = val; }
		}
	property bool Connected {
		bool get() { return m_Connected; }
		private: void set(bool val) { m_Connected = val; }
		}

	property UINT32 BlockSize {
		UINT32 get() { return GCFOS_BLOCK_SIZE; }
		}

	property UINT32 FileHashSize {
		UINT32 get() { return GCFOS_SHA1_LEN; }
		}

	property UINT32 BlockHashSize {
		UINT32 get() { return GCFOS_BLOCK_HASH_LEN; }
		}

	property UINT32 BlocksPerQuery {
		UINT32 get() { return GCFOS_BLOCKS_PER_QUERY; }
		}
	
	GCFOS_Client_Managed();
	~GCFOS_Client_Managed();

	void			SetLastError(GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE Response);
	void			ClearLastError() { LastError = ""; }
	bool			Connect(System::String ^cachePath, System::String ^CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache);
	bool			Connect(System::String ^cachePath, System::String ^CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache, System::String ^Server, GCFOS_CLIENTID ClientId, array<const System::Byte> ^Secret);
	GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE Query(array<const System::Byte> ^hash, System::UInt32);
	void			Close();
	GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE Auth();
	bool			ContributeFile(System::String ^filename, array<const System::Byte> ^SHA1, System::UInt32 size, System::Byte flags);
	bool			ContributeFileByHandle(Microsoft::Win32::SafeHandles::SafeFileHandle ^filehandle, array<const System::Byte> ^SHA1, System::UInt32 size, System::String ^filename, System::Byte flags); // Filename is used only for logging to server
	bool			GetHash(System::String ^filename, System::String ^filepathForOpen, array<System::Byte> ^SHA1, System::DateTime ^dt, System::UInt32 ^filesize, array<System::Byte> ^ValidationKey);
	bool			GetHash(System::String ^filename, System::String ^filepathForOpen, array<System::Byte> ^SHA1, array<System::Byte> ^ValidationKey);
	bool			GetHashForHandle(System::String ^filename, Microsoft::Win32::SafeHandles::SafeFileHandle ^filehandle, array<System::Byte> ^SHA1, System::DateTime ^dt, System::UInt32 ^filesize, array<System::Byte> ^ValidationKey);
	bool			RetrieveWholeFile(array<const System::Byte> ^SHA1, System::UInt32 size, System::String ^filename, array<System::Byte> ^ValidationKey);
	GCFOS_MANAGED_CLIENT::GCFOS_CLIENT_SESSIONINFO^ GetSessionInfo();
	System::UInt32	GetClientID();
	bool			EraseLocalCache(System::String ^CachePath, System::String ^CompanyName, GCFOS_MANAGED_CLIENT::GCFOS_LOCAL_ERASE_TYPE type);
	bool			StoreBlocks(array<const System::Byte> ^BlockData, array<System::Byte> ^ References, System::UInt32 %outsize);	
	bool			RetrieveBlocks(array<const System::Byte> ^Hashes, System::UInt16 %Count, array<System::Byte> ^Blocks);
	array<System::Byte> ^ SendBlocksInFile(System::IO::FileInfo ^inputfile, System::Int64 %filesize);
	bool			BuildFileFromHashes(array<const System::Byte> ^hashes, System::IO::FileInfo ^outputfile, System::Int64 const filesize);
	GCFOS_MANAGED_CLIENT::GCFOS_SRV_RESPONSE DeleteObject(array<const System::Byte> ^hash, System::UInt32 size, System::Byte flags);

private:
	GCFOS_Client	*g;
	System::String	^m_LastError;
	bool			m_LocalBlockCacheEnabled;
	bool			m_BlockStoreEnabled;
	bool			m_FileStoreEnabled;
	bool			m_Connected;
	};
