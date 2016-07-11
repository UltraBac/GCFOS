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

#include <stdafx.h>
#include <Project.h>

#include "FileRepository.h"

FileRepository::~FileRepository()
	{
	}

System::String^ FileRepository::NormalizeKey(System::String ^key)
	{
	// remove forward slashes (incompatible with filesystem) and replace with backslashes
	return key->Replace("/", "\\");
	}

bool FileRepository::CreateContainer(System::String ^BucketName)
	{
	try {
		System::IO::Directory::CreateDirectory(BucketName);
		}
	catch(...)
		{
		return false;
		}
	return true;
	}

bool FileRepository::Initialize(LPCTSTR pszLocation, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region)
	{
	Repository::Initialize(pszLocation, AccessKey, SecretKey, EndPoint, Region);

	return CreateContainer(m_Bucket);
	}

bool FileRepository::GetObject(System::String ^Key, System::IO::Stream ^%Stream, bool bAutoRetry/*= true*/, System::String ^force_bucket/* = nullptr*/)
	{
	System::String ^filename;

	if(force_bucket == nullptr)
		filename = m_Bucket;
	else
		filename = force_bucket;
	filename += "\\";
	filename += Key;
	filename = NormalizeKey(filename);

	try {
		Stream = gcnew System::IO::FileStream(filename, System::IO::FileMode::Open);
		}
	catch(...)
		{
		if(!bAutoRetry)
			{
			DEBUGLOG_L(2, ("Exception during FileRepository::GetObject %s\n", (LPCSTR)CStringA(filename)));
			}
		return false;
		}

	return true;
	}

bool FileRepository::DeleteObjects(System::String ^Key, bool bFile)
	{
	System::String ^filename = m_Bucket;
	filename += "\\";
	filename += Key;
	filename = NormalizeKey(filename);
	if(bFile)
		{
		// this is an individual object within a directory (used by UpdateFileStore)
		try {
			System::IO::File::Delete(filename);
			return true;
			}
		catch(...)
			{
			DEBUGLOG_L(2, ("FileRepository::DeleteObjects exception for %s\n", (LPCSTR)CStringA(filename)));
			return false;
			}
		}

	try {
		System::IO::Directory::Delete(filename, true);
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("FileRepository::DeleteObjects exception for %s\n", (LPCSTR)CStringA(filename)));
		return false;
		}

	return true;
	}

bool FileRepository::Put(System::String ^Key, System::IO::Stream ^Stream, System::String ^force_bucket)
	{
	bool retval = true;
	System::IO::FileStream ^fs;

	System::String ^filename;

	if(force_bucket == nullptr)
		filename = m_Bucket;
	else
		filename = force_bucket;
	filename += "\\";
	filename += Key;
	filename = NormalizeKey(filename);

	try {
		// First make sure directory exists
		System::IO::Directory::CreateDirectory(System::IO::Path::GetDirectoryName(filename));
		fs = gcnew System::IO::FileStream(filename, System::IO::FileMode::Create);
		Stream->CopyTo(fs);
		fs->Close();
		Stream->Close();
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("FileRepository::Put - failed to put object %s\n", (LPCSTR)CStringA(filename)));
		retval = false;
		}
	return retval;
	}

bool FileRepository::GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, System::String ^force_bucket)
	{
	bool retval = true;
	UINT ignorepart;
	System::String ^searchpath = force_bucket == nullptr ? m_Bucket : force_bucket;

	searchpath += "\\";
	ignorepart = searchpath->Length;
	searchpath += Key;
	searchpath = NormalizeKey(searchpath);

	names->Clear();
	sizes->Clear();

	try {
		System::IO::FileInfo ^info = gcnew System::IO::FileInfo(searchpath);
		// no exception -- this must be a single file request
		if((info->Attributes & System::IO::FileAttributes::Directory) != System::IO::FileAttributes::Directory)
			{
			names->Add(searchpath->Substring(ignorepart));
			sizes->Add((UINT32)info->Length);
			return true;
			}
		}
	catch(...)
		{
		//exception thrown if file does not exist (ie it's a directory)
		}

	if(Key->Length == 0)
		{
		// this is a top-level directory enumeration (Migrator)
		array<System::IO::DirectoryInfo ^> ^dirs;

		try {
			System::IO::DirectoryInfo ^di = gcnew System::IO::DirectoryInfo(searchpath);
			dirs = di->GetDirectories(gcnew System::String("*"), System::IO::SearchOption::TopDirectoryOnly);
			for each(System::IO::DirectoryInfo ^d in dirs)
				{
				names->Add(d->FullName->Substring(ignorepart));
				sizes->Add((UINT32)0);
				}
			}
		catch(...)
			{
			DEBUGLOG_L(1, ("FileRepository::GetList exception for %s\n", (LPCSTR)CStringA(searchpath)));
			retval = false;
			}

		}
	else
		{
		array<System::IO::FileInfo ^> ^files;

		try {
			System::IO::DirectoryInfo ^di = gcnew System::IO::DirectoryInfo(searchpath);
			files = di->GetFiles(gcnew System::String("*"), System::IO::SearchOption::TopDirectoryOnly);
			for each(System::IO::FileInfo ^f in files)
				{
				names->Add(f->FullName->Substring(ignorepart)->Replace("\\", "/"));
				sizes->Add((UINT32)f->Length);
				}
			}
		catch(...)
			{
			DEBUGLOG_L(5, ("FileRepository::GetList exception for %s\n", (LPCSTR)CStringA(searchpath)));
			retval = false;
			}
		}
	return retval;
	}