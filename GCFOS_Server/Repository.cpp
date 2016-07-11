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
#include <Project.h>

#include "Repository.h"

bool Repository::Initialize(LPCTSTR Bucket, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region)
	{
	m_Bucket = gcnew System::String(Bucket);
	m_Region = gcnew System::String(Region);
	m_EndPoint = gcnew System::String(EndPoint);
	return true;
	}

bool Repository::GetObject(System::String ^key, System::IO::Stream ^%Stream, Repository* SecondaryRepo/* = NULL*/, bool bAutoRetry/* = true*/, System::String ^force_bucket/* = nullptr*/)
	{
	if(!this->GetObject(key, Stream, bAutoRetry, force_bucket))
		{
		if(SecondaryRepo != NULL)
			{
			return SecondaryRepo->GetObject(key, Stream, bAutoRetry, force_bucket);
			}
		return false;
		}

	return true;
	}

bool Repository::DeleteObjects(System::String ^Key, Repository* SecondaryRepo, bool bFile/* = false*/)
	{
	if(this->DeleteObjects(Key, bFile))
		{
		if(SecondaryRepo != NULL)
			{
			return SecondaryRepo->DeleteObjects(Key, bFile);
			}
		return true;
		}

	return false;
	}
	
bool Repository::Put(System::String ^Key, System::IO::Stream ^Stream, Repository* SecondaryRepo, System::String ^force_bucket/*= nullptr*/)
	{
	if(SecondaryRepo != NULL)
		{
		System::IO::MemoryStream ^ms = gcnew System::IO::MemoryStream((int)Stream->Length);
		Stream->CopyTo(ms);
		Stream->Position = 0; // make sure we're at the beginning of the stream
		ms->Position = 0;
		if(!SecondaryRepo->Put(Key, ms, force_bucket))
			return false;
		}
	return this->Put(Key, Stream, force_bucket);
	}

bool Repository::GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, Repository* SecondaryRepo, System::String ^force_bucket)
	{
	if(!GetList(Key, names, sizes, force_bucket))
		{
		if(SecondaryRepo != NULL)
			{
			return SecondaryRepo->GetList(Key, names, sizes, force_bucket);
			}
		return false;
		}

	return true;
	}

