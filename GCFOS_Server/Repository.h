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

#pragma once
class Repository {
public:
	virtual ~Repository() {};
	virtual bool			Initialize(LPCTSTR pszLocation, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region);
	virtual bool			GetObject(System::String ^key, System::IO::Stream ^%Stream, bool bAutoRetry, System::String ^force_bucket) = 0;
	virtual bool			DeleteObjects(System::String ^Key, bool bFile) = 0;
	virtual bool			Put(System::String ^Key, System::IO::Stream ^Stream, System::String ^force_bucket) = 0;
	virtual bool			GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, System::String ^force_bucket) = 0;
	virtual bool			CreateContainer(System::String ^BucketName) = 0;

	bool					GetObject(System::String ^key, System::IO::Stream ^%Stream, Repository* SecondaryRepo = NULL, bool bAutoRetry = true, System::String ^force_bucket = nullptr);
	bool					DeleteObjects(System::String ^Key, Repository* SecondaryRepo, bool bFile = false);
	bool					Put(System::String ^Key, System::IO::Stream ^Stream, Repository* SecondaryRepo, System::String ^force_bucket = nullptr);
	bool					GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, Repository* SecondaryRepo, System::String ^force_bucket = nullptr);

	void					SetRegion(System::String ^Region) { m_Region = Region; }
protected:
	gcroot<System::String ^>			m_Bucket;
	gcroot<System::String ^>			m_Region;
	gcroot<System::String ^>			m_EndPoint;
	};