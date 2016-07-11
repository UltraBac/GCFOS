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

#include "OpenStackRepository.h"

// These overrides fix a bug in the openstack.net implementation (when used with Internap for example)
ref class CloudFilesProviderWithContentType : net::openstack::Providers::Rackspace::CloudFilesProvider
{
public:
	CloudFilesProviderWithContentType(net::openstack::Core::Domain::CloudIdentity ^defaultIdentity,
									  System::String ^defaultRegion,
									  net::openstack::Core::Providers::IIdentityProvider^ identityProvider,
									  JSIStudios::SimpleRESTServices::Client::IRestService ^restService
									  ) : net::openstack::Providers::Rackspace::CloudFilesProvider(defaultIdentity, defaultRegion, identityProvider, restService)
    {
    }

protected:
	virtual JSIStudios::SimpleRESTServices::Client::RequestSettings^ BuildDefaultRequestSettings(System::Collections::Generic::IEnumerable<System::Net::HttpStatusCode>^ non200SuccessCodes) override
    {
        JSIStudios::SimpleRESTServices::Client::RequestSettings^ settings = net::openstack::Providers::Rackspace::CloudFilesProvider::BuildDefaultRequestSettings(non200SuccessCodes);
        settings->AllowZeroContentLength = true;
        return settings;
    }
};

OpenStackRepository::~OpenStackRepository()
	{
	delete m_Files;
	delete m_Identity;
	delete m_IdentityProvider;
	delete m_User;
	}

bool OpenStackRepository::CreateContainer(System::String ^BucketName)
	{
	net::openstack::Core::Domain::ObjectStore createContainerResponse;

	try {
		createContainerResponse = m_Files->CreateContainer(BucketName, nullptr, nullptr, false, m_Identity);
		if(createContainerResponse == net::openstack::Core::Domain::ObjectStore::ContainerCreated)
			{
			DEBUGLOG_L(2, ("OpenStackRepository::Initialize container %s CREATED\n", (LPCSTR)CStringA(static_cast<System::String^>(BucketName))));
			}
		if(createContainerResponse == net::openstack::Core::Domain::ObjectStore::ContainerExists)
			{
			DEBUGLOG_L(2, ("OpenStackRepository::Initialize found container %s\n", (LPCSTR)CStringA(static_cast<System::String^>(BucketName))));
			}
		}
	catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize exception creating container %s : %s\n", (LPCSTR)CStringA(static_cast<System::String^>(BucketName)), (LPCSTR)CStringA(e->Message)));
		return false;
		}
	return true;
	}

bool OpenStackRepository::Initialize(LPCTSTR pszBucket, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region)
	{
	Repository::Initialize(pszBucket, AccessKey, SecretKey, EndPoint, Region); // call base class
	System::String ^s_AccessKey = gcnew System::String(AccessKey);
	System::String ^s_SecretKey = gcnew System::String(SecretKey);

	m_Identity = gcnew net::openstack::Core::Domain::CloudIdentityWithProject();
	System::String		^delimiter = gcnew System::String(":");
	array<System::Char>^ delimiter_array = delimiter->ToCharArray();
	array<System::String ^>^ components;

	System::Uri ^URI = gcnew System::Uri(m_EndPoint);

	DEBUGLOG_L(2, ("OpenStackRepository::Initialize - bucket: %S Region: %S Endpoint: %S\n", pszBucket, Region, EndPoint));
	components = s_AccessKey->Split(delimiter_array);
	if(components->Length < 2)
		{
		m_IdentityProvider = gcnew net::openstack::Providers::Rackspace::CloudIdentityProvider();
		m_Identity->Username = gcnew System::String(AccessKey);
		m_Identity->APIKey = s_SecretKey;
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize - not using [user]:[tenant] format, assuming RackSpace\n"));
		}
	else
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize - using [user]:[tenant/project] format\n"));
		m_Identity->ProjectName = components[0];
		m_Identity->Username = components[1];
		m_Identity->Password = s_SecretKey;
		m_IdentityProvider = gcnew net::openstack::Providers::Hp::HpIdentityProvider(URI, m_Identity);
		}	

	try {
		m_User = m_IdentityProvider->Authenticate(m_Identity);
		}
	catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize exception %s\n", (LPCSTR)CStringA(e->Message)));
		return false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize general exception\n"));
		return false;
		}

	try {
		m_Files = gcnew net::openstack::Providers::Rackspace::CloudFilesProvider(m_Identity, m_Region, m_IdentityProvider, nullptr);
		}
	catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize CloudFilesProvider exception %s\n", (LPCSTR)CStringA(e->Message)));
		return false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Initialize CloudFilesProvider general exception\n"));
		return false;
		}

	if(!CreateContainer(m_Bucket))
		return false;

	return true;
	}

bool OpenStackRepository::GetObject(System::String ^Key, System::IO::Stream ^%Stream, bool bAutoRetry /*=true*/, System::String ^force_bucket)
	{
	Stream= gcnew System::IO::MemoryStream(0x8000);
	try
		{
		m_Files->GetObject((force_bucket == nullptr ? m_Bucket : force_bucket), Key, Stream, 0x8000, nullptr, m_Region, false, nullptr, false, m_Identity);
		Stream->Position = 0;
		}
	catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
		{
		if(!bAutoRetry)
			{
			DEBUGLOG_L(2, ("OpenStackRepository::GetObject for %s exception %s\n", (LPCSTR)CStringA(Key), (LPCSTR)CStringA(e->Message)));
			}
		delete Stream;
		Stream = nullptr;
		return false;
		}

	return true;
	}

bool OpenStackRepository::DeleteObjects(System::String ^Key, bool bFile)
	{
	System::String			^Marker = nullptr;
	bool					bFound;

	System::Collections::Generic::IEnumerable<net::openstack::Core::Domain::ContainerObject^> ^objectList;

	while(true)
		{
		bFound = false;
		try
			{
			objectList = m_Files->ListObjects(m_Bucket, 1000, Marker, nullptr, Key, nullptr, false, m_Identity);
			}
		catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
			{
			DEBUGLOG_L(2, ("OpenStackRepository::GetList exception %s for %s", (LPCSTR)CStringA(e->Message), (LPCSTR)CStringA(Key)));
			return false;
			}
		for each(net::openstack::Core::Domain::ContainerObject ^object in objectList)
			{
			bFound = true;
			try
				{
				m_Files->DeleteObject(m_Bucket, object->Name, nullptr, true, nullptr, false, m_Identity);
				}
			catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
				{
				DEBUGLOG_L(2, ("OpenStackRepository::DeleteObjects exception %s for %s", (LPCSTR)CStringA(e->Message), (LPCSTR)CStringA(object->Name)));
				return false;
				}
			}
		if(!bFound)
			break;
		}
	return true;
	}

bool OpenStackRepository::Put(System::String ^Key, System::IO::Stream ^stream, System::String ^force_bucket)
	{
	bool retval = true;
	try
		{
		m_Files->CreateObject((force_bucket == nullptr ? m_Bucket : force_bucket), stream, Key, nullptr, 0x8000, nullptr, nullptr, nullptr, false, m_Identity);
		if(stream->CanRead)
			{
			stream->Close();
			}
		}
	catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
		{
		DEBUGLOG_L(2, ("OpenStackRepository::Put exception for %s : %s", (LPCSTR)CStringA(Key), (LPCSTR)CStringA(e->Message)));
		return false;
		}
	return retval;
	}


bool OpenStackRepository::GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, System::String ^force_bucket)
	{
	System::String			^Marker = nullptr;
	bool					bFound;

	System::Collections::Generic::IEnumerable<net::openstack::Core::Domain::ContainerObject^> ^objectList;

	while(true)
		{
		bFound = false;
		try
			{
			objectList = m_Files->ListObjects(force_bucket == nullptr ? m_Bucket : force_bucket, 1000, Marker, nullptr, Key, nullptr, false, m_Identity);
			}
		catch(net::openstack::Core::Exceptions::Response::ResponseException ^e)
			{
			DEBUGLOG_L(2, ("OpenStackRepository::GetList exception %s for %s", (LPCSTR)CStringA(e->Message), (LPCSTR)CStringA(Key)));
			return false;
			}
		for each(net::openstack::Core::Domain::ContainerObject ^object in objectList)
			{
			names->Add(object->Name);
			sizes->Add((UINT32)object->Bytes);
			Marker = object->Name;
			bFound = true;
			}
		if(!bFound)
			break;
		}
	delete objectList;

	return true;
	}