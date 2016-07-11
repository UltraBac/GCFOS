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


AzureRepository::~AzureRepository()
	{
	delete m_StorageAccount;
	delete m_Credentials;
	delete m_Container;
	}

bool AzureRepository::CreateContainer(System::String ^BucketName)
	{
	bool				bRtn = true;

	try	{
		m_Container = m_BlobAccount->GetContainerReference(BucketName);
		m_Container->CreateIfNotExists(Microsoft::WindowsAzure::Storage::Blob::BlobContainerPublicAccessType::Off, nullptr, nullptr);
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::CreateContainer exception: %s", CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::CreateContainer exception: general"));
		bRtn = false;
		}
	return bRtn;
	}

bool AzureRepository::Initialize(LPCTSTR pszBucket, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region)
	{
	bool				bRtn = true;

	Repository::Initialize(pszBucket, AccessKey, SecretKey, EndPoint, Region); // call base class

	try	{
		m_Credentials = gcnew Microsoft::WindowsAzure::Storage::Auth::StorageCredentials(gcnew System::String(AccessKey), gcnew System::String(SecretKey));

		m_StorageAccount = gcnew Microsoft::WindowsAzure::Storage::CloudStorageAccount(m_Credentials, false);

		m_BlobAccount = m_StorageAccount->CreateCloudBlobClient();
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::Initialize exception: %s", CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::Initialize exception: general"));
		bRtn = false;
		}

	bRtn = CreateContainer(m_Bucket);

	return bRtn;
	}

bool AzureRepository::GetObject(System::String ^Key, System::IO::Stream ^%Stream, bool bAutoRetry /*=true*/, System::String ^force_bucket /*= nullptr*/)
	{
	bool		bRtn = true;

	Microsoft::WindowsAzure::Storage::Blob::CloudBlockBlob ^blob; 
	try
		{
		blob = m_Container->GetBlockBlobReference(Key);
		// GetBlockBlobReference doesn't get the attributes of the file, force that now with Exists()
		if(!blob->Exists(nullptr, nullptr))
			{
			return false;
			}
		int streamlen = (int)blob->Properties->Length;
		Stream = gcnew System::IO::MemoryStream(streamlen);

		blob->DownloadToStream(Stream, nullptr, nullptr, nullptr);
		Stream->Position = 0;
		delete blob;
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::Get %s exception: %s", CStringA(Key), CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::Get %s general exception", CStringA(Key)));
		bRtn = false;
		}
	return bRtn;
	}

bool AzureRepository::DeleteObjects(System::String ^Key, bool bFile)
	{
	bool				bRtn = true;

	Microsoft::WindowsAzure::Storage::Blob::CloudBlockBlob ^blob; 
	try
		{
		blob = m_Container->GetBlockBlobReference(Key);

		auto bloblist = m_Container->ListBlobs(Key, true,  Microsoft::WindowsAzure::Storage::Blob::BlobListingDetails::None, nullptr, nullptr);
		for each(Microsoft::WindowsAzure::Storage::Blob::CloudBlockBlob ^b in bloblist)
			{
			b->Delete(Microsoft::WindowsAzure::Storage::Blob::DeleteSnapshotsOption::None, nullptr, nullptr, nullptr);
			}
		blob->DeleteIfExists(Microsoft::WindowsAzure::Storage::Blob::DeleteSnapshotsOption::None, nullptr, nullptr, nullptr);
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::DeleteObjects %s exception: %s", CStringA(Key), CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::DeleteObjects %s general exception", CStringA(Key)));
		bRtn = false;
		}

	return bRtn;
	}

bool AzureRepository::Put(System::String ^Key, System::IO::Stream ^stream, System::String ^force_bucket)
	{
	bool		bRtn = true;

	Microsoft::WindowsAzure::Storage::Blob::CloudBlockBlob ^blob; 
	try
		{
		blob = m_Container->GetBlockBlobReference(Key);

		blob->UploadFromStream(stream, nullptr, nullptr, nullptr);
		delete blob;
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::Put %s exception: %s", CStringA(Key), CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::Put %s general exception", CStringA(Key)));
		bRtn = false;
		}
	return bRtn;
	}


bool AzureRepository::GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, System::String ^AlternateBucket/* = nullptr*/)
	{
	bool				bRtn = true;

	names->Clear();
	sizes->Clear();

	try {
		auto bloblist = m_Container->ListBlobs(Key, true,  Microsoft::WindowsAzure::Storage::Blob::BlobListingDetails::Metadata, nullptr, nullptr);

		for each(Microsoft::WindowsAzure::Storage::Blob::CloudBlockBlob ^blob in bloblist)
			{
			names->Add(blob->Name);
			sizes->Add((System::UInt32)blob->Properties->Length);
			}
		}
	catch(Microsoft::WindowsAzure::Storage::StorageException ^e)
		{
		DEBUGLOG_L(2, ("AzureRepository::GetList %s exception: %s", CStringA(Key), CStringA(e->Message)));
		bRtn = false;
		}
	catch(...)
		{
		DEBUGLOG_L(2, ("AzureRepository::GetList %s exception: %s", CStringA(Key)));
		bRtn = false;
		}
	return bRtn;
	}