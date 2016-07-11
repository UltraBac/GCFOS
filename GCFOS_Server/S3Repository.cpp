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

#include "S3Repository.h"

S3Repository::~S3Repository()
	{
	delete s3;
	delete s3_config;
	}

bool S3Repository::CreateContainer(System::String ^BucketName)
	{
	Amazon::S3::Model::PutBucketRequest ^putBucketRequest;
	putBucketRequest = gcnew Amazon::S3::Model::PutBucketRequest();
	putBucketRequest->UseClientRegion = true;
	putBucketRequest->BucketName = BucketName;
//	putBucketRequest->BucketRegion = myregion;
	try {
		s3->PutBucket(putBucketRequest);
		DEBUGLOG_L(1, ("S3 Bucket: %s created successfully\n", (LPCSTR)CStringA(putBucketRequest->BucketName)));
		return true;
		}
	catch(Amazon::S3::AmazonS3Exception ^s3Exception)
		{
		if(!s3Exception->ErrorCode->Equals("BucketAlreadyOwnedByYou"))
			{
			DEBUGLOG_L(1, ("Error creating S3 bucket: %s\n", (LPCSTR)CStringA(s3Exception->Message)));
			return false;
			}
		}
	return true;
	}

bool S3Repository::Initialize(LPCTSTR pszBucket, LPCTSTR AccessKey, LPCTSTR SecretKey, LPCTSTR EndPoint, LPCTSTR Region)
	{
	bool bFoundOurBucket;
	Repository::Initialize(pszBucket, AccessKey, SecretKey, EndPoint, Region); // call base class
	
	//NameValueCollection appSettings = ConfigurationManager.AppSettings;
	// Credentials are stored in app.config (build process copies file to binary directory as *GCFOS_Server.exe.app.config"

	s3_config = gcnew Amazon::S3::AmazonS3Config;
	s3_config->ServiceURL = m_EndPoint; //s3-us-west-2.amazonaws.com
//	s3_config->UseHttp = true;
//	s3_config->ProxyHost = System::String::Empty;
//	s3_config->CommunicationProtocol = 0;
//	s3_config->RegionEndpoint = Amazon::RegionEndpoint::USWest2;
//	s3_config->AuthenticationRegion = myregion;
	s3_config->ForcePathStyle = true;

	// credentials can be stored at System::Configuration::ConfigurationManager::AppSettings["AWSAccessKey"]
	System::String ^AWS_AccessKey = gcnew System::String(AccessKey);
	System::String ^AWS_SecretKey = gcnew System::String(SecretKey);

	DEBUGLOG_L(1, ("Using Amazon-S3 credential: %S\n", AccessKey));
	bFoundOurBucket = false;
	try {
		s3 = gcnew Amazon::S3::AmazonS3Client(AWS_AccessKey, AWS_SecretKey, s3_config);
		}
	catch(Amazon::S3::AmazonS3Exception ^s3Exception)
		{
		DEBUGLOG_L(1, ("Error creating S3 client: %s\n", (LPCSTR)CStringA(s3Exception->Message)));
		return false;
		}
	catch(...)
		{
		DEBUGLOG_L(1, ("Exception creating S3 client\n"));
		return false;
		}

	CreateContainer(m_Bucket);

	try {
		Amazon::S3::Model::ListBucketsResponse ^response = s3->ListBuckets();
		for each(Amazon::S3::Model::S3Bucket ^bucketlist in response->Buckets)
			{
			DEBUGLOG_L(2, ("Discovered bucket: %s\n", (LPCSTR)CStringA(bucketlist->BucketName)));
			if(bucketlist->BucketName->Equals(m_Bucket))
				{
				bFoundOurBucket = true;
				}
			}
		}
	catch(Amazon::S3::AmazonS3Exception ^s3Exception)
		{
		DEBUGLOG_L(1, ("Failed to enumerate buckets: %s\n", (LPCSTR)CStringA(s3Exception->Message)));
		return false;
		}
	catch(...)
		{
		DEBUGLOG_L(1, ("Exception occurred attempting to access S3\n"));
		return false;
		}

	if(bFoundOurBucket == false)
		{
		// This style of nasty casting is required when accessing gcroot-style strings
		DEBUGLOG_L(2, ("Unable to find %s bucket --please create it\n", (LPCSTR)CStringA(static_cast<System::String^>(m_Bucket))));
		return false;
		}

	return true;
	}

bool S3Repository::GetObject(System::String ^Key, System::IO::Stream ^%Stream, bool bAutoRetry /*=true*/, System::String ^force_bucket /*= nullptr*/)
	{
	Amazon::S3::Model::GetObjectResponse	^getResponse;
	Amazon::S3::Model::GetObjectRequest		^getRequest;

	for(int retry = 0; retry < 5; retry++)
		{
		getRequest = gcnew Amazon::S3::Model::GetObjectRequest();
		if(force_bucket == nullptr)
			getRequest->BucketName = m_Bucket;
		else
			getRequest->BucketName = force_bucket;

		getRequest->Key = Key;

		try {
			getResponse = s3->GetObject(getRequest);
			Stream = getResponse->ResponseStream;
			return true;
			}
		catch(Amazon::S3::AmazonS3Exception ^s3Exception)
			{
			if(bAutoRetry)
				{
				DEBUGLOG_L(3, ("S3 Exception (%s : %s) during GetObjectRequest for %s\n", (LPCSTR)CStringA(s3Exception->Message), (LPCSTR)CStringA(s3Exception->ErrorCode), (LPCSTR)CStringA(Key)));
				continue;
				}
			break;
			}
		catch(...)
			{
			if(bAutoRetry)
				{
				DEBUGLOG_L(3, ("Exception during GetObjectRequest for %s\n", (LPCSTR)CStringA(Key)));
				continue;
				}
			break;
			}
		}
	return false;
	}

bool S3Repository::DeleteObjects(System::String ^Key, bool bFile)
	{
	Amazon::S3::Model::DeleteObjectRequest		^DeleteRequest;
	Amazon::S3::Model::ListObjectsResponse		^listResponse;
	Amazon::S3::Model::ListObjectsRequest		^listRequest;
	Amazon::S3::Model::S3Object					^obj;

	listRequest = gcnew Amazon::S3::Model::ListObjectsRequest();
	listRequest->BucketName = m_Bucket;
	listRequest->Prefix = Key;
	listRequest->Delimiter = "/";
	while(true)
		{
		listResponse = s3->ListObjects(listRequest);

		for each (^obj in listResponse->S3Objects)
			{			
			DeleteRequest = gcnew Amazon::S3::Model::DeleteObjectRequest();

			DeleteRequest->BucketName = m_Bucket;
			DeleteRequest->Key = obj->Key;
			try {
				s3->DeleteObject(DeleteRequest);
				}
			catch(Amazon::S3::AmazonS3Exception ^s3Exception)
				{
				DEBUGLOG_L(2, ("Error during DeleteObject %s: %s\n", (LPCSTR)CStringA(s3Exception->Message), (LPCSTR)CStringA(obj->Key)));
				}
			delete DeleteRequest;
			}
		if(listResponse->IsTruncated == false)
			break; // we're done -- all objects enumerated for this key-prefix
		listRequest->Marker = listResponse->NextMarker;
		// now get the next batch
		}

	// now delete "root" key

	DeleteRequest = gcnew Amazon::S3::Model::DeleteObjectRequest();

	DeleteRequest->BucketName = m_Bucket;
	DeleteRequest->Key = Key;
	try {
		s3->DeleteObject(DeleteRequest);
		}
	catch(Amazon::S3::AmazonS3Exception ^s3Exception)
		{
		DEBUGLOG_L(2, ("Error during DeleteObject %s: %s\n", (LPCSTR)CStringA(s3Exception->Message), (LPCSTR)CStringA(obj->Key)));
		}
	return true;
	}

bool S3Repository::Put(System::String ^Key, System::IO::Stream ^stream, System::String ^force_bucket)
	{
	bool retval = true;
	Amazon::S3::Model::PutObjectRequest ^putRequest;

	putRequest = gcnew Amazon::S3::Model::PutObjectRequest();
	if(force_bucket == nullptr)
		putRequest->BucketName = m_Bucket;
	else
		putRequest->BucketName = force_bucket;
	putRequest->Key = Key;
	putRequest->InputStream = stream;
	try {
		s3->PutObject(putRequest);
		}
	catch(Amazon::S3::AmazonS3Exception ^s3Exception)
		{
		DEBUGLOG_L(2, ("Error during PutObject %s: %s\n%s\n", (LPCSTR)CStringA(s3Exception->Message), (LPCSTR)CStringA(Key), (LPCSTR)CStringA(s3Exception->StackTrace)));
		retval = false;
		}
	return retval;
	}


bool S3Repository::GetList(System::String ^Key, System::Collections::Generic::List<System::String ^> ^names, System::Collections::Generic::List<System::UInt32> ^sizes, System::String ^AlternateBucket/* = nullptr*/)
	{
	Amazon::S3::Model::ListObjectsResponse		^listResponse;
	Amazon::S3::Model::ListObjectsRequest		^listRequest;
	Amazon::S3::Model::S3Object					^obj;
	System::String								^DirName;
	bool										bEnumDirs = false;
	listRequest = gcnew Amazon::S3::Model::ListObjectsRequest();

	listRequest->BucketName = AlternateBucket == nullptr ? m_Bucket : AlternateBucket;
	if(Key->Length > 0)
		{
		listRequest->Prefix = Key;
		}
	else
		{
		bEnumDirs = true;
		}
	listRequest->Delimiter = "/";

	names->Clear();
	sizes->Clear();
	while(true)
		{
		try {
			listResponse = s3->ListObjects(listRequest);
			if(bEnumDirs)
				{
				for each (^DirName in listResponse->CommonPrefixes)
					{
					names->Add(DirName);
					sizes->Add((System::UInt32)0);
					}
				}
			else
				{
				for each (^obj in listResponse->S3Objects)
					{
					names->Add(obj->Key);
					sizes->Add((System::UInt32)obj->Size);
					}
				}
			if(listResponse->IsTruncated == false)
				break; // we're done -- all objects enumerated for this key-prefix
			listRequest->Marker = listResponse->NextMarker;
			// now get the next batch
			}
		catch(Amazon::S3::AmazonS3Exception ^s3Exception)
			{
			DEBUGLOG_L(2, ("S3 Error during ListObjects for GetList: %s : %s\n", (LPCSTR)CStringA(s3Exception->Message), (LPCSTR)CStringA(listRequest->Prefix)));
			break;
			}
		catch(...)
			{
			DEBUGLOG_L(2, ("Exception during ListObjects for GetList: %s\n", (LPCSTR)CStringA(listRequest->Prefix)));
			break;
			}
		}
	return true;
	}