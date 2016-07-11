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


// main.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#pragma warning(disable:4127) // disable bitching about "while(true)"

#include <Project.h>
#include "S3Repository.h"
#include "FileRepository.h"
#include "OpenStackRepository.h"

// example commands:
// copy beginning with files beginning ff46* from local file to S3
// -r ff46 -st file -sb h:\restorerepo -dt S3 -db ultrabac-gcfos -dr us-west-2 -da <accessskey> -dk <secretkey> -de http://s3-us-west-2.amazonaws.com
// copy from local to openstack:
// -r ff46 -st file -sb h:\restorerepo -dt OpenStack -db test-bucket -de https://identity.api.rackspacecloud.com/v2.0/ -da <accesskey> -dk <secretkey>
// -st S3 -sb bucket-gcfos -sr us-west-2 -sa <accesskey> -sk <secretkey> -se http://s3-us-west-2.amazonaws.com -dt File -db g:\old-repo
void PrintUsage()
	{
	_tprintf(TEXT("Usage:\n"));
	_tprintf(TEXT("  Migrator (source repository:)\n"));
	_tprintf(TEXT("           -st [File|S3|RackSpace] -sb [source:location (or bucket)]\n"));
	_tprintf(TEXT("           -sa [accesskey] -sk [secretkey] -sr [region] -se [endpoint]\n"));
	_tprintf(TEXT("  Dest:    -dt [File|S3|RackSpace] -db [source:location (or bucket)]\n"));
	_tprintf(TEXT("           -da [accesskey] -dk [secretkey] -dr [region] -de [endpoint]\n"));
	_tprintf(TEXT("  (opt)    -r [resume from]\n"));
	_tprintf(TEXT("  (opt)    -f [force overwrite]\n"));
	}

int _tmain(int argc, _TCHAR* argv[])
	{
	int						i,j;
	int						idx;
	LPTSTR					string_arg;
	UINT32					copied = 0;
	UINT32					skipped = 0;
	UINT64					bytescopied = 0;
	UINT32					bytes_subtotal = 0;
	LPTSTR					resume = NULL;
	size_t					resumelen = 0;
	LARGE_INTEGER			counterFreq;
	LARGE_INTEGER			start_time;
	LARGE_INTEGER			end_time;
	double					rate;
	bool					bForceOverwrite = false;
	int						findindex;
	bool					bDeleteAll = false;
	UINT64					deleted = 0;

	std::vector<LPCTSTR> regions(2); // all these vectors are 0=src, 1=dest
	std::vector<LPCTSTR> buckets(2);
	std::vector<LPCTSTR> types(2);
	std::vector<LPCTSTR> accesskeys(2);
	std::vector<LPCTSTR> accesssecrets(2);
	std::vector<LPCTSTR> endpoints(2);

	std::vector<Repository *> repos(2);
	System::Collections::Generic::List<System::String ^> ^dirs = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes = gcnew System::Collections::Generic::List<System::UInt32>;
	System::Collections::Generic::List<System::String ^> ^subdirs = gcnew System::Collections::Generic::List<System::String ^>;
	System::Collections::Generic::List<System::UInt32> ^sizes_d = gcnew System::Collections::Generic::List<System::UInt32>;
	System::Collections::Generic::List<System::String ^> ^subdirs_d = gcnew System::Collections::Generic::List<System::String ^>;
	System::IO::Stream ^mystream;

	if(argc < 3)
		{
		PrintUsage();
		return -1;
		}

	for(i = 1; i < argc; i++)
		{
		if(_tcslen(argv[i]) < 2
		|| (argv[i][0] != '/' && argv[i][0] != '-'))
			{
			PrintUsage();
			return -1;
			}

		if(_tcscmp(argv[i], _T("-deleteall")) == 0)
			{
			printf("Delete ALL OBJECTS selected\n");
			bDeleteAll = true;
			continue;
			}

		if(_tcslen(argv[i]) == 3)
			{
			if(i+1 >= argc)
				{
				PrintUsage();
				return -1;
				}
			string_arg = argv[i+1];
			}
		else
			{
			string_arg = &argv[i][3];
			}

		switch(tolower(argv[i][1]))
			{
			case 's':
				idx = 0;
				break;
			case 'd':
				idx = 1;
				break;
			case 'r': // resume
				if(argv[i][2])
					{
					resume = &argv[i][2];
					}
				else
					{
					resume = argv[i+1];
					i++;
					}
				resumelen = _tcslen(resume);
				continue; // get next argument
			case 'f':
				bForceOverwrite = true;
				continue; // get next argument

			default:
				PrintUsage();
				return -1;
			}
		switch(tolower(argv[i][2]))
			{
			case 'b':
				buckets[idx] = string_arg;
				break;

			case 'r':
				regions[idx] = string_arg;
				break;

			case 'a':
				accesskeys[idx] = string_arg;
				break;

			case 'k':
				accesssecrets[idx] = string_arg;
				break;

			case 't':
				types[idx] = string_arg;
				break;

			case 'e':
				endpoints[idx] = string_arg;
				break;

			default:
				PrintUsage();
				_tprintf(L"Invalid argument\n");
				return -1;
			}
		if(string_arg == argv[i+1])
			{
			i++;
			}
		}

	for(i = 0; i < 2; i++)
		{
		if(i == 1 && bDeleteAll)
			break;

		if(_tcsicmp(types[i], L"File") == 0)
			{
			repos[i] = new FileRepository();
			}
		else if(_tcsicmp(types[i], L"S3") == 0)
			{
			repos[i] = new S3Repository();
			}
		else if(_tcsicmp(types[i], L"OpenStack") == 0)
			{
			repos[i] = new OpenStackRepository();
			}
		else
			{
			PrintUsage();
			_tprintf(L"Invalid repository type specified\n");
			return -2;
			}
		}

	for(i = 0; i < 2; i++)
		{
		if(i == 1 && bDeleteAll)
			break;

		if(!repos[i]->Initialize(buckets[i], accesskeys[i], accesssecrets[i], endpoints[i], regions[i]))
			{
			_tprintf(L"Failed to connect to repository:%u\n", i);
			return -3;
			}
		}

	_tprintf(L"Enumerating source objects..");
	if(!repos[0]->GetList(gcnew System::String(""), dirs, sizes, NULL))
		{
		printf("Failed to get object list from source\n");
		goto exit_migrator;
		}
	_tprintf(L"Complete\n");

	QueryPerformanceFrequency(&counterFreq);
	QueryPerformanceCounter(&start_time);

	for(i = 0; i < dirs->Count; i++)
		{
		if(resume != NULL)
			{
			if(_tcsnicmp(CString(dirs[i]), resume, resumelen) < 0)
				continue; // ignore this sub-dir
			}
		if(bDeleteAll)
			{
			if(!repos[0]->DeleteObjects(dirs[i], false))
				{
				_tprintf(L"Delete failed for %s\n", (LPCTSTR)CString(dirs[i]));
				break;
				}
			else
				{
				deleted++;
				if((deleted % 100) == 0)
					{
					_tprintf(L"%I64u objects deleted     \r", deleted);
					}
				}
			continue;
			}
		if(!repos[0]->GetList(dirs[i], subdirs, sizes, NULL))
			{
			_tprintf(L"Failed to get source object list for %s\n", (LPCTSTR)CString(dirs[i]));
			continue;
			}
		if(!bForceOverwrite && !bDeleteAll)
			{
			// this will fail (and empty subdirs_d, sizes_d if there are no files present in search
			repos[1]->GetList(dirs[i], subdirs_d, sizes_d, NULL); 
			}
		for(j = 0; j < subdirs->Count; j++)
			{
			if(!bForceOverwrite)
				{
				findindex = subdirs_d->IndexOf(subdirs[j]);
				if(findindex != -1)
					{
					if(sizes_d[findindex] == sizes[j])
						{
						skipped++;
						continue; // file is valid already in destination, don't copy
						}
					}
				}
			if(repos[0]->GetObject(subdirs[j], mystream))
				{
				bytescopied += mystream->Length;
				bytes_subtotal += (UINT32)mystream->Length;
				if(repos[1]->Put(subdirs[j], mystream, NULL))
					{
					copied++;
					if((copied % 100) == 0)
						{
						QueryPerformanceCounter(&end_time);
						rate = (double)bytes_subtotal / ((double)(end_time.QuadPart - start_time.QuadPart) / (double)counterFreq.QuadPart) / (1024.0f * 1024.0f);
						_tprintf(L"%u objects migrated (%u MB, %0.2f MB/s)     \r", copied, (UINT32)(bytescopied >> (UINT64)20), rate);
						start_time.QuadPart = end_time.QuadPart;
						bytes_subtotal = 0;
						}
					}
				else
					{
					_tprintf(L"Put failed for %s\n", (LPCTSTR)CString(subdirs[j]));
					}
				}
			else
				{
				_tprintf(L"GetObject failed for %s\n", (LPCTSTR)CString(subdirs[j]));
				}
			mystream->Close();
			delete mystream;
			}
		}
	_tprintf(L"\n%u objects migrated, %u skipped, %I64u bytes\n", copied, skipped, bytescopied);

exit_migrator:
	return 0;
	}