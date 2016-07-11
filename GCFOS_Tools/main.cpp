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

#pragma warning(disable:4127) // disable bitching about "while(true)"
#pragma warning(disable:4100) // disable bitching about unreferenced parameters

#define STRICT
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _CRT_RAND_S

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <process.h>
#include <iostream>
#include <fstream>

#include "ipp.h"
#include "ippcp.h"

#include "GCFOS_Client.h"

GCFOS_Client *client;

void PrintUsage()
{
	printf("GCFOS_Tools:\n"
		   "  -a   Add new client\n"
		   "  -d [id] Delete existing client\n"
		   "  -s [id] Show key of existing client\n"
		   "\n");
}

void tohex(void *p, size_t len, char* out)
{
	LPBYTE in = (LPBYTE)p;

	while(len--)
		{
		sprintf_s(out, 3, "%02x", *in++);
		out +=2;
		}
	*out = 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	int			i;
	int			clientid = -1;
	GCFOS_SRV_RESPONSE status;
	UINT32		newid;
	UCHAR		key[GCFOS_SHARED_KEY_LEN];
	CHAR		textkey[GCFOS_SHARED_KEY_LEN * 2 + 1];

	enum { INVALID, ADD, DELETE_CLIENT, SHOW, BOMBARD } mode = INVALID;

	GCFOS_Client::SetConsoleLogging(true);
		
	for(i = 1; i < argc; i++)
		{
		if(argv[i][0] == '/' || argv[i][0] == '-')
			{
			switch(argv[i][1])
				{
				case 'a':
					mode = ADD;
					break;

				case 'd':
					mode = DELETE_CLIENT;
					break;

				case 's':
					mode = SHOW;
					break;

				case 'b':
					mode = BOMBARD;
					break;

				default:
					PrintUsage();
					return 0;
				}
			}
		else
			{
			clientid = _ttoi(argv[i]);
			}
		}

	client = new GCFOS_Client();

	if(mode == BOMBARD)
		{
		for(int y = 0; y < 10000; y++)
			{
			if(client->Connect(_T("C:\\gcfos\\"), _T("UltraBac Software"), false, false) == false)
				{
				printf(("Unable to connect to GCFOS server\n"));
				return 0;
				}
			// all these will fail because no auth has been made
			status = client->RegisterNewClient(&newid, key);
			}
		printf(("Bombard complete\n"));
		return 0;
		}

	if(client->Connect(_T("C:\\gcfos\\"), _T("UltraBac Software"), false, false) == false)
		{
		printf(("Unable to connect to GCFOS server\n"));
		return 0;
		}

	if(client->Auth() == GCFOS_SRV_RESP_AUTH)
		{
		printf("Successfully authenticated\n");
		}
	else
		{
		printf("FAILED to authenticate\n");
		return 0;
		}

	switch(mode)
		{
		case ADD:
			status = client->RegisterNewClient(&newid, key);
			if(status == GCFOS_SRV_RESP_OK)
				{
				tohex(key, GCFOS_SHARED_KEY_LEN, textkey);
				printf("Added client %u, key = %s\n", newid, textkey);
				}
			else
				{
				printf("Error(%hu) adding client\n", status);
				}
			break;

		case DELETE_CLIENT:
			if(clientid == -1)
				{
				printf("\nClient specifier missing\n");
				PrintUsage();
				break;
				}
			status = client->DeleteClient(clientid);
			if(status == GCFOS_SRV_RESP_OK)
				{
				tohex(key, GCFOS_SHARED_KEY_LEN, textkey);
				printf("Client %u deleted successfully\n", clientid);
				}
			else
				{
				printf("Deleting: Error(%hu) locating client\n", status);
				}
			break;

		case SHOW:
			if(clientid == -1)
				{
				printf("\nClient specifier missing\n");
				PrintUsage();
				break;
				}
			status = client->GetClientDetails(clientid, key);
			if(status == GCFOS_SRV_RESP_OK)
				{
				tohex(key, GCFOS_SHARED_KEY_LEN, textkey);
				printf("Client key = %s\n", textkey);
				}
			else
				{
				printf("Error(%hu) locating client\n", status);
				}
			break;

		default:
			break;
		}


	client->Close();

	delete client;

}

