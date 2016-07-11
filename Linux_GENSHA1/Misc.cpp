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
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <string.h>
#include <string.h>
#include <wchar.h>
#include <queue>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

#include "WinTypes.h"
#include "Misc.h"

void tohex_A(LPBYTE p, size_t len, char* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = p + len - 1;
		}
	else
		{
		in = p;
		}

	while(len--)
		{
		sprintf_s(out, 3, "%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}

void tobin_A(char* in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}
}

// Unicode versions

#ifdef _UNICODE
void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse /* = false */)
{
	LPBYTE in;
	
	if(reverse)
		{
		in = (LPBYTE)p + len - 1;
		}
	else
		{
		in = (LPBYTE)p;
		}

	while(len--)
		{
		swprintf_s(out, 3, L"%02x", *in);
		out +=2;
		if(reverse)
			in--;
		else
			in++;
		}
	*out = 0;
}
   
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse /*= false*/)
{
	// text must be lowercase hex
	unsigned char c;
	int adj;

	if(len & 1)
		return; // invalid -- must be multiple of 2

	if(reverse)
		{
		in = (in + len - 2);
		adj = -2;
		}
	else
		{
		adj = 2;
		}


	while(len)
		{
		c = (BYTE)(*in <= '9' ? *in - '0' : (*in - 'a')+10) * 16;
		c = c + (BYTE)(*(in+1) <= '9' ? *(in+1) - '0' : (*(in+1) - 'a')+10);
		*p = c;
		p++;
		in += adj;
		len-=2;
		}

}
#endif//_UNICODE

   
       
   
     
   
 
 
 
             
    
 
     
