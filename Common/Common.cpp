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

// Routines common to both GCFOS_Server and GCFOS_Client where it's important to
// maintain that these are synchronized
#include "stdafx.h"

UINT32 DetermineOffsetForValidationKey(GCFOS_CLIENTID ClientID, LPBYTE SHA1, UINT32 size)
	{
	DWORD				dwFirstWordOfHash = (*((LPDWORD)SHA1)) * ClientID;
	DWORD				dwDivisor = (size-4) & 0xfffff;

	if(dwDivisor == 0)
		dwDivisor = 1;

	return (dwFirstWordOfHash % dwDivisor);
	}

// Time (GCFOS_UsefulTime) functions
void GCFOS_UsefulTime::GetTime(time_t *t)
	{
	// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724228%28v=vs.85%29.aspx
	// A time_t is the number of 1-second intervals since January 1, 1970.
	// A GCFOS_UsefulTime is number of seconds since 12/4/2013 (5pm PST)
	
	//(130306793251016374 - 116444736000000000) / 1000000 = 1386205725;
	
	*t = secsSince2013 + 1386205725;
	}

void GCFOS_UsefulTime::ObtainTimeNow()
	{
	// Ignore alignment fault warnings in documentation -- this will be correctly aligned
	INT64			ft;
	// Number of 100-ns intervals between 1/1/1601 (when FILETIMEs start, until 12/4/2013 5pm (PST) when WE believe time starts)
	// overflow will occur in 136 years from then LOL(NMP)

	const UINT64	Since1601to2013 = 130306793251016374;

#ifdef _WIN32
	GetSystemTimeAsFileTime((PFILETIME)&ft); // this is UTC time
#else
	time_t t_now;
	time(&t_now);
	time_t_to_FILETIME(t_now, (FILETIME*)&ft);
#endif//_WIN32

	ft -= Since1601to2013;

	// discard bits of resolution that we don't care about (reduce resolution to seconds)
	ft = ft / 10000000;
	secsSince2013 = (UINT32)ft;
	}



