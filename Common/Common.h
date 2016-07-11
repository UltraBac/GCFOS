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


// This method is not included in the class so as to keep it from being exported (and documented)
// It is used to determine the offset into the 1st 1MB of a file that should be used as "ValidationKey"
// The offset is deterministic based on the SHA1-hash, the size and most importantly the CLIENT-ID
// this ensures that one client obtaining the ValidationKey for a file will not work for a different
// client. More importantly, it is not possible to restore the file (if the data at the offset is not
// known), so this data must be stored with the hash/size. So, without having access to the original
// file (or, at least the first MB of the file), it will not be possible to restore it. This goes a 
// long way to eliminate the possibility that a restore is attempted of a file whose hash is known
// (possibly publically available) without ever having had access to the file in the first place.
UINT32 DetermineOffsetForValidationKey(GCFOS_CLIENTID ClientID, LPBYTE SHA1, UINT32 size);

#define CHARCOUNT(_x) (sizeof(_x) / sizeof(TCHAR))
// other routines shared between client and server

class GCFOS_UsefulTime {
	// The point of this class is to have a time "useful" to GCFOS -- one that doesn't take up
	// a lot of storage. This is done by discarding precision and storing only the seconds.
	// Since this project was started in 2013, this was chosen as the "base date" and won't
	// overflow for 136 years. The #secs is stored as a UINT32 internally.
public:
	GCFOS_UsefulTime() { ObtainTimeNow(); };
	GCFOS_UsefulTime(UINT32 i) { secsSince2013 = 0; }; // Used to set an "invalid" time (not present)
	void ObtainTimeNow();
	UINT32 GetUsefulValue() { return secsSince2013; };
	INT32 Diff(const GCFOS_UsefulTime &compare) { return (secsSince2013 - compare.secsSince2013); }
	void GetTime(time_t *t);
	UINT16 AsDays() { return (UINT16)(secsSince2013 / 86400); } // convert secs to days
	void FromDays(UINT16 Days) { secsSince2013 = Days * 86400; } // load from #days (ie approximate)

private:
	UINT32 secsSince2013;
	};
