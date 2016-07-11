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

#ifndef _UNICODE
#define tobin tobin_A
#define tohex tohex_A
#else
#define tobin tobin_W
#define tohex tohex_W
void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse = false);
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse = false);
#endif

void tohex_A(LPBYTE p, size_t len, char* out, bool reverse = false);
void tobin_A(LPSTR in, size_t len, LPBYTE p, bool reverse = false);

