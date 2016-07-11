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


// This file is currently not used in the project.
// It is a lightweight class to provide a locking mechanism for 
// multi-reader/single-writer paradigm


class Locker {
private:
	CRITICAL_SECTION	m_csWrite;
	CRITICAL_SECTION	m_csReaders;
	LONG volatile		m_ReaderCount;
	HANDLE				m_heWrite;

public:
	Locker() {
		m_ReaderCount = 0;
		InitializeCriticalSection(&m_csReaders);
		InitializeCriticalSection(&m_csWrite);
		m_heWrite = CreateEvent(NULL, TRUE, TRUE, NULL);
		}

	~Locker() {
		CloseHandle(m_heWrite);
		DeleteCriticalSection(&m_csReaders);
		}

	void Read() {
		EnterCriticalSection(&m_csWrite);
		EnterCriticalSection(&m_csReaders);
		m_ReaderCount++;
		ResetEvent(m_heWrite);
		LeaveCriticalSection(&m_csReaders);
		LeaveCriticalSection(&m_csWrite);
		}

	void ReadEnd() {
		EnterCriticalSection(&m_csReaders);
		m_ReaderCount--;
		if(m_ReaderCount == 0)
			{
			// Indicate that there are no readers now
			SetEvent(m_heWrite);
			}
		LeaveCriticalSection(&m_csReaders);
		}

	void Write() {
		EnterCriticalSection(&m_csWrite);
		while(true)
			{
			EnterCriticalSection(&m_csReaders);
			if(m_ReaderCount > 0)
				{
				LeaveCriticalSection(&m_csReaders);
				WaitForSingleObject(m_heWrite, INFINITE);
				continue;
				}
			else
				{
				LeaveCriticalSection(&m_csReaders);
				break;
				}
			}
		}

	void WriteEnd() {
		LeaveCriticalSection(&m_csReaders);
		LeaveCriticalSection(&m_csWrite);
		}
};
