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

int ProcessUpdate(GCFOS_UPDATE_ENTRY *updateEntry, gcfosdbTxn *txn, PGCFOS_SRV_RESPONSE response);
void ProcessLimboEntries();
void DeleteIncompleteSessionRecords();
bool AddSessionRecord(PGCFOS_CONNECT_STATE context);
bool UpdateSessionRecord(PGCFOS_CONNECT_STATE context, GCFOS_SESSION_END_REASON reason);
void ReportSessionActivity();
unsigned __stdcall ValidateBlocksWorker(void * param);
unsigned __stdcall MigrateBlockStoreToSecondary(void * param);
void DumpSessionsToLogFiles();
       
   
     
   
 
 
 
             
    
 
     
