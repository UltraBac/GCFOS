/*
GCFOS_Client.cpp : Defines the exported functions for the DLL application.

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

#include "stdafx.h"

// This is an example of an exported variable
GCFOS_CLIENT_API int nGCFOS_Client_Ver=1;

GCFOS_PRIVATE_STATICS *GCFOS_Client::m_statics = NULL;

// This is the constructor of a class that has been exported.
// see GCFOS_Client.h for the class definition
GCFOS_Client::GCFOS_Client()
	{
#ifdef _WIN32
	WSADATA			wsaData;
#else
	srand48(time(NULL));
#endif//_WIN32

	m_priv = new GCFOS_PRIVATE_MEMBERS();
	m_priv->m_bInit = false;
	m_priv->m_bConnected = false;
	m_priv->m_uLZOsize = 0;

	if(m_statics == NULL)
		{
		m_statics = new GCFOS_PRIVATE_STATICS;
		}
	m_CachePath = new TCHAR[3];
#ifdef _WIN32
	_tcscpy_s(m_CachePath, 3, _T(".\\"));
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
		{
		DEBUGLOG(("GCFOS_Client: WSAStartup failed!\n"));
		}
#else
	_tcscpy_s(m_CachePath, 3, _T("./"));
#endif//_WIN32
	}

GCFOS_Client::~GCFOS_Client()
	{
	delete m_CachePath;
	delete m_priv;
#ifdef _WIN32
	WSACleanup();
#endif

	}

GCFOS_CLIENTID GCFOS_Client::GetClientID()
	{
	return m_priv->m_ClientID;
	}

bool GCFOS_Client::AttemptAutoConfig(HKEY hKey)
	{
	SOCKET					udp_s;
	struct sockaddr_in		broadcastaddr;
	GCFOS_REQUEST_CONFIG	request;
	GCFOS_CONFIG_RESPONSE_2	response2;
	PGCFOS_CONFIG_RESPONSE	response = (PGCFOS_CONFIG_RESPONSE)&response2; // response and response2 share same buffer

	DWORD					dwLen;
	int						broadcastPermission = 1;
	fd_set					FDS;
	struct timeval			sockettimeout = { 2, 0 }; // 2 sec
	int						retry;
	bool					retval = false;
	LONG					status;
	TCHAR					szSecret[GCFOS_SHARED_KEY_LEN * 2 + 1]; // hex representation of secret key (written in registry)
	TCHAR					client_str[12];

	udp_s = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
	if(udp_s == SOCKET_ERROR)
		{
		DEBUGLOG(("AttemptAutoConfig: Failed to create socket, %u\n", WSAGetLastError()));
		return false;
		}

	if(setsockopt(udp_s, SOL_SOCKET, SO_BROADCAST, (LPCSTR)&broadcastPermission, sizeof(broadcastPermission)) == SOCKET_ERROR)
		{
		DEBUGLOG(("AttemptAutoConfig: Failed to enable broadcast permission on socket, %u\n", WSAGetLastError()));
		closesocket(udp_s);
		return false;
		}

	memset(&request, 0, sizeof(request));
	request.type = GCFOS_REQ_CONFIG;
	dwLen = MAX_COMPUTERNAME_LENGTH + 1;
	if(!GetComputerNameW(request.wszComputerName, &dwLen))
		{
		DEBUGLOG(("AttemptAutoConfig: GetComputerName failed: %u\n", GetLastError()));
		closesocket(udp_s);
		return false;
		}

	memset((char *) &broadcastaddr, 0, sizeof(broadcastaddr));
    broadcastaddr.sin_family = AF_INET;
    broadcastaddr.sin_port = htons((u_short)atoi(GCFOS_SERVER_PORT));
    broadcastaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	// NOTE: In case of failure-to-connect, this routine will be called twice, doubling
	//       the actual retry count.
	for(retry = 0; retry < 2 && retval == false; retry++)
		{
		FD_ZERO(&FDS);
		FD_SET(udp_s, &FDS);
		if(SOCKET_ERROR == sendto(udp_s, (LPCSTR)&request, sizeof(request), 0, (const sockaddr *)&broadcastaddr, sizeof(broadcastaddr)))
			{
			DEBUGLOG(("AttemptAutoConfig: sendto failed, %u\n", WSAGetLastError()));
			break;
			}
		switch(select((int)udp_s + 1, &FDS, NULL, NULL, &sockettimeout))
			{
			case SOCKET_ERROR:
				DEBUGLOG(("AttemptAutoConfig: select failed, %u\n", WSAGetLastError()));
				retry = 99;
				break;
			case 0:
				break; // timeout
			case 1:
				if(SOCKET_ERROR == recv(udp_s, (LPSTR)response, sizeof(response2), 0))
					{
					DEBUGLOG(("AttemptAutoConfig: recv failed, %u\n", WSAGetLastError()));
					retry = 99;
					break;
					}
				switch(response2.Size)
					{
					case sizeof(GCFOS_CONFIG_RESPONSE):
						dwLen = (DWORD)(_wcslen(response->wszComputerName) + 1) * sizeof(WCHAR);
						status = RegSetValueExW(hKey, GCFOS_CLIENT_REG_SERVER, NULL, REG_SZ, (LPBYTE)&response->wszComputerName, dwLen);
						if(status != ERROR_SUCCESS)
							{
							DEBUGLOG(("AttemptAutoConfig: failed to update registry with server address %u\n", status));
							}
						dwLen = (DWORD)(_wcslen(response->wszServerIP) + 1) * sizeof(WCHAR);
						status = RegSetValueExW(hKey, GCFOS_CLIENT_REG_SERVER_IP, NULL, REG_SZ, (LPBYTE)&response->wszServerIP, dwLen);
						if(status != ERROR_SUCCESS)
							{
							DEBUGLOG(("AttemptAutoConfig: failed to update registry with server IP address %u\n", status));
							}
						retval = true;
						break;

					case sizeof(GCFOS_CONFIG_RESPONSE_2):
						dwLen = (DWORD)(_wcslen(response2.wszServerIP) + 1) * sizeof(WCHAR);
						status = RegSetValueExW(hKey, GCFOS_CLIENT_REG_SERVER, NULL, REG_SZ, (LPBYTE)&response2.wszServerIP, dwLen);
						if(status != ERROR_SUCCESS)
							{
							DEBUGLOG(("AttemptAutoConfig: failed to update registry with server address %u\n", status));
							retry = 99;
							break;
							}

						dwLen = sizeof(szSecret);
						tohex(response2.Secret, GCFOS_SHARED_KEY_LEN, szSecret);
						status = RegSetValueEx(hKey, GCFOS_CLIENT_REG_SECRETKEY, NULL, REG_SZ, (LPBYTE)&szSecret, dwLen);
						if(status != ERROR_SUCCESS)
							{
							DEBUGLOG(("AttemptAutoConfig: failed to update registry with secret %u\n", status));
							}
						RegDeleteValue(hKey, GCFOS_CLIENT_REG_SERVER_IP);
						_itot_s(response2.ClientID, client_str, 10);
						status = RegSetValueEx(hKey, GCFOS_CLIENT_REG_CLIENTID, NULL, REG_SZ, (LPBYTE)&client_str, ((DWORD)_tcslen(client_str) + 1) * sizeof(TCHAR));
						if(status != ERROR_SUCCESS)
							{
							DEBUGLOG(("AttemptAutoConfig: failed to update registry with clientid %u\n", status));
							retry = 99;
							break;
							}

						DEBUGLOG(("AutoConfig: Using server %S, client-id %u\n", response2.wszServerIP, response2.ClientID));
						retval = true;
						break;

					default:
						DEBUGLOG(("AttemptAutoConfig: invalid response size received, %d\n", response->Size));
						retry = 99;
						break;
					}
				break;
			}
		}
	closesocket(udp_s);
	return retval;
	}

#ifdef _WIN32
HKEY CreateRegistryKeyWithEveryoneAccess(LPCTSTR pszKeyPath)
	{
    HANDLE hToken = NULL; 
    PSID pSIDEveryone = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SECURITY_ATTRIBUTES sa;
    const int NUM_ACES  = 1;
    EXPLICIT_ACCESS ea[NUM_ACES];
	HKEY hKey = NULL;
	LSTATUS Status;

    // Specify the DACL to use.
    // Create a SID for the Everyone group.
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                     SECURITY_WORLD_RID,
                     0,
                     0, 0, 0, 0, 0, 0,
                     &pSIDEveryone)) 
		{
		DEBUGLOG(("GCFOS_Client::CreateRegistryKeyWithEveryoneAccess - AllocateAndInitializeSid failed %u\n", GetLastError()));
        goto CreateRegistryKeyWithEveryoneAccess_exit;
		}

    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    // Set read access for Everyone.
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR) pSIDEveryone;

    if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES,
                                         ea,
                                         NULL,
                                         &pACL))
		{
		DEBUGLOG(("GCFOS_Client::CreateRegistryKeyWithEveryoneAccess - SetEntriesInAcl failed %u\n", GetLastError()));
        goto CreateRegistryKeyWithEveryoneAccess_exit;
		}

	// Initialize a security descriptor.  
    pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 
    if (NULL == pSD) 
	    { 
		DEBUGLOG(("GCFOS_Client::CreateRegistryKeyWithEveryoneAccess - LocalAlloc failed %u\n", GetLastError()));
        goto CreateRegistryKeyWithEveryoneAccess_exit; 
		} 
 
    if (!InitializeSecurityDescriptor(pSD,
            SECURITY_DESCRIPTOR_REVISION)) 
		{  
		DEBUGLOG(("GCFOS_Client::CreateRegistryKeyWithEveryoneAccess - InitializeSecurityDescriptor failed %u\n", GetLastError()));
        goto CreateRegistryKeyWithEveryoneAccess_exit; 
	    } 
 
    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(pSD, 
            TRUE,     // bDaclPresent flag   
            pACL, 
            FALSE))   // not a default DACL 
		{  
		DEBUGLOG(("GCFOS_Client::CreateRegistryKeyWithEveryoneAccess - SetSecurityDescriptorDacl failed %u\n", GetLastError()));
        goto CreateRegistryKeyWithEveryoneAccess_exit; 
		} 

    // Initialize a security attributes structure.
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = TRUE;

	Status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, pszKeyPath, 0, NULL, 0, KEY_READ | KEY_WRITE, &sa, &hKey, NULL);
	if(Status != ERROR_SUCCESS)
		{
		DEBUGLOG(("GCFOS_Client: Unable to open/create registry key %S for configuration: %u\n", pszKeyPath, Status));
		}
        

CreateRegistryKeyWithEveryoneAccess_exit:

    if(pSIDEveryone)
        FreeSid(pSIDEveryone); 

    if(pACL)
       LocalFree(pACL);

	if(pSD)
		LocalFree(pSD);

    if(hToken)
       CloseHandle(hToken);

    return hKey;
	}
#else
HKEY CreateRegistryKeyWithEveryoneAccess(LPCTSTR pszKeyPath)
{
	HKEY hKey;

	RegCreateKeyEx(HKEY_LOCAL_MACHINE, pszKeyPath, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &hKey, NULL);
	return hKey;
}
#endif//_WIN32

bool GCFOS_Client::Connect(LPCTSTR cachePath, LPCTSTR CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache)
	{
	return Connect(cachePath, CompanyName, EnableLocalBlockCache, EnableExtendedBlockCache, NULL, 0, NULL);
	}

bool GCFOS_Client::Connect(LPCTSTR cachePath, LPCTSTR CompanyName, bool EnableLocalBlockCache, bool EnableExtendedBlockCache, LPCTSTR Server, GCFOS_CLIENTID Client, BYTE const * Secret)
	{
	struct addrinfo hints = {0};
	struct addrinfo *GCFOS_addr = NULL;
	int				retVal;
	BOOL			one = 1;
	TCHAR			szSecretKey[(GCFOS_SHARED_KEY_LEN +1) * sizeof(TCHAR)];
	TCHAR			szKeyPath[128];
	TCHAR			szClientID[16];
	DWORD			dwLen;
	LONG			status;
	INT				connectionAttempt;
	bool			bConfigInfoFound = false;

	m_priv->m_ClientID = 0;
	if(CompanyName == NULL)
		return false;

	m_bEnableLocalBlockCache = EnableLocalBlockCache;
	m_bEnableExtendedLocalBlockCache = EnableExtendedBlockCache;
	m_bSimpleAuthSuccessful = false;

	if(cachePath != NULL && _tcslen(cachePath) > 0)
		{
		// The path is used to store local cache files
		size_t newlen = _tcslen(cachePath) + 2;

		if(m_CachePath != NULL)
			delete m_CachePath;

		m_CachePath = new TCHAR[newlen];
		_tcscpy_s(m_CachePath, newlen, cachePath);
		if(m_CachePath[_tcslen(m_CachePath) - 1] != '\\')
			{
			_tcscat_s(m_CachePath, newlen, _T("\\"));
			}
		m_bEnableLocalCache = true;
		}
	else
		{
		m_bEnableLocalCache = false;
		}

	if(m_statics->m_hKey == NULL)
		{
		_stprintf_s(szKeyPath, 128, _T("SOFTWARE\\%s\\GCFOS\\Client"), CompanyName);
		m_statics->m_hKey = CreateRegistryKeyWithEveryoneAccess(szKeyPath);
		if(m_statics == NULL)
			{
			return false;
			}
		}

	if(Client != 0 && Secret != NULL)
		{
		m_priv->m_bSecretFound = true;
		if(Server == NULL)
			{
			_tcscpy_s(m_priv->m_szIPConnection, CHARCOUNT(m_priv->m_szIPConnection), _T("<default IP address>"));
			}
		else
			{
			_tcscpy_s(m_priv->m_szIPConnection, CHARCOUNT(m_priv->m_szIPConnection), Server);
			}
		memcpy(m_priv->m_SecretKey, Secret, GCFOS_SHARED_KEY_LEN);
		m_priv->m_ClientID = Client;
		bConfigInfoFound = true;
		}

	for(connectionAttempt = 0; connectionAttempt < 2; connectionAttempt++)
		{
		if(!bConfigInfoFound)
			{
			dwLen = sizeof(szSecretKey);

			m_priv->m_bSecretFound = false;
			if(RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_SECRETKEY, NULL, NULL, (LPBYTE)&szSecretKey, &dwLen) == ERROR_SUCCESS
			&& dwLen >= GCFOS_SHARED_KEY_LEN * sizeof(TCHAR))
				{
				m_priv->m_bSecretFound = true;
				tobin(szSecretKey, GCFOS_SHARED_KEY_LEN * sizeof(TCHAR), m_priv->m_SecretKey);
				}

			dwLen = sizeof(szClientID);
			status = RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_CLIENTID, NULL, NULL, (LPBYTE)&szClientID, &dwLen);
			if(status != ERROR_SUCCESS)
				{
				if(m_priv->m_bSecretFound == true)
					{
					DEBUGLOG(("GCFOS_Client: Unable to read client key: %u\n", status));
					}
				m_priv->m_ClientID = 0;
				}
			else
				{
				m_priv->m_ClientID = _ttoi(szClientID);
				}

			if(m_priv->m_ClientID == 1)
				{
				DEBUGLOG(("GCFOS_Client: !!WARNING!! Running as GCFOS administrator\n"));
				}

			dwLen = sizeof(m_priv->m_szIPConnection);
			m_priv->m_szIPConnection[0] = 0;
			RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_SERVER_IP, NULL, NULL, (LPBYTE)&m_priv->m_szIPConnection, &dwLen);
			if(m_priv->m_szIPConnection[0] == 0)
				{
				_tcscpy_s(m_priv->m_szIPConnection, _T("<default IP address>"));
				}
			else
				{
				bConfigInfoFound = true;
				}

			if(ERROR_SUCCESS != RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_SERVER, NULL, NULL, (LPBYTE)&m_priv->m_szServerConnection, &dwLen))
				{
				// Server not specified, use default
				_tcscpy_s(m_priv->m_szServerConnection, _T("<default address>"));
				if(!bConfigInfoFound && m_priv->m_bSecretFound && m_priv->m_ClientID < 2)
					{
					DEBUGLOG(("GCFOS_Client: Invalid client id specified when no server has been specified\n"));
					return false;
					}
				}
			else
				{
				bConfigInfoFound = true;
				}

			if(!m_priv->m_bSecretFound && !bConfigInfoFound)
				{
				if(!AttemptAutoConfig(m_statics->m_hKey))
					{
					DEBUGLOG(("GCFOS_Client: Auto-config failed\n"));
					return false;
					}
				else
					{
					// attempt to re-load values from registry now
					continue;
					}
				}
			}

		// Leave hKey open for further queries

		if(m_priv->m_bInit == false)
			{
			if(!m_priv->InitializeCompression())
				{
				DEBUGLOG(("GCFOS_Client: failed to initialize compression\n"));
				return false;
				}
			m_priv->m_bInit = true;
			}

		hints.ai_flags  = 0;
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if(getaddrinfo(CStringA(m_priv->m_szIPConnection), GCFOS_SERVER_PORT, &hints, &GCFOS_addr) != 0 )
			{
			DEBUGLOG(("GCFOS_Client: unable to get IP address of GCFOS server: %d\n", WSAGetLastError()));
			if(getaddrinfo(CStringA(m_priv->m_szServerConnection), GCFOS_SERVER_PORT, &hints, &GCFOS_addr) != 0 )
				{
				continue; // this will force an attempt to auto-config which might change the settings, so retry connection
				}
			DEBUGLOG(("GCFOS_Client: Using registered address %s\n", CStringA(m_priv->m_szServerConnection)));
			}

		if(GCFOS_addr == NULL)
			{
			DEBUGLOG(("getaddrinfo() failed to resolve GCFOS server\n"));
			continue; // this will force an attempt to auto-config which might change the settings, so retry connection
			}

		m_priv->m_srv = WSASocket(GCFOS_addr->ai_family, GCFOS_addr->ai_socktype, GCFOS_addr->ai_protocol, NULL, 0, 0);
		if(m_priv->m_srv == INVALID_SOCKET)
			{
			DEBUGLOG(("GCFOS_Client: socket() failed: %d\n", WSAGetLastError()));
			freeaddrinfo(GCFOS_addr);
			continue; // this will force an attempt to auto-config which might change the settings, so retry connection
			}

#if 0
		// Disable output buffering
		retVal = setsockopt(m_srv, SOL_SOCKET, SO_SNDBUF, (char *)&zero, sizeof(zero));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG(("setsockopt(SNDBUF) failed: %d\n", WSAGetLastError()));
			closesocket(m_srv);
			freeaddrinfo(GCFOS_addr);
			return false;
			}
#endif

		// Disable delay -- MUST be done PRIOR to connect (bug in implementation)
		retVal = setsockopt(m_priv->m_srv, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG(("setsockopt(TCP_NODELAY) failed: %d\n", WSAGetLastError()));
			closesocket(m_priv->m_srv);
			freeaddrinfo(GCFOS_addr);
			return false;
			}

		retVal = connect(m_priv->m_srv, GCFOS_addr->ai_addr, (int) GCFOS_addr->ai_addrlen);
		if(retVal == SOCKET_ERROR)
			{
			DEBUGLOG(("GCFOS_Client: connect failed: %d\n", WSAGetLastError()));
			closesocket(m_priv->m_srv);
			freeaddrinfo(GCFOS_addr);
			continue; // this will force an attempt to auto-config which might change the settings, so retry connection
			}

		freeaddrinfo(GCFOS_addr);
		break; // successfully connected
	}

	dwLen = GCFOS_COMPUTER_NAME_LENGTH;
	m_priv->m_bUBDR = false;
	GetComputerNameW(m_priv->m_ComputerName, &dwLen);
#ifdef _WIN32
	if(_tcsnicmp(m_priv->m_ComputerName, GCFOS_COMPUTER_NAME_MININT, GCFOS_COMPUTER_NAME_MININT_LEN) == 0)
		{
		DEBUGLOG(("GCFOS_Client::Connect UBDR environment detected\n"));
		_tcscpy_s(m_priv->m_ComputerName, GCFOS_CLIENT_UBDR_STRING);
		// this is from a UBDR environment -- because the computer name begins "MININT-"
		m_priv->m_bUBDR = true;
		}
#endif//_WIN32
	if(!m_priv->m_bSecretFound)
		{
		GCFOS_REQUEST_SIMPLE_AUTH	simpleauth;
		GCFOS_SIMPLE_AUTH_RESPONSE	simpleauth_resp;
		memset(&simpleauth, 0, sizeof(simpleauth));
		_wcsncpy(simpleauth.szName, m_priv->m_ComputerName, GCFOS_COMPUTER_NAME_LENGTH);
		simpleauth.type = GCFOS_REQ_SIMPLE_AUTH;
		if(sendBlock(m_priv->m_srv, (char *)&simpleauth, sizeof(simpleauth), 0) != sizeof(simpleauth))
			{
			DEBUGLOG(("GCFOS_Client::Connect sendBloack failed %d\n", GetLastError()));
		    closesocket(m_priv->m_srv);
			return false;
			}
		if(recv(m_priv->m_srv, (char *)&simpleauth_resp, sizeof(simpleauth_resp), 0) != sizeof(simpleauth_resp))
			{
			DEBUGLOG(("GCFOS_Client::Connect recv from simpleauth failed %d\n", GetLastError()));
		    closesocket(m_priv->m_srv);
			return false;
			}
		if(simpleauth_resp.SrvResponse != GCFOS_SRV_RESP_AUTH || simpleauth_resp.client_id == 0)
			{
			DEBUGLOG(("GCFOS_Client::Connect unexpected response (%u) from simpleauth request\n", (UINT32)simpleauth_resp.SrvResponse));
		    closesocket(m_priv->m_srv);
			return false;
			}
		m_priv->m_ClientID = simpleauth_resp.client_id;
		// normally m_LCUD_seq would be set by phase-2 authentication, but this is a "local" GCFOS implementation
		m_priv->m_LCUD_seq = simpleauth_resp.seq;
		m_bSimpleAuthSuccessful = true;
		}

	DEBUGLOG(("GCFOS Client %u connected\n", m_priv->m_ClientID));
	m_priv->m_bConnected = true;
	return true;
	}

bool GCFOS_Client::SwitchClient(LPCWSTR pszNewComputerName)
	{
	GCFOS_REQUEST_SIMPLE_AUTH	simpleauth;
	GCFOS_SIMPLE_AUTH_RESPONSE	simpleauth_resp;

	memset(&simpleauth, 0, sizeof(simpleauth));
	_wcsncpy(simpleauth.szName, pszNewComputerName, GCFOS_COMPUTER_NAME_LENGTH);
	simpleauth.type = GCFOS_REQ_SIMPLE_AUTH;
	EnterCriticalSection(&m_priv->m_csAccess);
	if(sendBlock(m_priv->m_srv, (char *)&simpleauth, sizeof(simpleauth), 0) != sizeof(simpleauth))
		{
		DEBUGLOG(("GCFOS_Client::SwitchClient sendBloack failed %d\n", GetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}
	if(recv(m_priv->m_srv, (char *)&simpleauth_resp, sizeof(simpleauth_resp), 0) != sizeof(simpleauth_resp))
		{
		DEBUGLOG(("GCFOS_Client::SwitchClient recv from simpleauth failed %d\n", GetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(simpleauth_resp.SrvResponse != GCFOS_SRV_RESP_AUTH || simpleauth_resp.client_id == 0)
		{
		DEBUGLOG(("GCFOS_Client::SwitchClient unexpected response (%u) from simpleauth request\n", (UINT32)simpleauth_resp.SrvResponse));
		return false;
		}
	m_priv->m_ClientID = simpleauth_resp.client_id;
	_wcsncpy(m_priv->m_ComputerName, pszNewComputerName, GCFOS_COMPUTER_NAME_LENGTH);
	DEBUGLOG(("GCFOS_Client::SwitchClient switched to %s, client %d\n", CStringA(pszNewComputerName), m_priv->m_ClientID));
	return true;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::Query(BYTE const * q, UINT32 size)
	{
	GCFOS_REQUEST_QUERY			req;
	GCFOS_SRV_QUERY_RESPONSE	result;
	DWORD						dwLen;
	GCFOS_LOCAL_ENTRY			residentEntry;
	LARGE_INTEGER				start_time, end_time;
	int							rc;

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	if(m_priv->m_bUBDR)
		return GCFOS_SRV_RESP_CLIENT_ERROR; // UBDR clients not allowed to query

	if(!FileStoreEnabled())
		return GCFOS_SRV_RESP_NOT_CONFIGURED;

	memcpy(req.SHA1Bytes, q, GCFOS_SHA1_LEN);
	req.type = GCFOS_REQ_QUERY;
	req.size = size;

	if(m_bEnableLocalCache)
		{
		memcpy(&residentEntry.SHA1, q, GCFOS_SHA1_LEN);
		residentEntry.size = req.size;
		if(m_statics->m_db_resident.find(&residentEntry) == 0)
			{
			// this has been found in the local cache
			m_priv->m_locallyResidentHits++;
			return GCFOS_SRV_RESP_RESIDENT;
			}

		if(m_statics->m_db_LCUD.find(&residentEntry) == 0)
			{
			// this has been found in the local cache (LCUD)
			m_priv->m_UniqueHits++;
			return GCFOS_SRV_RESP_UNIQUE;
			}
		}
	
	EnterCriticalSection(&m_priv->m_csAccess);
	QueryPerformanceCounter(&start_time);
	m_priv->m_Queries++;

	result.Response = GCFOS_SRV_RESP_ERROR;
	dwLen = sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0);
	if(dwLen == sizeof(req))
		{
		dwLen = recvBlock(m_priv->m_srv, (char *)&result, sizeof(result), 0);
		LeaveCriticalSection(&m_priv->m_csAccess);
		if(dwLen == sizeof(result))
			{
			switch(result.Response)
				{
				case GCFOS_SRV_RESP_WANT_FILENAME:
#ifndef _DEBUG
					result.Response = GCFOS_SRV_RESP_WANT_FILENAME;
#endif
					// fall-through
				case GCFOS_SRV_RESP_RESIDENT:
					// Record resident file in local cache
					if(m_bEnableLocalCache)
						{
						rc = m_statics->m_db_resident.insert(&residentEntry);
						if(rc != 0)
							{
							DEBUGLOG(("GCOFS_Client::Query unable to commit to resident cache, %d", rc));
							}
						else
							{
							m_priv->m_locallyAdded++;
							}
						}

					// fall through..
				case GCFOS_SRV_RESP_WANTED:
					break;
				}
			}
		}
	else
		{
		DEBUGLOG(("GCFOS_Client::Query failed to send %d:%u\n", dwLen, WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		}

	QueryPerformanceCounter(&end_time);
	m_priv->m_QueryTime += (end_time.QuadPart - start_time.QuadPart);

	return result.Response;
	}

void GCFOS_Client::Close()
	{
	UINT16 i;

	UpdateLocalBlockCache();

	closesocket(m_priv->m_srv);
	m_priv->m_srv = INVALID_SOCKET;
	GetHashForHandle(NULL, NULL, NULL, FILETIME(), NULL, NULL);

	if(m_priv->m_hWorkerPort != INVALID_HANDLE_VALUE)
		{
		// tell worker threads to exit
		for(i = 0; i < m_priv->m_WorkerThreadCount; i++)
			{
			PostQueuedCompletionStatus(m_priv->m_hWorkerPort, 0, 0, NULL);
			}
		}

	m_priv->m_bConnected = false;

	gcfosdb::CloseEnvironment();
	return;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::Auth()
	{
	GCFOS_REQUEST_AUTH			auth;
	GCFOS_AUTH_RESPONSE			response;
	GCFOS_REQUEST_AUTH_2		auth_2;
	GCFOS_AUTH2_RESPONSE		response_2;
	int							ctxSize;
	int							i;
	DWORD						dwLen;
	LONG						status;
	GCFOS_REQ_TYPE				GetVer = GCFOS_REQ_GET_SERVER_VERSION;
	UINT						ClientValidation;
	TCHAR						szFilePath[MAX_PATH];

	if(m_priv->m_ClientID > 0 && gcfosdb::EnvironmentInitialized())
		{
		LoadLCUDList();
		return GCFOS_SRV_RESP_AUTH; // already authenticated
		}

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	if(!m_bSimpleAuthSuccessful)
		{
		auth.type = GCFOS_REQ_AUTH;

		EnterCriticalSection(&m_priv->m_csAccess);
		if(sendBlock(m_priv->m_srv, (char *)&auth, sizeof(auth), 0) == SOCKET_ERROR)
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			if(WSAGetLastError() == WSAECONNRESET)
				return GCFOS_SRV_RESP_SERVER_BUSY;
			else
				return GCFOS_SRV_RESP_ERROR;
			}

		if(recv(m_priv->m_srv, (char *)&response, sizeof(response), 0) == SOCKET_ERROR)
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			return GCFOS_SRV_RESP_ERROR;
			}

		// define and setup AES cipher
		ippsAESGetSize(&ctxSize);
		IppsAESSpec* pAES = (IppsAESSpec*)( new Ipp8u [ctxSize] );
		ippsAESInit(m_priv->m_SecretKey, GCFOS_SHARED_KEY_LEN, pAES, ctxSize);

		// initialize counter, which will be provided to remote end
		UINT32		counter[4];

		for(i = 0; i < 4; i++)
			{
			rand_s(&counter[i]);
			}
		memcpy(auth_2.counter, counter, 16);

		ippsAESEncryptCTR(response.challenge, auth_2.challenge_enc, GCFOS_CHALLENGE_STR_LEN, pAES, (Ipp8u*)counter, 64);

		// remove secret and release resource
		ippsAESInit(NULL, GCFOS_CHALLENGE_STR_LEN, pAES, ctxSize);
		delete [] (Ipp8u*)pAES;

		auth_2.type = GCFOS_REQ_AUTH_2;
		auth_2.client = m_priv->m_ClientID;

		if(sendBlock(m_priv->m_srv, (char *)&auth_2, sizeof(auth_2), 0) == SOCKET_ERROR)
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			if(WSAGetLastError() == WSAECONNRESET)
				return GCFOS_SRV_RESP_SERVER_BUSY;
			else
				return GCFOS_SRV_RESP_ERROR;
			}

		if(recv(m_priv->m_srv, (char *)&response_2, sizeof(response_2), 0) == SOCKET_ERROR)
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			return GCFOS_SRV_RESP_ERROR;
			}
		LeaveCriticalSection(&m_priv->m_csAccess);

		m_priv->m_LCUD_seq = response_2.seq;
		if(response_2.result != GCFOS_SRV_RESP_AUTH)
			return response_2.result;
		}
	else
		{
		response_2.result = GCFOS_SRV_RESP_AUTH;
		}

	if(sendBlock(m_priv->m_srv, (char *)&GetVer, sizeof(GetVer), 0) != sizeof(GetVer))
		{
		DEBUGLOG(("GCFOS_Client::unable to send get server version request %d\n", GetLastError()));
		closesocket(m_priv->m_srv);
		return GCFOS_SRV_RESP_ERROR;
		}
	if(recv(m_priv->m_srv, (char *)&m_priv->m_ServerVersion, sizeof(m_priv->m_ServerVersion), 0) != sizeof(m_priv->m_ServerVersion))
		{
		DEBUGLOG(("GCFOS_Client::Connect recv from get server version req failed %d\n", GetLastError()));
		closesocket(m_priv->m_srv);
		return GCFOS_SRV_RESP_ERROR;
		}
	DEBUGLOG(("GCFOS Client: Server version %u File:%u Block:%u Purging Enabled:%u Validation:%08x\n", m_priv->m_ServerVersion.Version, 
		m_priv->m_ServerVersion.FileStore, m_priv->m_ServerVersion.BlockStore, m_priv->m_ServerVersion.EnableBlockPurging, m_priv->m_ServerVersion.ServerValidation));

	m_bBlockPurgingEnabled = m_priv->m_ServerVersion.EnableBlockPurging;

	dwLen = sizeof(ClientValidation);
	status = RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_CLIENT_VALIDATION, NULL, NULL, (LPBYTE)&ClientValidation, &dwLen);
	if(status != ERROR_SUCCESS)
		{
		ClientValidation = 0;
		}

	if(ClientValidation != m_priv->m_ServerVersion.ServerValidation)
		{
		DEBUGLOG(("GCFOS_Client::Connect Server/Client validation mismatch -- deleting local cache db\n"));
		_stprintf_s(szFilePath, MAX_PATH, _T("%s\\gcfosdb.dat"), m_CachePath);
		if(!DeleteFile(szFilePath) && GetLastError() != ERROR_FILE_NOT_FOUND)
			{
			DEBUGLOG(("GCFOS_Client::Connect failed to delete %s (%u)\n", szFilePath, GetLastError()));
			return GCFOS_SRV_RESP_ERROR;
			}
		_stprintf_s(szFilePath, MAX_PATH, _T("%s\\gcfosdb.lck"), m_CachePath);
		if(!DeleteFile(szFilePath) && GetLastError() != ERROR_FILE_NOT_FOUND)
			{
			DEBUGLOG(("GCFOS_Client::Connect failed to delete %s (%u)\n", szFilePath, GetLastError()));
			return GCFOS_SRV_RESP_ERROR;
			}
		ClientValidation = m_priv->m_ServerVersion.ServerValidation;
		status = RegSetValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_CLIENT_VALIDATION, 0, REG_DWORD, (LPBYTE)&ClientValidation, sizeof(DWORD));
		if(status != ERROR_SUCCESS)
			{
			DEBUGLOG(("GCFOS_Client::Connect Failed to set client validation value %08x\n", status));
			}
		status = RegDeleteValue(m_statics->m_hKey, GCFOS_CLIENT_REG_LCUD_SEQ);
		if(status != ERROR_SUCCESS)
			{
			DEBUGLOG(("GCFOS_Client::Connect Failed to delete GCFOS_CLIENT_REG_LCUD_SEQ (%08x)\n", status));
			}
		}

	if(m_bEnableLocalCache)
		{
		gcfosdb::setBlockCacheEnabled(m_bEnableExtendedLocalBlockCache);
		if(gcfosdb::CreateEnvironment(CStringA(m_CachePath)) != 0)
			{
			return GCFOS_SRV_RESP_ERROR;
			}
		}
	else
		{
		m_bEnableLocalBlockCache = false;
		m_bEnableExtendedLocalBlockCache = false;
		}

#ifdef _WIN64
	if(m_bEnableLocalCache && m_bEnableLocalBlockCache)
		{
		if(!m_statics->m_db_blocks.open(GCFOS_CLIENT_DB_BLOCKS_NAME, 0, RTL_SIZEOF_THROUGH_FIELD(GCFOS_LOCAL_BLOCK_ENTRY, hash), FIELD_OFFSET(GCFOS_LOCAL_BLOCK_ENTRY, last_ref), sizeof(UINT16)))
			{
			DEBUGLOG(("GCFOS_Client: Failed to open blocks db\n"));
			m_bEnableLocalBlockCache = false;
			m_bEnableExtendedLocalBlockCache = false;
			}
		else
			{
			DEBUGLOG(("GCFOS_Client: Blocks in local cache: %I64u\n", m_statics->m_db_blocks.size()));
			}
		}
#else
	// LMDB being memory-mapped cannot support block-cache as it would not likely fit in address-space
	m_bEnableLocalBlockCache = false;
	m_bEnableExtendedLocalBlockCache = false;
#endif

	if(!m_bEnableLocalCache)
		{
		return response_2.result;
		}

	if(!m_statics->m_db_resident.open(GCFOS_CLIENT_DB_RESIDENT_NAME, 0, sizeof(GCFOS_LOCAL_ENTRY), 0, 0))
		{
		DEBUGLOG(("GCFOS_Client: Failed to open resident db\n"));
		closesocket(m_priv->m_srv);
		return GCFOS_SRV_RESP_ERROR;
		}
	DEBUGLOG(("GCFOS_Client: Files in resident cache: %I64u\n", m_statics->m_db_resident.size()));

	if(!m_statics->m_db_hashes.open(GCFOS_CLIENT_DB_HASH_NAME, 0, GCFOS_FILENAME_HASH_LEN, GCFOS_FILENAME_HASH_LEN, RTL_SIZEOF_THROUGH_FIELD(GCFOS_CLIENT_CACHE_ENTRY, last_ref)-GCFOS_FILENAME_HASH_LEN))
		{
		DEBUGLOG(("GCFOS_Client: Failed to open hashes db\n"));
		closesocket(m_priv->m_srv);
		return GCFOS_SRV_RESP_ERROR;
		}
	DEBUGLOG(("GCFOS_Client: Entries in hash cache: %I64u\n", m_statics->m_db_hashes.size()));

	if(!m_statics->m_db_LCUD.open(GCFOS_CLIENT_DB_LCUD_NAME, 0, sizeof(GCFOS_LOCAL_ENTRY), 0, 0))
		{
		DEBUGLOG(("GCFOS_Client: Failed to open lcud db\n"));
		closesocket(m_priv->m_srv);
		return GCFOS_SRV_RESP_ERROR;
		}
	DEBUGLOG(("GCFOS_Client: Entries in LCUD cache: %I64u\n", m_statics->m_db_LCUD.size()));

	LoadLCUDList();

	return response_2.result;
	}

bool GCFOS_PRIVATE_MEMBERS::InitializeCompression()
	{
	// Initialize compression

	if(m_uLZOsize > 0)
		return true; // already initialized

	if(ippsEncodeLZOGetSize(IppLZO1XST, GCFOS_CLIENT_SRC_BUFSIZE, &m_uLZOsize) != ippStsNoErr)
		{
		// failed
		m_uLZOsize = 0;
		return false;
		}

	m_pLZOState = (IppLZOState_8u*)ippsMalloc_8u(m_uLZOsize);

	if(ippsEncodeLZOInit_8u(IppLZO1XST, GCFOS_CLIENT_SRC_BUFSIZE, m_pLZOState) != ippStsNoErr)
		{
		// failed
		m_uLZOsize = 0;
		ippsFree(m_pLZOState);
		m_pLZOState = NULL;
		return false;
		}	

	return true;
	}

bool GCFOS_Client::RetrieveWholeFile(FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPBYTE ValidationKey)
	{
	LPBYTE			inputBuffer = NULL, decompressedBuffer = NULL;
	bool			rtn = false;
	UINT32			blks = GCFOS_OBJECT_COUNT_FOR_ENTRY(size);
	UINT32			i;
	GCFOS_REQUEST_GET_WHOLE_FILE	requestHdr;
	IppStatus		iDecompressionStatus;
	DWORD			dwWritten;
	DWORD			dwBytesToWrite;
	GCFOS_SRV_RESPONSE srvresp;
	UINT32			offset = 0;
	UINT32			totalrecd;
	INT32			expected;
	UINT32			stragglerbytes;
	LPBYTE			pHashes = NULL, curHash;
	UINT16			b;
	BYTE			hashsave[GCFOS_BLOCK_HASH_LEN];
	UINT32			*sizes = NULL;

	if(!FileStoreEnabled())
		return false;

	if(m_priv->m_bConnected == false)
		return false;

#ifdef _WIN32
	if(SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		return false;
#else
	rewind((FILE*)hFile);
#endif//_WIN32

	inputBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(inputBuffer == NULL)
		{
		goto RetrieveWholeFile_cleanup;
		}

	decompressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_DST_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(decompressedBuffer == NULL)
		{
		goto RetrieveWholeFile_cleanup;
		}

	requestHdr.type = GCFOS_REQ_GET_WHOLE_FILE;
	memcpy(&requestHdr.SHA1Bytes, SHA1, GCFOS_SHA1_LEN);
	memcpy(&requestHdr.AuthorizationKey, ValidationKey, GCFOS_VALIDATION_KEY_LEN);
	requestHdr.size = size;

	EnterCriticalSection(&m_priv->m_csAccess);
	if(sendBlock(m_priv->m_srv, (char *)&requestHdr, sizeof(requestHdr), 0) != sizeof(requestHdr))
		{
		goto RetrieveWholeFile_cleanup;
		}
	if(recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0) != sizeof(srvresp))
		{
		goto RetrieveWholeFile_cleanup;
		}
	if(srvresp == GCFOS_SRV_RESP_HASHES_AVAILABLE)
		{
		// this file is not available as file data, but rather as a chain of block-store hashes
		blks = (size / GCFOS_BLOCK_SIZE);
		expected = blks * GCFOS_BLOCK_HASH_LEN;
		if(size % GCFOS_BLOCK_SIZE > 0)
			{
			if(size % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
				{
				stragglerbytes = size % GCFOS_BLOCK_SIZE;
				expected += stragglerbytes;
				}
			else
				{
				expected += GCFOS_BLOCK_HASH_LEN;
				blks++;
				stragglerbytes = 0;
				}
			}
		else
			{
			stragglerbytes = 0;
			}
		pHashes = (LPBYTE)malloc(expected + GCFOS_BLOCK_HASH_LEN);
		if(recvBlock(m_priv->m_srv, (char *)pHashes, expected, 0) != expected)
			{
			DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to receive hashchain\n"));
			goto RetrieveWholeFile_cleanup;
			}
		totalrecd = 0;
		curHash = pHashes;
		while(blks > 0)
			{
			if(blks > GCFOS_BLOCKS_PER_QUERY)
				{
				b = GCFOS_BLOCKS_PER_QUERY;
				}
			else
				{
				b = (UINT16)blks;
				// we have to set the sentinel, but that data contains possibly the "straggler bytes"
				// so we save the existing bytes first for later restore in a little bit
				memcpy(hashsave, curHash + (GCFOS_BLOCK_HASH_LEN * b), GCFOS_BLOCK_HASH_LEN);
				memset(curHash + (GCFOS_BLOCK_HASH_LEN * b), 0, GCFOS_BLOCK_HASH_LEN);
				}
			if(!RetrieveBlocks(curHash, &b, inputBuffer))
				{
				DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to retrieve blocks\n"));
				goto RetrieveWholeFile_cleanup;
				}
			dwBytesToWrite = (b * GCFOS_BLOCK_SIZE);
			if(dwBytesToWrite + totalrecd > size)
				dwBytesToWrite = size - totalrecd;
			if(!WriteFile(hFile, inputBuffer, dwBytesToWrite, &dwWritten, NULL))
				{
				DEBUGLOG(("GCFOS_Client::RetrieveWholeFile write failed %u\n", GetLastError()));
				goto RetrieveWholeFile_cleanup;
				}
			if(dwBytesToWrite != dwWritten)
				{
				DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to write correct length %u:%u\n", dwBytesToWrite, dwWritten));
				goto RetrieveWholeFile_cleanup;
				}
			if(blks <= GCFOS_BLOCKS_PER_QUERY)
				{
				// restore data we overwrote when setting sentinel
				memcpy(curHash + (GCFOS_BLOCK_HASH_LEN * b), hashsave, GCFOS_BLOCK_HASH_LEN);
				}
			blks -= b;
			curHash += (b * GCFOS_BLOCK_HASH_LEN);
			totalrecd += dwWritten;
			if(blks == 0 && stragglerbytes > 0)
				{
				if(!WriteFile(hFile, curHash, stragglerbytes, &dwWritten, NULL))
					{
					DEBUGLOG(("GCFOS_Client::RetrieveWholeFile write failed for straggler bytes %u\n", GetLastError()));
					goto RetrieveWholeFile_cleanup;
					}
				if(stragglerbytes != dwWritten)
					{
					DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to write correct length %u:%u\n", dwBytesToWrite, dwWritten));
					goto RetrieveWholeFile_cleanup;
					}
				}
			}
		rtn = true;
		goto RetrieveWholeFile_cleanup;
		}

	if(srvresp != GCFOS_SRV_RESP_OK)
		{
		goto RetrieveWholeFile_cleanup;
		}

	// we've requested a description of all the hdrs -- now process the expected data

	sizes = new UINT32[blks];

	recvBlock(m_priv->m_srv, (char *)sizes, sizeof(INT32) * blks, 0);
	Ipp32u uncompsize;

	for(i = 0; i < blks; i++)
		{
		totalrecd = recvBlock(m_priv->m_srv, (char *)inputBuffer, sizes[i] & GCFOS_COMPRESSED_BITMASK, 0);
		if(totalrecd != (sizes[i] & GCFOS_COMPRESSED_BITMASK))
			{
			goto RetrieveWholeFile_cleanup;
			}
		if((sizes[i] & GCFOS_COMPRESSED_BIT))
			{
			//compressed block
			uncompsize = GCFOS_CLIENT_SRC_BUFSIZE;
			iDecompressionStatus = ippsDecodeLZOSafe_8u(inputBuffer, sizes[i] & GCFOS_COMPRESSED_BITMASK, decompressedBuffer, &uncompsize);
			if(iDecompressionStatus != ippStsNoErr)
				{
				goto RetrieveWholeFile_cleanup;
				}
			if(!WriteFile(hFile, decompressedBuffer, uncompsize, &dwWritten, NULL))
				{
				goto RetrieveWholeFile_cleanup;
				}
			}
		else
			{
			if(!WriteFile(hFile, inputBuffer, sizes[i], &dwWritten, NULL))
				{
				goto RetrieveWholeFile_cleanup;
				}
		}


		offset += dwWritten;
		}

	rtn = true;

RetrieveWholeFile_cleanup:
#ifdef _WIN32
	SetEndOfFile(hFile);
#endif//_WIN32
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(inputBuffer != NULL)
		{
		VirtualFree(inputBuffer, 0, MEM_RELEASE);
		}
	if(decompressedBuffer != NULL)
		{
		VirtualFree(decompressedBuffer, 0, MEM_RELEASE);
		}
	if(pHashes != NULL)
		{
		free(pHashes);
		}
	if(sizes != NULL)
		{
		delete[] sizes;
		}
	return rtn;
	}

bool GCFOS_Client::RetrieveFilePortion(BYTE const * SHA1, UINT32 size, LPBYTE ValidationKey, UINT32 offset, LPBYTE buffer, UINT32 buffersize)
	{
	// Retrieve a portion of a file from the server (nothing is written, just a buffer is returned)
	GCFOS_REQUEST_GET_FILE_PORTION			Request;
	GCFOS_SRV_RESPONSE						srvresp;
	UINT32									blks;
	INT32									expected;
	UINT32									stragglerbytes;
	LPBYTE									localbuffer;
	BYTE									localhashes[GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_HASH_LEN];
	UINT16									localhashes_size;
	UINT32									copybytes, firstblk, blkcount;

	if(!FileStoreEnabled())
		return false;
	if(m_priv->m_bConnected == false)
		return false;

	if(offset + buffersize > size || buffersize > GCFOS_RETRIEVE_FILE_MAX_PORTION_SIZE)
		return false;

	// calculate information about possible blocks now (as the actual data retrieved may be cached)
	blks = (size / GCFOS_BLOCK_SIZE);
	expected = blks * GCFOS_BLOCK_HASH_LEN;
	if(size % GCFOS_BLOCK_SIZE > 0)
		{
		if(size % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			stragglerbytes = size % GCFOS_BLOCK_SIZE;
			expected += stragglerbytes;
			}
		else
			{
			expected += GCFOS_BLOCK_HASH_LEN;
			blks++;
			stragglerbytes = 0;
			}
		}
	else
		{
		stragglerbytes = 0;
		}

	if(m_priv->m_SaveSize != size
	|| memcmp(m_priv->m_SaveSHA1, SHA1, GCFOS_SHA1_LEN) != 0
	|| memcmp(m_priv->m_SaveValidationKey, ValidationKey, GCFOS_VALIDATION_KEY_LEN) != 0)
		{
		// this is a request on a DIFFERENT file than last time, so we need to get the new details
		// about this new file
		Request.type = GCFOS_REQ_GET_FILE_PORTION;
		memcpy(Request.AuthorizationKey, ValidationKey, GCFOS_VALIDATION_KEY_LEN);
		Request.Offset = offset;
		Request.Length = buffersize;
		memcpy(Request.SHA1Bytes, SHA1, GCFOS_SHA1_LEN);
		Request.size = size;
	
		EnterCriticalSection(&m_priv->m_csAccess);

		if(sendBlock(m_priv->m_srv, (char *)&Request, sizeof(Request), 0) != sizeof(Request))
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			return false;
			}
		if(recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0) != sizeof(srvresp))
			{
			LeaveCriticalSection(&m_priv->m_csAccess);
			return false;
			}
		if(srvresp == GCFOS_SRV_RESP_HASHES_AVAILABLE)
			{
			// this file is not available as file data, but rather as a chain of block-store hashes
			// note: extra bit at end is for possible sentinel
			if(m_priv->m_HashChainSize < expected + GCFOS_BLOCK_HASH_LEN)
				{
				if(m_priv->m_pHashChain != NULL)
					{
					VirtualFree(m_priv->m_pHashChain, 0, MEM_RELEASE);
					}
				m_priv->m_HashChainSize = expected + GCFOS_BLOCK_HASH_LEN;
				m_priv->m_pHashChain = (LPBYTE)VirtualAlloc(NULL, m_priv->m_HashChainSize,  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				}
			if(recvBlock(m_priv->m_srv, (char *)m_priv->m_pHashChain, expected, 0) != expected)
				{
				DEBUGLOG(("GCFOS_Client::RetrieveFilePortion failed to receive hashchain\n"));
				LeaveCriticalSection(&m_priv->m_csAccess);
				return false;
				}
			m_priv->m_SaveSize = size;
			memcpy(m_priv->m_SaveSHA1, SHA1, GCFOS_SHA1_LEN);
			memcpy(m_priv->m_SaveValidationKey, ValidationKey, GCFOS_VALIDATION_KEY_LEN);

			LeaveCriticalSection(&m_priv->m_csAccess);
			}
		else
			{
			if(srvresp != GCFOS_SRV_RESP_OK)
				{
				return false;
				}
			// this is likely a normal (non-hashchain) common file -- the server will 
			// send the file-data uncompressed directly to us
			if(recvBlock(m_priv->m_srv, (char *)buffer, (INT32)buffersize, 0) != (INT32)buffersize)
				{
				DEBUGLOG(("GCFOS_Client::RetrieveFilePortion failed to receive file data from server\n"));
				LeaveCriticalSection(&m_priv->m_csAccess);
				return false;
				}
			LeaveCriticalSection(&m_priv->m_csAccess);
			return true;
			}
		}

	// at this point we have the correct hashchain loaded
	localbuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_MAX_BLOCK_SIZE,  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
	localhashes_size = 0;
	while(buffersize > 0)
		{
		firstblk = offset / GCFOS_BLOCK_SIZE;
		blkcount = (offset % GCFOS_BLOCK_SIZE + buffersize + (GCFOS_BLOCK_SIZE - 1)) / GCFOS_BLOCK_SIZE;
		if(blkcount > GCFOS_BLOCKS_PER_QUERY)
			blkcount = GCFOS_BLOCKS_PER_QUERY;

		copybytes = buffersize;
		if(stragglerbytes > 0 && (offset + buffersize) > (blks * GCFOS_BLOCK_SIZE))
			{
			if((blks * GCFOS_BLOCK_SIZE) > offset)
				copybytes = (blks * GCFOS_BLOCK_SIZE) - offset;
			else
				copybytes = 0;
			}
		if(firstblk + blkcount > blks)
			{
			blkcount = blks - firstblk;
			}
		if(copybytes == 0)
			{
			// just stragglers remain
			copybytes = stragglerbytes;
			if(copybytes > buffersize)
				copybytes = buffersize;
			memcpy(buffer, m_priv->m_pHashChain + (blks * GCFOS_BLOCK_HASH_LEN) + (offset - (GCFOS_BLOCK_SIZE * blks)), copybytes);
			buffersize -= copybytes;
			assert(buffersize == 0);
			VirtualFree(localbuffer, 0, MEM_RELEASE);
			return true;
			}

		memcpy(localhashes, m_priv->m_pHashChain + (firstblk * GCFOS_BLOCK_HASH_LEN), blkcount * GCFOS_BLOCK_HASH_LEN);
		if(blkcount < GCFOS_BLOCKS_PER_QUERY)
			{
			memset(localhashes + (blkcount * GCFOS_BLOCK_HASH_LEN), 0, GCFOS_BLOCK_HASH_LEN);
			}
		if(!RetrieveBlocks(localhashes, &localhashes_size, localbuffer))
			{
			DEBUGLOG(("GCFOS_Client::RetrieveFilePortion failed to retrieve blocks from server\n"));
			VirtualFree(localbuffer, 0, MEM_RELEASE);
			return false;
			}
		memcpy(buffer, localbuffer + offset - (firstblk * GCFOS_BLOCK_SIZE), copybytes);
		buffer += copybytes;
		buffersize -= copybytes;
		offset += copybytes;
		}
	VirtualFree(localbuffer, 0, MEM_RELEASE);
	return true;
	}

bool GCFOS_Client::RetrieveWholeFile(BYTE const * SHA1, UINT32 size, LPCTSTR filename, LPBYTE ValidationKey)
	{
	FILEHANDLE		hFile = INVALID_HANDLE_VALUE;
	bool			rtnval;

	if(!FileStoreEnabled())
		return false;
#ifdef _WIN32
	hFile = CreateFile(filename, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_NEW, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to create file %S, error %u\n", filename, GetLastError()));
		return false;
		}
#else
	hFile = fopen(filename, "wb");
	if(hFile == NULL)
		{
		DEBUGLOG(("GCFOS_Client::RetrieveWholeFile failed to create file %s, error %u\n", filename, GetLastError()));
		return false;
		}
#endif//_WIN32
	rtnval = RetrieveWholeFile(hFile, SHA1, size, ValidationKey);
	CloseHandle(hFile);
	return rtnval;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::RegisterNewClient(PUINT32 newid, LPBYTE sharedkey)
	{
	GCFOS_REQUEST_ADD_CLIENT		req;
	GCFOS_CLIENT_INFO				response;
	DWORD							dwLen;

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	if(m_priv->m_ClientID != 1)
		return GCFOS_SRV_RESP_NOTAUTH;

	req.type = GCFOS_REQ_ADD_CLIENT;

	EnterCriticalSection(&m_priv->m_csAccess);

	dwLen = sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0);
	if(dwLen != sizeof(req))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		return GCFOS_SRV_RESP_ERROR;
		}

	dwLen = recvBlock(m_priv->m_srv, (char *)&response, sizeof(response), 0);
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(dwLen != sizeof(response))
		return GCFOS_SRV_RESP_ERROR;

	*newid = response.client_id;
	memcpy(sharedkey, &response.shared_key, GCFOS_SHARED_KEY_LEN);

	return GCFOS_SRV_RESP_OK;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::GetClientDetails(UINT32 id, PUCHAR sharedkey)
	{
	GCFOS_REQUEST_GET_CLIENT		req;
	DWORD							dwLen;
	GCFOS_CLIENT_INFO				response;

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	if(m_priv->m_ClientID != 1)
		return GCFOS_SRV_RESP_NOTAUTH;

	req.type = GCFOS_REQ_GET_CLIENT;
	req.client_id = id;
	EnterCriticalSection(&m_priv->m_csAccess);
	dwLen = sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0);
	if(dwLen != sizeof(req))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		return GCFOS_SRV_RESP_ERROR;
		}

	dwLen = recvBlock(m_priv->m_srv, (char *)&response, sizeof(response), 0);
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(dwLen != sizeof(response))
		return GCFOS_SRV_RESP_ERROR;

	if(response.client_id == 0)
		// not found
		return GCFOS_SRV_RESP_ERROR;

	memcpy(sharedkey, &response.shared_key, GCFOS_SHARED_KEY_LEN);
	return GCFOS_SRV_RESP_OK;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::DeleteClient(UINT32 id)
	{
	GCFOS_REQUEST_DELETE_CLIENT		req;
	GCFOS_SRV_RESPONSE				result;
	DWORD							dwLen;

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	if(m_priv->m_ClientID != 1)
		return GCFOS_SRV_RESP_NOTAUTH;

	req.type = 	GCFOS_REQ_DELETE_CLIENT;
	req.client_id = id;

	EnterCriticalSection(&m_priv->m_csAccess);
	dwLen = sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0);
	if(dwLen != sizeof(req))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		return GCFOS_SRV_RESP_ERROR;
		}

	dwLen = recv(m_priv->m_srv, (char *)&result, sizeof(result), 0);
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(dwLen != sizeof(result))
		return GCFOS_SRV_RESP_ERROR;

	return result;
	}


bool GCFOS_Client::ContributeFile(LPCTSTR filename, BYTE const * SHA1, UINT32 size, UCHAR flags /* = 0*/)
	{
	FILEHANDLE		hFile = INVALID_HANDLE_VALUE;
	bool			result;

	if(!FileStoreEnabled())
		return false;

	if(m_priv->m_bConnected == false)
		return false;

	if(m_priv->m_bUBDR)
		return false; // UBDR clients not allowed to get contribute

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		return false;
		}
	
	result = ContributeFileByHandle(hFile, SHA1, size, filename, flags);

	CloseHandle(hFile);
	return result;
	}

// This internal function sends all the individual blocks that comprise a common file and sends them
// to the server for storage, then sends the list of all the hashes that comprise the file
// There may be a "remainder" block to affix to the hash chain if the last block is smaller than
// GCFOS_MINIMUM_BLOCK_SIZE

bool GCFOS_Client::GenerateBlockHashChain(GCFOS_REQUEST_CONTRIBUTE_FILE *pReqContributeFile, FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPCTSTR filename)
	{
	LPBYTE			hashBuffer = NULL;
	LPBYTE			inputBuffer = NULL;
	UINT32			hashBufferSize = ((size / GCFOS_BLOCK_SIZE) + 1) * GCFOS_BLOCK_HASH_LEN + GCFOS_MINIMUM_BLOCK_SIZE;
	LPBYTE			pHash;
	UINT32			s = size;
	bool			rtn = false;
	DWORD			dwRead;
	int				databytesready = 0;
	GCFOS_SRV_RESPONSE srvresp;
	UINT16			blks;
	UINT32			stragglerbytes;
	UINT32			hashsizes;
	UINT32			totalread = 0;
	INT32			sendlen;
	GCFOS_LOCAL_ENTRY localResidentEntry;
	MDB_txn			*txn;
	int				rc;

	hashBuffer = (LPBYTE)VirtualAlloc(NULL, hashBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(hashBuffer == NULL)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain -- malloc of hashBuffer failed %u\n", GetLastError()));
		goto GenerateBlockHashChain_cleanup;
		}

	inputBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_MAX_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(inputBuffer == NULL)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain -- malloc of inputBuffer failed %u\n", GetLastError()));
		goto GenerateBlockHashChain_cleanup;
		}

	pHash = hashBuffer;

	while(s > 0)
		{
		if(!ReadFile(hFile, inputBuffer, GCFOS_MAX_BLOCK_SIZE, &dwRead, NULL))
			{
			DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain failed to read file: %u\n", GetLastError()));
			goto GenerateBlockHashChain_cleanup;
			}
		if(dwRead == 0)
			break;// end of file

		s -= dwRead;
		totalread += dwRead;
		blks = (UINT16)(dwRead / GCFOS_BLOCK_SIZE);
		stragglerbytes = dwRead - (blks * GCFOS_BLOCK_SIZE);
		if(stragglerbytes > 0 && stragglerbytes < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			// remove the straggler bytes from the store operation
			dwRead -= stragglerbytes;
			// this is the last block of data that will be read
			}
		if(dwRead > 0)
			{
			if(!StoreBlocks(inputBuffer, dwRead, pHash, &hashsizes))
				{
				DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain failed to store blocks\n"));
				goto GenerateBlockHashChain_cleanup;
				}
			pHash += hashsizes;
			}
		if(stragglerbytes > 0 && stragglerbytes < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			memcpy(pHash, inputBuffer + (blks * GCFOS_BLOCK_SIZE), stragglerbytes);
			pHash += stragglerbytes;
			}
		assert((UINT32)(pHash - hashBuffer) < hashBufferSize);
		}
	// sanity check
	if(totalread != size)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain invalid size read: %x (expected %x)\n", totalread, size));
		goto GenerateBlockHashChain_cleanup;
		}

	sendlen	= FIELD_OFFSET(GCFOS_REQUEST_CONTRIBUTE_FILE, filename) + pReqContributeFile->filenamelen;
	pReqContributeFile->flags |= GCFOS_REQUEST_CONTRIBUTE_FILE_FLAG_HASHCHAIN;

	EnterCriticalSection(&m_priv->m_csAccess);
	if(sendBlock(m_priv->m_srv, (char *)pReqContributeFile, sendlen, 0) != sendlen)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain -- sendBlock pReqContributeFile failed %u\n", WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		goto GenerateBlockHashChain_cleanup;
		}

	if(recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0) != sizeof(srvresp)
	|| srvresp != GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain -- recvBlock srvresp failed %u\n", WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		goto GenerateBlockHashChain_cleanup;
		}

	sendlen = (UINT32)(pHash - hashBuffer);
	if(sendBlock(m_priv->m_srv, (char *)hashBuffer, sendlen, 0) != sendlen)
		{
		DEBUGLOG(("GCFOS_Client::GenerateBlockHashChain -- sendBlock pHash failed %u\n", WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		goto GenerateBlockHashChain_cleanup;
		}

	LeaveCriticalSection(&m_priv->m_csAccess);

	rtn = true;

	if(!m_bEnableLocalCache)
		goto GenerateBlockHashChain_cleanup;

	memcpy(&localResidentEntry.SHA1, SHA1, GCFOS_SHA1_LEN);
	localResidentEntry.size = size;
	rc = gcfosdb::BeginTxn(&txn);
	if(rc == 0)
		{
		m_statics->m_db_resident.insert(&localResidentEntry, &txn);
		m_priv->m_locallyAdded++;
		rc = gcfosdb::CommitTxn(&txn);
		if(rc != 0)
			{
			DEBUGLOG(("GCOFS_Client::GenerateBlockHashChain unable to commit to resident cache, %d", rc));
			if(txn != NULL)
				{
				gcfosdb::AbortTxn(txn);
				}
			}
		}
	else
		{
		DEBUGLOG(("GCOFS_Client::GenerateBlockHashChain unable to begin txn, %d", rc));
		}

GenerateBlockHashChain_cleanup:
	if(inputBuffer != NULL)
		{
		VirtualFree(inputBuffer, 0, MEM_RELEASE);
		}
	if(hashBuffer != NULL)
		{
		VirtualFree(hashBuffer, 0, MEM_RELEASE);
		}
	if(rtn == false)
		{
		// there might be some trailing data (SRV RESP), discard
		WSAIoctl(m_priv->m_srv, FIONREAD, NULL, 0, &databytesready, sizeof(databytesready), &dwRead, NULL, NULL);
		if(dwRead == sizeof(databytesready) && databytesready > 0)
			{
			recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0);
			}
		}
	free(pReqContributeFile);
	return rtn;
	}

bool GCFOS_Client::ContributeFileByHandle(FILEHANDLE hFile, BYTE const * SHA1, UINT32 size, LPCTSTR filename, UCHAR flags /* = 0*/) 
	{
//	HANDLE cannot be OVERLAPPED because BackupRead/Write require a file to be opened
//  without overlapped IO.

	IppStatus		iCompressionStatus;
	DWORD			dwRead;
	LPBYTE			inputBuffer=NULL, compressedBuffer=NULL;
	bool			rtn = false;
	bool			bCompressible=true; // assume that file is compressible
	Ipp32u			compressedSize=0;
	PGCFOS_REQUEST_CONTRIBUTE_FILE pReqContributeFile = NULL;
	UINT32			ReqContributeFileLen;
	UINT32			SendLen;
	size_t			filenamelen, deststrlen;
	GCFOS_REQUEST_DATABLOCK hdr;
	UINT64			fileoffset;
	GCFOS_SRV_RESPONSE srvresp;
	GCFOS_LOCAL_ENTRY localResidentEntry;
	int				databytesready = 0;
	DWORD			dwLen;
	bool			bAquiredCriticalSection = false;
	int				rc;
	MDB_txn			*txn;

	if(!FileStoreEnabled())
		return false;

	if(m_priv->m_bConnected == false)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- not connected\n"));
		return false;
		}

	if(m_priv->m_bUBDR)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- UBDR client denied\n"));
		return false; // UBDR clients not allowed to get contribute
		}

#ifdef _WIN32
	if(SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- failed to set file ptr\n", GetLastError()));
		return false;
		}
#else
	rewind((FILE*)hFile);
#endif//_WIN32

	if(filename != NULL)
		{
		filenamelen = _tcslen(filename);
		ReqContributeFileLen = (UINT32)(FIELD_OFFSET(GCFOS_REQUEST_CONTRIBUTE_FILE, filename) + (filenamelen * 2));
		pReqContributeFile = (PGCFOS_REQUEST_CONTRIBUTE_FILE)malloc(ReqContributeFileLen);
		if(pReqContributeFile == NULL)
			{
			DEBUGLOG(("ContributeFileByHandle: malloc failed\n"));
			return false;
			}
		memset(pReqContributeFile, 0, ReqContributeFileLen);
#ifdef _UNICODE
		if(0 != wcstombs_s(&deststrlen, pReqContributeFile->filename, (filenamelen * 2), filename, filenamelen))
			{
			pReqContributeFile->filenamelen = 0;
			}
		else
			{
			pReqContributeFile->filenamelen = (UINT16)(deststrlen - 1); // do not include null terminator in length
			}
#else
		strcpy(pReqContributeFile->filename, filename);
#endif//_UNICODE
		}
	else
		{
		ReqContributeFileLen = (UINT32)(FIELD_OFFSET(GCFOS_REQUEST_CONTRIBUTE_FILE, filename));
		pReqContributeFile = (PGCFOS_REQUEST_CONTRIBUTE_FILE)malloc(ReqContributeFileLen);
		if(pReqContributeFile == NULL)
			{
			DEBUGLOG(("ContributeFileByHandle: malloc failed\n"));
			return false;
			}
		memset(pReqContributeFile, 0, ReqContributeFileLen);
		pReqContributeFile->filenamelen = 0;
		}
	pReqContributeFile->flags = flags;
	memcpy(&pReqContributeFile->SHA1Bytes, SHA1, GCFOS_SHA1_LEN);
	pReqContributeFile->size = size;
	pReqContributeFile->type = GCFOS_REQ_CONTRIBUTE_FILE;

	if(BlockStoreEnabled())
		return GenerateBlockHashChain(pReqContributeFile, hFile, SHA1, size, filename);

	SendLen	= FIELD_OFFSET(GCFOS_REQUEST_CONTRIBUTE_FILE, filename) + pReqContributeFile->filenamelen;

	inputBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_SRC_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(inputBuffer == NULL)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- malloc of inputBuffer failed %u\n", GetLastError()));
		goto ContributeFile_cleanup;
		}

	compressedBuffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_CLIENT_DST_BUFSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(compressedBuffer == NULL)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- malloc of compressedBuffer failed %u\n", GetLastError()));
		goto ContributeFile_cleanup;
		}

	EnterCriticalSection(&m_priv->m_csAccess);
	bAquiredCriticalSection = true;
	if(sendBlock(m_priv->m_srv, (char *)pReqContributeFile, SendLen, 0) != (int)SendLen)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- sendBlock pReqContributeFile failed %u\n", WSAGetLastError()));
		goto ContributeFile_cleanup;
		}

	if(recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0) != sizeof(srvresp)
	|| srvresp != GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- recvBlock srvresp failed %u\n", WSAGetLastError()));
		goto ContributeFile_cleanup;
		}

	memset(&hdr, 0, sizeof(hdr));
	hdr.type = GCFOS_REQ_CONTRIBUTE_DATABLOCK; // this is static, always needs to be this value (to stop it being interpreted as a different operation)

	// Once we fail to compress a block, no other attempts will be made to compress data. Since we are processing blocks 1MB
	// at a time, it's really unlikely that a file will contain uncompressible and compressible data in the same file
	// therefore it is more efficient to not attempt compression of future blocks.
	fileoffset = 0;
	while(true)
		{
		if(!ReadFile(hFile, inputBuffer, GCFOS_CLIENT_SRC_BUFSIZE, &dwRead,NULL))
			{
			break;
			}
		if(dwRead == 0)
			break; // all data read from file

		if(bCompressible)
			{
			compressedSize = GCFOS_CLIENT_DST_BUFSIZE;
			iCompressionStatus = ippsEncodeLZO_8u(inputBuffer, dwRead, compressedBuffer, &compressedSize, m_priv->m_pLZOState);
			if(iCompressionStatus != ippStsNoErr || compressedSize >= dwRead)
				{
				bCompressible = false;
				}
			}

		hdr.uncompSize = dwRead;
		if(bCompressible)
			{
			hdr.blocksize =	compressedSize | GCFOS_COMPRESSED_BIT;
			if(sendBlock(m_priv->m_srv, (char *)&hdr, sizeof(hdr), 0) != sizeof(hdr))
				{
				DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- sendBlock hdr failed %u\n", WSAGetLastError()));
				goto ContributeFile_cleanup;
				}
			if(sendBlock(m_priv->m_srv, (char *)compressedBuffer, compressedSize, 0) != (int)compressedSize)
				{
				DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- recvBlock compressedBuffer failed %u\n", WSAGetLastError()));
				goto ContributeFile_cleanup;
				}
			}
		else
			{
			hdr.blocksize = dwRead;
			if(sendBlock(m_priv->m_srv, (char *)&hdr, sizeof(hdr), 0) != sizeof(hdr))
				{
				DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- sendBlock hdr2 failed %u\n", WSAGetLastError()));
				goto ContributeFile_cleanup;
				}
			if(sendBlock(m_priv->m_srv, (char *)inputBuffer, dwRead, 0) != (int)dwRead)
				{
				DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- recvBlock inputBuffer failed %u\n", WSAGetLastError()));
				goto ContributeFile_cleanup;
				}
			}
		fileoffset += dwRead;

		if(fileoffset == size)
			break; // all done
		}

	if(recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0) != sizeof(srvresp)
	|| srvresp != GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG(("GCFOS_Client::ContributeFileByHandle -- recvBlock inputBuffer failed %u\n", WSAGetLastError()));
		goto ContributeFile_cleanup;
		}

	if(m_bEnableLocalCache)
		{
		memcpy(&localResidentEntry.SHA1, SHA1, GCFOS_SHA1_LEN);
		localResidentEntry.size = size;
		rc = gcfosdb::BeginTxn(&txn);
		if(rc == 0)
			{
			m_statics->m_db_resident.insert(&localResidentEntry, &txn);
			m_priv->m_locallyAdded++;
			rc = gcfosdb::CommitTxn(&txn);
			if(rc != 0)
				{
				DEBUGLOG(("GCOFS_Client::ContributeFile unable to commit to resident cache, %d", rc));
				if(txn != NULL)
					{
					gcfosdb::AbortTxn(txn);
					}
				}
			}
		else
			{
			DEBUGLOG(("GCOFS_Client::ContributeFile unable to begin txn, %d", rc));
			}
		}

	rtn = true;

ContributeFile_cleanup:
	if(rtn == false)
		{
		// there might be some trailing data (SRV RESP), discard
		WSAIoctl(m_priv->m_srv, FIONREAD, NULL, 0, &databytesready, sizeof(databytesready), &dwLen, NULL, NULL);
		if(dwLen == sizeof(databytesready) && databytesready > 0)
			{
			recvBlock(m_priv->m_srv, (char *)&srvresp, sizeof(srvresp), 0);
			}
		}
	if(bAquiredCriticalSection)
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		}
	if(inputBuffer != NULL)
		{
		VirtualFree(inputBuffer, 0, MEM_RELEASE);
		}
	if(compressedBuffer != NULL)
		{
		VirtualFree(compressedBuffer, 0, MEM_RELEASE);
		}
	if(pReqContributeFile)
		{
		free(pReqContributeFile);
		}

	return rtn;
	}

 GCFOS_SRV_RESPONSE GCFOS_Client::DeleteObject(BYTE const * SHA1, UINT32 size, UCHAR flags)
	{
	GCFOS_REQUEST_CONTRIBUTE_FILE	req;
	GCFOS_LOCAL_ENTRY				residentEntry;
	DWORD							dwLen;
	GCFOS_SRV_RESPONSE				result;
	int								rc;
	MDB_txn							*txn;

	if(m_priv->m_bConnected == false)
		return GCFOS_SRV_RESP_NOT_CONNECTED;

	memset(&req, 0, sizeof(req));

	req.type = GCFOS_REQ_DELETE_OBJECT;
	req.flags = flags;
	memcpy(&req.SHA1Bytes, SHA1, GCFOS_SHA1_LEN);
	req.size = size;

	if(m_bEnableLocalCache)
		{
		rc = gcfosdb::BeginTxn(&txn);
		if(rc != 0)
			{
			DEBUGLOG(("GCFOS_Client::DeleteObject failed to begin new txn, %d\n", rc));
			return GCFOS_SRV_RESP_CLIENT_ERROR;
			}
		memcpy(&residentEntry.SHA1, &req.SHA1Bytes, GCFOS_SHA1_LEN);
		residentEntry.size = req.size;
		rc = m_statics->m_db_resident.erase(&residentEntry, &txn);
		if(rc == 0)
			{
			rc = gcfosdb::CommitTxn(&txn);
			if(rc == MDB_MAP_FULL)
				{
				m_statics->m_db_resident.erase(&residentEntry, &txn);
				rc = gcfosdb::CommitTxn(&txn);
				}
			else if(rc != 0)
				{
				gcfosdb::AbortTxn(txn);
				}
			}
		else
			{
			gcfosdb::AbortTxn(txn);
			}
		if(rc != 0)
			{
			DEBUGLOG(("GCFOS_Client::DeleteObject failed to erase resident entry, %d\n", rc));
			}
		}
	
	EnterCriticalSection(&m_priv->m_csAccess);
	dwLen = sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0);
	if(dwLen != sizeof(req))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		return GCFOS_SRV_RESP_ERROR;
		}

	dwLen = recvBlock(m_priv->m_srv, (char *)&result, sizeof(result), 0);
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(dwLen != sizeof(result))
		return GCFOS_SRV_RESP_ERROR;

	return result;
	}

void GCFOS_Client::GetSessionInfo(PGCFOS_CLIENT_SESSIONINFO info)
	{
	if(info == NULL)
		return;

	info->locallyAdded = m_priv->m_locallyAdded;
	info->locallyResidentHits = m_priv->m_locallyResidentHits;
	info->UniqueHits = m_priv->m_UniqueHits;
	info->SHA1Hits = m_priv->m_SHA1Hits;
	info->SHA1Misses = m_priv->m_SHA1Misses;
	if(m_bEnableLocalCache)
		{
		info->Resident = m_statics->m_db_resident.size();
		info->Unique = m_statics->m_db_LCUD.size();
		}
	else
		{
		info->Resident = 0;
		info->Unique = 0;
		}

	info->TotalQueryTime = (double)(m_priv->m_QueryTime) / (double)m_statics->liCounterFreq.QuadPart;
	info->ServerQueries = m_priv->m_Queries;
	info->BlocksQueried = m_priv->m_BlkQueries;
	info->BlocksStored = m_priv->m_BlkStores;
	info->BlocksHitCache = m_priv->m_BlkCacheHit;
	info->TotalBlockQueryTime = (double)(m_priv->m_BlkQueryTime) / (double)m_statics->liCounterFreq.QuadPart;
	info->TotalBlockStoreTime = (double)(m_priv->m_BlkStoreTime) / (double)m_statics->liCounterFreq.QuadPart;
	}

GCFOS_SRV_RESPONSE GCFOS_Client::ProvideFileName(LPCTSTR path, BYTE const * SHA1, UINT32 size)
	{
	GCFOS_REQUEST_PROVIDE_FILENAME		req;
	size_t								pathlen = _tcslen(path);
	size_t								adj;
	UINT32								i;
	GCFOS_SRV_RESPONSE					result;
	DWORD								dwLen;

	if(path == NULL)
		return GCFOS_SRV_RESP_ERROR;

	if(pathlen > GCFOS_MAX_FILENAME_LEN)
		{
		// adjust the pointer to only copy the last GCFOS_MAX_FILENAME_LEN chars
		// of the filename
		adj = (pathlen - GCFOS_MAX_FILENAME_LEN);
		path += adj;
		pathlen -= adj;
		}
	for(i = 0; *path; i++, path++)
		{
		// convert to ANSI
		req.filename[i] = (CHAR)*path;
		}
	req.filename[i] = 0;
		
	memcpy(req.SHA1Bytes, SHA1, GCFOS_SHA1_LEN);
	req.size = size;
	req.type = GCFOS_REQ_PROVIDE_FILENAME;
	// send the info to server, no response back expected
	EnterCriticalSection(&m_priv->m_csAccess);
	if(sendBlock(m_priv->m_srv, (char *)&req, sizeof(req), 0) != sizeof(req))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		return GCFOS_SRV_RESP_ERROR;
		}

	dwLen = recvBlock(m_priv->m_srv, (char *)&result, sizeof(result), 0);
	LeaveCriticalSection(&m_priv->m_csAccess);
	if(dwLen != sizeof(result))
		return GCFOS_SRV_RESP_ERROR;

	return result;
	}

bool GCFOS_Client::LoadLCUDList()
	{
	GCFOS_LOCAL_ENTRY			entry;
	int							i;
	UINT32						count = 0;
	UINT32						currentSeq = GCFOS_LCUD_NOT_PRESENT; // invalid value
	GCFOS_LCUD_REQUEST			lcudReq;
	UINT64						entriesExpected;
	int							rc;
	MDB_txn						*txn;
	DWORD						dwType;
	DWORD						dwLen;

	if(!m_bEnableLocalCache)
		{
		DEBUGLOG(("LoadLCUDList: cache not enabled\n"));
		return false;
		}

	DEBUGLOG(("LoadLCUDList: %u entries\n", m_statics->m_db_LCUD.size()));

	if(m_statics->m_hKey == NULL)
		{
		DEBUGLOG(("LoadLCUDList: invalid reg key\n"));
		return false;
		}

	if(m_statics->m_db_LCUD.size() == 0)
		{
		DEBUGLOG(("LoadLCUDList: Empty local LCUD -- resetting\n"));
		currentSeq = GCFOS_LCUD_NOT_PRESENT; // invalid value
		}
	else
		{
		dwLen = sizeof(DWORD);
		if(ERROR_SUCCESS != RegQueryValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_LCUD_SEQ, NULL, &dwType, (LPBYTE)&currentSeq, &dwLen) || dwType != REG_DWORD)
			{
			currentSeq = GCFOS_LCUD_NOT_PRESENT; // invalid value
			}
		}

	if(currentSeq == GCFOS_LCUD_NOT_PRESENT)
		{
		if(m_priv->m_LCUD_seq == 0)
			{
			DEBUGLOG(("LoadLCUDList: No LCUD available on server, exiting normally\n"));
			return true;
			}
		currentSeq = 0;
		}
	else
		{
		if(m_priv->m_LCUD_seq <= currentSeq)
			{
			// Nothing more to do, we're up-to-date with our current received 
			DEBUGLOG(("LoadLCUDList: Current at %u\n", currentSeq));
			return true;
			}
		}

	DEBUGLOG(("LoadLCUDList: Requesting lcud updates from server (currently at: %u)\n", currentSeq));
	// request updates from server for the local-unique entries for this client

	while(true)
		{
		count = 0;

		memset(&lcudReq, 0, sizeof(GCFOS_LCUD_REQUEST));
		lcudReq.type = GCFOS_REQ_LCUD_REQ;
		lcudReq.MySequenceNo = currentSeq;
		if(sendBlock(m_priv->m_srv, (char *)&lcudReq, sizeof(lcudReq)) == SOCKET_ERROR)
			{
			DEBUGLOG(("LoadLCUDList: send failed\n"));
			return false;
			}
		if(recvBlock(m_priv->m_srv, (char *)&entriesExpected, sizeof(UINT64), 0) == SOCKET_ERROR)
			{
			DEBUGLOG(("LoadLCUDList: recv failed\n"));
			return false;
			}
		if(entriesExpected == 0)
			{
			DEBUGLOG(("LoadLCUDList: No LCUD entries available for this client, exiting\n"));
			return true;
			}

		DEBUGLOG(("LoadLCUDList: Requesting %I64u updates from server\n", entriesExpected));

		rc = gcfosdb::BeginTxn(&txn);
		if(rc != 0)
			{
			DEBUGLOG(("LoadLCUDList: failed to begin txn, %d\n", rc));
			break;
			}

		rc = 0;
		while(entriesExpected)
			{
			i = recvBlock(m_priv->m_srv, (char *)&entry, sizeof(entry));
			if(i != sizeof(entry))
				break; // error
			if(rc != 0)
				{
				// we're in an error-state -- don't attempt insert (we likely have to start over again)
				entriesExpected--;
				continue;
				}
			rc = m_statics->m_db_LCUD.insert(&entry, &txn, 0, true, gcfosdb_NOOVERWRITE);
			if(rc != 0)
				{
				if(rc != MDB_KEYEXIST)
					{
					DEBUGLOG(("LoadLCUDList: failed to insert to LCUD, %d\n", rc));
					// we cannot abort yet -- discard all other receipts from server
					// and do not commmit txn later
					}
				else
					{
					rc = 0;
					}
				}
			else
				{
				count++;
				}
			entriesExpected--;
			}

		if(rc == MDB_MAP_FULL)
			{
			continue; // retry from beginning
			}
		if(rc != 0)
			{
			gcfosdb::AbortTxn(txn);
			break;
			}

		rc = gcfosdb::CommitTxn(&txn);
		if(rc == MDB_MAP_FULL)
			{
			continue; // retry from beginning
			}
		break;
		}

	if(entriesExpected)
		{
		DEBUGLOG(("LoadLCUDList: Error receiving lcud updates from server\n"));
		}
	else
		{
		DEBUGLOG(("LoadLCUDList: Added all entries, new total = %u\n", m_statics->m_db_LCUD.size()));
		}

	if(rc != 0)
		{
		DEBUGLOG(("LoadLCUDList: abandoning update\n"));
		}
	else
		{
		if(ERROR_SUCCESS != RegSetValueEx(m_statics->m_hKey, GCFOS_CLIENT_REG_LCUD_SEQ, NULL, REG_DWORD, (LPBYTE)&m_priv->m_LCUD_seq, sizeof(DWORD)))
			{
			DEBUGLOG(("LoadLCUDList: Failed to set registry value for current seq# %u\n", GetLastError()));
			return false;
			}
		}

	DEBUGLOG(("LoadLCUDList: Exiting\n"));
	return true;
	}

bool GCFOS_Client::GenerateHashForFile(LPCTSTR filename, LPBYTE SHA1, UINT32 expectedsize, LPBYTE ValidationKey)
	{
	FILEHANDLE			hFile;
	bool				rtnval;

	if(!FileStoreEnabled())
		return false;

	if(m_priv->m_bUBDR)
		return false; // UBDR clients not allowed to get hash

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		return false;
		}
	rtnval = GenerateHashForHandle(hFile, SHA1, expectedsize, ValidationKey);
	CloseHandle(hFile);
	return rtnval;
	}

bool GCFOS_Client::GenerateHashForHandle(FILEHANDLE hFile, LPBYTE SHA1, UINT32 expectedsize, LPBYTE ValidationKey)
	{
	const int buffersize = 0x8000;

	int					ctxSize;
	IppsHashState*		ctx1;
	DWORD				dwLen;
	Ipp8u				buffer[buffersize];
	DWORD				dwRead = 0;
	DWORD				dwPos;
	if(m_priv->m_ClientID == 0)
		return false;

	if(m_priv->m_bUBDR)
		return false; // UBDR clients not allowed to get hash

	ippsHashGetSize(&ctxSize);
	ctx1=(IppsHashState*)( new Ipp8u [ctxSize]);
	ippsHashInit(ctx1, IPP_ALG_HASH_SHA1);

#ifdef _WIN32
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
#else
	rewind((FILE*)hFile);
#endif//_WIN32

	while(true)
		{
		if(!ReadFile(hFile, buffer, buffersize, &dwLen, NULL))
			break;
		if(dwLen == 0)
			break;
		ippsHashUpdate(buffer, dwLen, ctx1);
		dwRead += dwLen;
		}
	ippsHashFinal(SHA1, ctx1);
	delete[] (Ipp8u*)ctx1;
	if(expectedsize != dwRead)
		{
		return false;
		}

	dwPos = DetermineOffsetForValidationKey(m_priv->m_ClientID, SHA1, expectedsize);
#ifdef _WIN32
	SetFilePointer(hFile, dwPos, NULL, FILE_BEGIN);
#else
	fseek((FILE*)hFile, dwPos, SEEK_SET);
#endif//_WIN32
	ReadFile(hFile, ValidationKey, GCFOS_VALIDATION_KEY_LEN, &dwLen, NULL);
#ifdef _WIN32
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
#else
	rewind((FILE*)hFile);
#endif//_WIN32
	if(dwLen != GCFOS_VALIDATION_KEY_LEN)
		return false;

	return true;
	}

bool GCFOS_Client::GetHash(LPCTSTR filename, LPCTSTR filepathForOpen, LPBYTE SHA1, LPFILETIME pFt, PUINT32 pSize, LPBYTE ValidationKey)
	{
	FILEHANDLE			hFile;
	bool				rtnval;
	WIN32_FILE_ATTRIBUTE_DATA attr;

	if(m_priv->m_bUBDR)
		return false; // UBDR clients not allowed to get hash

	if(!FileStoreEnabled())
		return false;

	if(filename == NULL)
		{
		// cleanup operation, pass through un-validated
		return GetHashForHandle(filename, NULL, NULL, FILETIME(), 0, NULL);
		}

	memset(&attr, 0, sizeof(attr));

	if(pSize == NULL || pFt == NULL)
		{
		if(!GetFileAttributesEx(filename, GetFileExInfoStandard, &attr))
			return false;
		if(attr.nFileSizeHigh > 0)
			return false; // file too big for consideration
		}

	hFile = CreateFile(filepathForOpen, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		{
		return false;
		}
	rtnval = GetHashForHandle(filename, hFile, SHA1, (pFt == NULL ? attr.ftLastWriteTime : *pFt), (pSize == NULL ? attr.nFileSizeLow : *pSize), ValidationKey);
	CloseHandle(hFile);
	return rtnval;
	}

bool GCFOS_Client::GetHashForFilename(LPCTSTR filename, BYTE *filenamehash)
	{
	ssize_t				filenamelen;

	ssize_t				i, j;
	int					bs;
	int					ctxSize;
	IppsHashState		*ctx1;

	filenamelen = _tcslen(filename);

	ippsHashGetSize(&ctxSize);
	ctx1=(IppsHashState*)( new Ipp8u [ctxSize]);
	ippsHashInit(ctx1, IPP_ALG_HASH_MD5);

#if 0
												Normalized (for MD5 generation)		value of firstpart(used to ensure same case)
case 1:		c:\dir\file.txt						c:\dir\file.txt						C:\
case 2:		\\?\C:\dir\file.txt					c:\dir\file.txt						C:\
case 3:		\\server\share\file.txt				\\server\share\file.txt				SERVER\SHARE\
case 4:		\\?\UNC\server\share\file.txt		\\server\share\file.txt				SERVER\SHARE\


#endif//0
#ifdef _WIN32
	TCHAR				firstpart[64];

	// Test if caller is disabling path parsing, if so normalize path name
	if(_tcsncmp(filename, _T("\\\\?\\"), 3) == 0)
		{
		// path parsing is being disabled -- normalize path now
		if(_tcsncmp(filename, _T("\\\\?\\UNC\\"), 7) == 0)
			{
			//case 4
			for(i = 0, j = 8, bs = 0; filename[j] != 0 && bs < 2; i++, j++)
				{
				if(filename[j] == '\\')
					{
					bs++;
					if(bs == 1)
						{
						firstpart[i] = 0;
						// firstpart now consists of only the computer name
						if(_tcsicmp(firstpart, m_priv->m_ComputerName) != 0
						&& !m_priv->m_bSecretFound) // secretfound will be false when connected to a LOCAL-gcfos install
							{
							// the computer has changed -- inform gcfos of the new computer name
							if(!SwitchClient(firstpart))
								{
								DEBUGLOG(("Failed to switch client context to %S\n", firstpart));
								delete[] (Ipp8u*)ctx1;
								return false;
								}
							}
						}
					}
				firstpart[i] = _totupper(filename[j]);
				}
			}
		else
			{
			//case 2
			if(filename[5] != ':')
				{
				delete[] (Ipp8u*)ctx1;
				return false;// not a fully-qualified path
				}
			for(i = 0, j = 4, bs = 0; filename[j] != 0 && bs < 1; i++, j++)
				{
				if(filename[j] == '\\')
					{
					bs++;
					}
				firstpart[i] = _totupper(filename[j]);
				}
			}
		}
	else
		{
		if(filename[1] == ':')
			{
			//case 1
			for(i = 0, j = 0, bs = 0; filename[j] != 0 && bs < 1; i++, j++)
				{
				if(filename[j] == '\\')
					bs++;
				firstpart[i] = _totupper(filename[j]);
				}
			}
		else if(filename[0] == '\\' && filename[1] == '\\')
			{
			for(i = 0, j = 2, bs = 0; filename[j] != 0 && bs < 2; i++, j++)
				{
				if(filename[j] == '\\')
					{
					bs++;
					if(bs == 1)
						{
						firstpart[i] = 0;
						// firstpart now consists of only the computer name
						if(_tcsicmp(firstpart, m_priv->m_ComputerName) != 0
						&& !m_priv->m_bSecretFound) // secretfound will be false when connected to a LOCAL-gcfos install
							{
							// the computer has changed -- inform gcfos of the new computer name
							if(!SwitchClient(firstpart))
								{
								DEBUGLOG(("Failed to switch client context to %S\n", firstpart));
								delete[] (Ipp8u*)ctx1;
								return false;
								}
							}
						}
					}
				firstpart[i] = _totupper(filename[j]);
				}
			//case 3
			}
		else
			{
			delete[] (Ipp8u*)ctx1;
			return false; // not a proper fully-qualified path
			}
		}
	ippsHashUpdate((Ipp8u*)&firstpart, (int)(i * sizeof(TCHAR)), ctx1);
#else
	j = 0;
	if(filenamelen == 0 || filename[0] != '/')
		{
		delete[] (Ipp8u*)ctx1;
		return false;
		}
#endif//_WIN32
	ippsHashUpdate((Ipp8u*)(filename + j), (int)((filenamelen - j) * sizeof(TCHAR)), ctx1);
	ippsHashFinal(filenamehash, ctx1);
	delete[] (Ipp8u*)ctx1;
	return true;
	}

bool GCFOS_Client::GetHashForHandle(LPCTSTR filename, FILEHANDLE hFile, LPBYTE SHA1, FILETIME Ft, UINT32 Size, LPBYTE ValidationKey)
	{
	Ipp8u				filenamehash[GCFOS_FILENAME_HASH_LEN];
	PGCFOS_CLIENT_CACHE_ENTRY cacheentry;

	int					rc;
	MDB_txn				*txn;
	GCFOS_UsefulTime	timenow;
	UINT32				extra_len;
	UINT32				SizeOfHashes;
	LPBYTE				value_ref;

	if(filename == NULL)
		{
		// release memory and handles used by cache
		return true;
		}

	if(!FileStoreEnabled())
		return false;

	if(Size < GCFOS_FILE_MINIMUM_SIZE)
		return false;

	if(_tcsnicmp(filename, m_CachePath, _tcslen(m_CachePath)) == 0)
		return false;

	if(!GetHashForFilename(filename, filenamehash))
		return false;

	SizeOfHashes = GetHashDataLengthForFileSize(Size);

	cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY)malloc(sizeof(GCFOS_CLIENT_CACHE_ENTRY));
	if(cacheentry == NULL)
		{
		DEBUGLOG(("GCOFS_Client::GetHashForHandle failed to malloc cacheentry"));
		return false;
		}

	if(m_bEnableLocalCache)
		{
		rc = gcfosdb::BeginTxn(&txn);
		if(rc != 0)
			{
			DEBUGLOG(("GCOFS_Client::GetHashForHandle unable to begin txn, %d", rc));
			return GenerateHashForHandle(hFile, SHA1, Size, ValidationKey);
			}
		memcpy(&cacheentry->filehash, &filenamehash, GCFOS_FILENAME_HASH_LEN);
		extra_len = 0;
		rc = m_statics->m_db_hashes.find(cacheentry, txn, &extra_len, &value_ref);
		if(rc == 0)
			{
			if(memcmp(&cacheentry->ft, &Ft, sizeof(FILETIME)) == 0
			&& cacheentry->size == Size)
				{
				memcpy(SHA1, &cacheentry->SHA1, GCFOS_SHA1_LEN);
				memcpy(ValidationKey, &cacheentry->validationKey, GCFOS_VALIDATION_KEY_LEN);
				if(cacheentry->last_ref != timenow.AsDays())
					{
					// rather than "insert" a record, modify the existing record directly by modifying
					// the data explicitly in memory
					free(cacheentry);
					cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY)(value_ref - m_statics->m_db_hashes.GetDataStart());
					cacheentry->last_ref = timenow.AsDays();
	//				m_statics->m_db_hashes.insert(cacheentry, &txn, extra_len); // update last_ref
					rc = gcfosdb::CommitTxn(&txn);
					if(rc == MDB_MAP_FULL)
						{
						// not a big deal if we fail to update last_ref
						gcfosdb::AbortTxn(txn);
						}
					}
				else
					{
					gcfosdb::AbortTxn(txn);
					free(cacheentry);
					}
				m_priv->m_SHA1Hits++;
				return true;
				}
			}

		gcfosdb::AbortTxn(txn);
		}

	m_priv->m_SHA1Misses++;
	if(!GenerateHashForHandle(hFile, SHA1, Size, ValidationKey))
		{
		free(cacheentry);
		return false;
		}

	if(!m_bEnableLocalCache)
		{
		free(cacheentry);
		return true;
		}

	// don't want to hold txn open during GenerateHashForHandle() as this could be a long operation
	rc = gcfosdb::BeginTxn(&txn);
	if(rc != 0)
		{
		DEBUGLOG(("GCOFS_Client::GetHashForHandle unable to begin txn, %d", rc));
		free(cacheentry);
		return true;
		}
	memcpy(&cacheentry->ft, &Ft, sizeof(FILETIME));
	memcpy(&cacheentry->SHA1, SHA1, GCFOS_SHA1_LEN);
	memcpy(&cacheentry->validationKey, ValidationKey, GCFOS_VALIDATION_KEY_LEN);
	cacheentry->last_ref = timenow.AsDays();
	cacheentry->size = Size;
	rc = m_statics->m_db_hashes.insert(cacheentry, &txn);
	if(rc != 0)
		{
		DEBUGLOG(("GCOFS_Client::GetHashForHandle unable to insert to hash cache, %d", rc));
		gcfosdb::AbortTxn(txn);
		}
	else
		{
		rc = gcfosdb::CommitTxn(&txn);
		if(rc == MDB_MAP_FULL)
			{
			rc = m_statics->m_db_hashes.insert(cacheentry, &txn);
			if(rc == 0)
				{
				rc = gcfosdb::CommitTxn(&txn);
				}
			}
		if(rc != 0)
			{
			DEBUGLOG(("GCOFS_Client::GetHashForHandle unable to commit to resident cache, %d", rc));
			if(txn != NULL)
				{
				gcfosdb::AbortTxn(txn);
				}
			}
		}
	free(cacheentry);
	return true;
	}

typedef struct {
	GCFOS_PRIVATE_MEMBERS	*me;
	UINT32			idx;
	EVENTHANDLE		heComplete;
	} GCFOSCLIENT_WORK_THREAD_INFO, *PGCFOSCLIENT_WORK_THREAD_INFO;

typedef struct {
	BYTE const *		inputbuffer;
	LPBYTE				hash;
	EVENTHANDLE			hComplete;
	} GCFOSCLIENT_WORK_ITEM, *PGCFOSCLIENT_WORK_ITEM;

void __cdecl BeginWorkThread(void *param)
	{
	GCFOS_PRIVATE_MEMBERS	*me;
	PGCFOSCLIENT_WORK_THREAD_INFO info = (PGCFOSCLIENT_WORK_THREAD_INFO)param;

	me = info->me;
	// now let creator know that we're running
	SetEvent(info->heComplete);
	// info NO LONGER ACCESSIBLE at this point!
	me->WorkThread();
	_endthread();
	}

void GCFOS_PRIVATE_MEMBERS::WorkThread()
	{
	PGCFOSCLIENT_WORK_ITEM	WorkItem;
	DWORD					dwXfer;
	ULONG_PTR				Key;
	int						ctxSize;
	IppsHashState			*ctx1;

	ippsHashGetSize(&ctxSize);
	ctx1=(IppsHashState*)( new Ipp8u [ctxSize]);

	while(GetQueuedCompletionStatus(m_hWorkerPort, &dwXfer, &Key, (LPOVERLAPPED *)&WorkItem, INFINITE))
		{
		if(WorkItem == NULL)
			break; // we've been told to quit
		ippsHashInit(ctx1, IPP_ALG_HASH_SHA512_224);

		ippsHashUpdate(WorkItem->inputbuffer, GCFOS_BLOCK_SIZE, ctx1);
		ippsHashFinal(WorkItem->hash, ctx1);
		SetEvent(WorkItem->hComplete);
		}
	}

bool GCFOS_PRIVATE_MEMBERS::InitializeWorkThreads()
	{
	long int			procs;
	UINT32				i;
	GCFOSCLIENT_WORK_THREAD_INFO *threadinfo;
	EVENTHANDLE			*heThreadRunning;

#ifdef _WIN32
	SYSTEM_INFO			SysInfo;
	GetSystemInfo(&SysInfo);
	procs = SysInfo.dwNumberOfProcessors;
#else
	procs = sysconf (_SC_NPROCESSORS_CONF);
#endif

	if(procs >= 2)
		{
		m_WorkerThreadCount = procs - 1;
		if(m_WorkerThreadCount > GCFOS_BLOCKS_PER_QUERY)
			{
			m_WorkerThreadCount = GCFOS_BLOCKS_PER_QUERY;
			}
		}
	else
		{
		m_WorkerThreadCount = 1;
		}

	if(!InitializeCompression())
		return false;

	m_hWorkerPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if(m_hWorkerPort == INVALID_HANDLE_VALUE)
		return false;

	threadinfo = new GCFOSCLIENT_WORK_THREAD_INFO[m_WorkerThreadCount];
	heThreadRunning = new EVENTHANDLE[m_WorkerThreadCount];

	for(i = 0; i < m_WorkerThreadCount; i ++)
		{
		threadinfo[i].me = this;
		threadinfo[i].idx = i;
		threadinfo[i].heComplete = CreateEvent(NULL, FALSE, FALSE, NULL);
		heThreadRunning[i] = threadinfo[i].heComplete;
		_beginthread(BeginWorkThread, 0, (void*)&threadinfo[i]);
		}
	WaitForMultipleObjects(m_WorkerThreadCount, heThreadRunning, TRUE, INFINITE);
	for(i = 0; i < m_WorkerThreadCount; i ++)
		{
		CloseEvent(threadinfo[i].heComplete); // don't need it anymore -- thread is now running
		}
	m_bWorkerThreadsInit = true;
	delete[] threadinfo;
	delete[] heThreadRunning;
	return true;
	}

int GCFOS_Client::CalculateHashesForBlocks(BYTE const * pBlockData, UINT32 &blks, const UINT32 size, LPBYTE pReferences, PUINT32 outsize, LPBYTE straggler_block)
	{
	GCFOSCLIENT_WORK_ITEM	WorkItems[GCFOS_BLOCKS_PER_QUERY];
	EVENTHANDLE				*hCompletedWork;
	UINT32					i;
	LPBYTE					pOutHash = pReferences;
	int						straggler = -1;
	UINT16					blksize;
	BYTE const *			pCurrentBlock = pBlockData;

	hCompletedWork = new EVENTHANDLE[GCFOS_BLOCKS_PER_QUERY];

	*outsize = 0;
	blks = size / GCFOS_BLOCK_SIZE;

	for(i = 0; i < blks; i++)
		{
		WorkItems[i].hash = pOutHash;
		hCompletedWork[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
		WorkItems[i].hComplete = hCompletedWork[i];
		WorkItems[i].inputbuffer = pCurrentBlock;

		PostQueuedCompletionStatus(m_priv->m_hWorkerPort, 0, 0, (LPOVERLAPPED)&WorkItems[i]);
		pCurrentBlock += GCFOS_BLOCK_SIZE;
		pOutHash += GCFOS_BLOCK_HASH_LEN;
		*outsize += GCFOS_BLOCK_HASH_LEN;
		}

	if(straggler_block != NULL && blks < GCFOS_BLOCKS_PER_QUERY && (size % GCFOS_BLOCK_SIZE) >= GCFOS_MINIMUM_BLOCK_SIZE)
		{
		straggler = blks;
		blksize = (UINT16)size % GCFOS_BLOCK_SIZE;
		memcpy(straggler_block, pCurrentBlock, blksize);
		memset(straggler_block + blksize, 0, GCFOS_BLOCK_SIZE - blksize);

		hCompletedWork[blks] = CreateEvent(NULL, FALSE, FALSE, NULL);
		WorkItems[blks].hComplete = hCompletedWork[blks];
		WorkItems[blks].hash = pOutHash;
		WorkItems[blks].inputbuffer = straggler_block;

		PostQueuedCompletionStatus(m_priv->m_hWorkerPort, 0, 0, (LPOVERLAPPED)&WorkItems[blks]);
		pOutHash += GCFOS_BLOCK_HASH_LEN;
		*outsize += GCFOS_BLOCK_HASH_LEN;
		blks++;
		}

	WaitForMultipleObjects(blks, hCompletedWork, TRUE, INFINITE);
	for(i = 0; i < blks; i++)
		{
		CloseEvent(hCompletedWork[i]);
		}
	delete hCompletedWork;
	return straggler;
	}

bool GCFOS_Client::StoreBlocks(BYTE const * pBlockData, UINT32 size, LPBYTE pReferences, PUINT32 outsize)
	{
	UINT32					i, found;
	UINT32					blks;
	GCFOS_REQUEST_QUERY_BLOCKS QueryBlocks;
	GCFOS_RESPONSE_QUERY_BLOCKS QueryResponse;
	int						dwLen;
	BYTE const *			pCurrentBlock = pBlockData;
	LPBYTE					pOutHash = pReferences;
	LPBYTE					compressedBuffer = NULL;
	IppStatus				iCompressionStatus;
	Ipp32u					CompressedSize;
	const Ipp32u			DestBlockSize = GCFOS_BLOCK_SIZE + 0x800;
	UINT16					blksize;
	LARGE_INTEGER			start_time, end_time;
	BYTE const *			block_addr[GCFOS_BLOCKS_PER_QUERY];
	int						straggler = -1;
	int						rc;
	MDB_txn					*txn;
	INT16					iBlocksSent = 0;
	GCFOS_LOCAL_BLOCK_ENTRY BlockEntry;
	GCFOS_UsefulTime        timenow;
	BYTE					straggler_block[GCFOS_BLOCK_SIZE];

	if(m_priv->m_ServerVersion.BlockStore == FALSE)
		{
		DEBUGLOG(("GCFOS_Client::Block store not configured\n"));
		return false;
		}

	if(m_priv->m_bUBDR)
		{
		DEBUGLOG(("GCFOS_Client::StoreBlocks -- denying UBDR client\n"));
		return false;
		}

	if(m_priv->m_bWorkerThreadsInit == false)
		{
		if(m_priv->InitializeWorkThreads() == false)
			{
			DEBUGLOG(("GCFOS_Client::Failed starting worker threads\n"));
			return false;
			}
		}

	if(size % GCFOS_BLOCK_SIZE  && (size % GCFOS_BLOCK_SIZE) < GCFOS_MINIMUM_BLOCK_SIZE)
		{
		DEBUGLOG(("GCFOS_Client::StoreBlocks (warning) received straggler block of insufficient size %u\n", size));
		}

	if(size > (GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE) || size == 0)
		{
		SetLastError(ERROR_INVALID_PARAMETER);
		DEBUGLOG(("GCFOS_Client::StoreBlocks invalid parameter %u\n", size));
		return false;
		}

	QueryPerformanceCounter(&start_time);

	straggler = CalculateHashesForBlocks(pBlockData, blks, size, pReferences, outsize, straggler_block);

	if(m_bEnableLocalBlockCache)
		{
		rc = gcfosdb::BeginTxn(&txn, 0);
		if(rc == 0)
			{
			pOutHash = pReferences;
			found = blks;
			blks = 0;
			for(i = 0; i < found; i++)
				{
				memcpy(&BlockEntry.hash, pOutHash, GCFOS_BLOCK_HASH_LEN);
				if(m_statics->m_db_blocks.find(&BlockEntry, txn) != 0)
					{
					memcpy(QueryBlocks.hashes + (blks * GCFOS_BLOCK_HASH_LEN), pOutHash, GCFOS_BLOCK_HASH_LEN);
					if(i == (UINT32)straggler)
						{
						block_addr[blks] = straggler_block;
						}
					else
						{
						block_addr[blks] = pBlockData + i * GCFOS_BLOCK_SIZE;
						}
					blks++;
					}
				else
					{
					m_priv->m_BlkCacheHit++;
					// use a little entropy from the hash to determine how many days to allow last_ref to be stale
					// only update a portion of the records to reduce db update
					// max_stale = 7 + ((BlockEntry.hash[18 + (m_priv->m_ClientID & 3)] ^ BlockEntry.hash[10]) & 0xf); // ie from 7 to 22 days allowed
					if(timenow.AsDays() - BlockEntry.last_ref > 0)
						{
						BlockEntry.last_ref = timenow.AsDays();
						m_statics->m_db_blocks.insert(&BlockEntry, &txn);
						}
					}
				pOutHash += GCFOS_BLOCK_HASH_LEN;
				}
			rc = gcfosdb::CommitTxn(&txn);
			if(rc != 0)
				{
				// the database has probably been resized -- just abort -- it will likely succeed next time
				DEBUGLOG(("GCFOS_Client::StoreBlocks failed to commit txn: %d -- aborting txn\n", rc));
				gcfosdb::AbortTxn(txn);
				}
			if(blks == 0)
				{
				// all blocks are present in cache
				return true;
				}
			pOutHash = pReferences + (blks * GCFOS_BLOCK_HASH_LEN); // force address to value that will calc correct hash count later
			}
		else
			{
			DEBUGLOG(("GCFOS_Client::StoreBlocks failed to begin txn1: %d\n", rc));
			}
		}
	else
		{
		memcpy(QueryBlocks.hashes, pReferences, (pOutHash - pReferences));
		}

	if(blks < GCFOS_BLOCKS_PER_QUERY)
		{
		// set sentinel
		memset(QueryBlocks.hashes + blks * GCFOS_BLOCK_HASH_LEN, 0, GCFOS_BLOCK_HASH_LEN);
		}
	QueryBlocks.type = GCFOS_REQ_QUERY_BLOCKS;

	EnterCriticalSection(&m_priv->m_csAccess);

	dwLen = sendBlock(m_priv->m_srv, (char *)&QueryBlocks, sizeof(QueryBlocks), 0);
	if(dwLen != sizeof(QueryBlocks))
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		DEBUGLOG(("GCFOS_Client::StoreBlocks failed sending Query Blocks %d\n", dwLen));
		return false;
		}

	m_priv->m_BlkQueries += blks;

	dwLen = recvBlock(m_priv->m_srv, (char *)&QueryResponse, sizeof(QueryResponse), 0);
	if(dwLen != sizeof(QueryResponse))
		{
		DEBUGLOG(("GCFOS_Client::StoreBlocks invalid length received %d:%u\n", dwLen, WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	QueryPerformanceCounter(&end_time);
	m_priv->m_BlkQueryTime += (end_time.QuadPart - start_time.QuadPart);

	if(QueryResponse.SrvResponse != GCFOS_SRV_RESP_OK)
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		DEBUGLOG(("GCFOS_Client::StoreBlocks received error response %u\n", QueryResponse.SrvResponse));
		return false;
		}

	compressedBuffer = (LPBYTE)VirtualAlloc(NULL, DestBlockSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(compressedBuffer == NULL)
		{
		LeaveCriticalSection(&m_priv->m_csAccess);
		DEBUGLOG(("GCFOS_Client::StoreBlocks failed to get compressedBuffer, %u\n", GetLastError()));
		return false;
		}

	QueryPerformanceCounter(&start_time);
	for(i = 0; i < blks; i++)
		{
		pCurrentBlock = block_addr[i];
		if(QueryResponse.present[i] == 0)
			{
			// NOTE: First 2 bytes of compressed buffer will contain size of compressed buffer
			CompressedSize = DestBlockSize - sizeof(UINT16);
			iCompressionStatus = ippsEncodeLZO_8u(pCurrentBlock, GCFOS_BLOCK_SIZE, compressedBuffer + sizeof(UINT16), &CompressedSize, m_priv->m_pLZOState);
			if(iCompressionStatus != ippStsNoErr || CompressedSize >= GCFOS_BLOCK_SIZE)
				{
				blksize = GCFOS_BLOCK_SIZE;
				dwLen = sendBlock(m_priv->m_srv, (char *)&blksize, sizeof(blksize), 0);
				if(dwLen != sizeof(blksize))
					{
					LeaveCriticalSection(&m_priv->m_csAccess);
					VirtualFree(compressedBuffer, 0, MEM_RELEASE);
					DEBUGLOG(("GCFOS_Client::StoreBlocks failed sending uncomp blksize %d\n", dwLen));
					return false;
					}
				dwLen = sendBlock(m_priv->m_srv, (char *)pCurrentBlock, GCFOS_BLOCK_SIZE, 0);
				if(dwLen != GCFOS_BLOCK_SIZE)
					{
					LeaveCriticalSection(&m_priv->m_csAccess);
					VirtualFree(compressedBuffer, 0, MEM_RELEASE);
					DEBUGLOG(("GCFOS_Client::StoreBlocks failed sending uncomp data %d\n", dwLen));
					return false;
					}
				}
			else
				{
				// compressed successfully
				blksize = (UINT16)(CompressedSize + sizeof(UINT16));
				*(PUINT16)compressedBuffer = (UINT16)CompressedSize;
				dwLen = sendBlock(m_priv->m_srv, (char *)compressedBuffer, blksize, 0);
				if(dwLen != blksize)
					{
					LeaveCriticalSection(&m_priv->m_csAccess);
					VirtualFree(compressedBuffer, 0, MEM_RELEASE);
					DEBUGLOG(("GCFOS_Client::StoreBlocks failed sending comp data %d\n", dwLen));
					return false;
					}
				}
			m_priv->m_BlkStores++;
			iBlocksSent++;
			}
		pCurrentBlock += GCFOS_BLOCK_SIZE;
		}
	
	VirtualFree(compressedBuffer, 0, MEM_RELEASE);
	compressedBuffer = NULL;

	rc = 0;
	if(m_bEnableLocalBlockCache)
		{
		rc = gcfosdb::BeginTxn(&txn);
		if(rc == 0)
			{
			for(int retry = 0; retry < 3; retry++)
				{
				pOutHash = QueryBlocks.hashes;
				for(i = 0; i < blks; i++)
					{
					// We already queried earlier for this hash, we know it is not present
					// in local cache, so add it now
					memcpy(&BlockEntry.hash, pOutHash, GCFOS_BLOCK_HASH_LEN);
					BlockEntry.last_ref = timenow.AsDays();
					rc = m_statics->m_db_blocks.insert(&BlockEntry, &txn);
					if(rc != 0)
						{
						break;
						}
					pOutHash += GCFOS_BLOCK_HASH_LEN;
					}
				if(rc == 0)
					{
					rc = gcfosdb::CommitTxn(&txn);
					if(rc == MDB_MAP_FULL)
						{
						continue;
						}
					break;
					}
				}
			if(rc != 0)
				{
				gcfosdb::AbortTxn(txn);
				}
			}
		else
			{
			DEBUGLOG(("GCFOS_Client::StoreBlocks failed to begin txn2: %d\n", rc));
			}
		}

	if(iBlocksSent == 0)
		{
		// This can hit if we are not using local cache, and we discover that all blocks are already present
		// on server
		LeaveCriticalSection(&m_priv->m_csAccess);
		QueryPerformanceCounter(&end_time);
		m_priv->m_BlkStoreTime += (end_time.QuadPart - start_time.QuadPart);
		return true;
		}

	// only expect an ack if we had to send some blocks
	dwLen = recvBlock(m_priv->m_srv, (char *)&QueryResponse.SrvResponse, sizeof(QueryResponse.SrvResponse), 0);
	if(dwLen != sizeof(QueryResponse.SrvResponse))
		{
		DEBUGLOG(("GCFOS_Client::StoreBlocks failed to receive ack %d:%u\n", dwLen, WSAGetLastError()));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}
	if(QueryResponse.SrvResponse != GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG(("GCFOS_Client::StoreBlocks received bad ack %u\n", QueryResponse.SrvResponse));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	LeaveCriticalSection(&m_priv->m_csAccess);
	QueryPerformanceCounter(&end_time);
	m_priv->m_BlkStoreTime += (end_time.QuadPart - start_time.QuadPart);

	return true;
	}

bool GCFOS_Client::BlockStoreEnabled()
	{
	return (m_priv->m_ServerVersion.BlockStore ? true : false);
	}

bool GCFOS_Client::FileStoreEnabled()
	{
	return (m_priv->m_ServerVersion.FileStore ? true : false);
	}

bool GCFOS_Client::RetrieveBlocks(BYTE const * Hashes, PUINT16 Count, LPBYTE Blocks)
	{
	GCFOS_REQUEST_RETRIEVE_BLOCKS	Req;
	GCFOS_RESPONSE_RETRIEVE_BLOCKS	RetrieveBlockResp;
	DWORD							dwLen;
	DWORD							i;
	Ipp8u							Sentinel[GCFOS_BLOCK_HASH_LEN];
	BYTE							RawData[GCFOS_BLOCK_SIZE];
	Ipp32u							uncompsize;
	IppStatus						iDecompressionStatus;

	if(!BlockStoreEnabled())
		return false;

	memset(&Sentinel, 0, GCFOS_BLOCK_HASH_LEN);
	for(*Count = 0; (*Count) < GCFOS_BLOCKS_PER_QUERY; (*Count)++)
		{
		if(memcmp(&Sentinel, &Hashes[(*Count) * GCFOS_BLOCK_HASH_LEN], GCFOS_BLOCK_HASH_LEN) == 0)
			break;
		}

	memcpy(&Req.hashes, Hashes, (*Count) * GCFOS_BLOCK_HASH_LEN);
	if((*Count) < GCFOS_BLOCKS_PER_QUERY)
		memset(&Req.hashes[(*Count) * GCFOS_BLOCK_HASH_LEN], 0, GCFOS_BLOCK_HASH_LEN);

	Req.type = GCFOS_REQ_RESTORE_BLOCK;

	EnterCriticalSection(&m_priv->m_csAccess);
	dwLen = sendBlock(m_priv->m_srv, (char *)&Req, sizeof(GCFOS_REQUEST_RETRIEVE_BLOCKS), 0);
	if(dwLen != sizeof(GCFOS_REQUEST_RETRIEVE_BLOCKS))
		{
		DEBUGLOG(("GCFOS_Client::RetrieveBlocks failed sending request %d\n", dwLen));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	dwLen = recvBlock(m_priv->m_srv, (char *)&RetrieveBlockResp, sizeof(GCFOS_RESPONSE_RETRIEVE_BLOCKS), 0);
	if(dwLen != sizeof(GCFOS_RESPONSE_RETRIEVE_BLOCKS))
		{
		DEBUGLOG(("GCFOS_Client::RetrieveBlocks failed receiving response %d\n", dwLen));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	if(RetrieveBlockResp.SrvResponse != GCFOS_SRV_RESP_OK)
		{
		DEBUGLOG(("GCFOS_Client::RetrieveBlocks received failed response %d\n", (UINT32)RetrieveBlockResp.SrvResponse));
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	for(i = 0; i < (*Count); i++)
		{
		dwLen = recvBlock(m_priv->m_srv, (char *)&RawData, RetrieveBlockResp.Sizes[i], 0);
		if(dwLen != RetrieveBlockResp.Sizes[i])
			{
			DEBUGLOG(("GCFOS_Client::RetrieveBlocks failed receiving block%u %d\n", i, dwLen));
			LeaveCriticalSection(&m_priv->m_csAccess);
			return false;
			}
		if(RetrieveBlockResp.Sizes[i] == GCFOS_BLOCK_SIZE)
			{
			// uncompressed
			memcpy(Blocks, &RawData, GCFOS_BLOCK_SIZE);
			}
		else
			{
			uncompsize = GCFOS_BLOCK_SIZE;
			iDecompressionStatus = ippsDecodeLZOSafe_8u(RawData, RetrieveBlockResp.Sizes[i], Blocks, &uncompsize);
			if(iDecompressionStatus != ippStsNoErr || uncompsize != GCFOS_BLOCK_SIZE)
				{
				DEBUGLOG(("GCFOS_Client::RetrieveBlocks decomp failed block%u %d\n", i, dwLen));
				LeaveCriticalSection(&m_priv->m_csAccess);
				return false;
				}
			}
		Blocks += GCFOS_BLOCK_SIZE;
		}
	LeaveCriticalSection(&m_priv->m_csAccess);
	return true;
	}

bool GCFOS_Client::EraseLocalCache(LPCTSTR pszCachePath, LPCTSTR CompanyName, GCFOS_LOCAL_ERASE_TYPE type)
	{
	LPCSTR			tablename;
	bool			retval;
	TCHAR			szKeyPath[128];
	LSTATUS			status;
	HKEY			hKey;

	if(m_priv->m_bConnected)
		{
		DEBUGLOG(("GCFOS_Client::EraseLocalCache must be called before connected\n"));
		return false;
		}

	switch(type)
		{
		case GCFOS_LOCAL_ERASE_TYPE_BLOCKS:
			tablename = GCFOS_CLIENT_DB_BLOCKS_NAME;
			break;

		case GCFOS_LOCAL_ERASE_TYPE_RESIDENT:
			tablename = GCFOS_CLIENT_DB_RESIDENT_NAME;
			break;

		case GCFOS_LOCAL_ERASE_TYPE_UNIQUE:
			tablename = GCFOS_CLIENT_DB_LCUD_NAME;
			break;

		case GCFOS_LOCAL_ERASE_TYPE_HASH:
			tablename = GCFOS_CLIENT_DB_HASH_NAME;
			break;

		default:
			DEBUGLOG(("GCFOS_Client::EraseLocalCache failed to open environment\n"));
			return false;
		}

	if(gcfosdb::CreateEnvironment(CStringA(pszCachePath)) != 0)
		{
		DEBUGLOG(("GCFOS_Client::EraseLocalCache failed to open environment\n"));
		return false;
		}

	retval = gcfosdb::drop(tablename);

	if(retval == true)
		{
		if(type == GCFOS_LOCAL_ERASE_TYPE_UNIQUE)
			{
			_stprintf_s(szKeyPath, 128, _T("SOFTWARE\\%s\\GCFOS"), CompanyName);
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyPath, 0, KEY_WRITE, &hKey);
			if(status == ERROR_SUCCESS)
				{
				status = RegDeleteValue(hKey, GCFOS_CLIENT_REG_LCUD_SEQ);
				if(status != ERROR_SUCCESS)
					{
					DEBUGLOG(("GCFOS_Client::EraseLocalCache failed to delete registry config value %u\n", status));
					}
				RegCloseKey(hKey);
				}
			else
				{
				DEBUGLOG(("GCFOS_Client::EraseLocalCache unable to open reg path %S %u\n", szKeyPath, status));
				}
			}
		}

	gcfosdb::CloseEnvironment();

	return true;
	}

bool GCFOS_Client::UpdateLocalBlockCache()
	{
	GCFOS_LOCAL_BLOCK_ENTRY					BlockEntry;
	Ipp8u									restart_hash[GCFOS_BLOCK_HASH_LEN];
	MDB_cursor								*c_blocks;
	MDB_txn									*txn = NULL;
	int										rc;
	UINT32									RecsModified = 0;
	UINT64									RecsRead = 0, RecsDeleted = 0, RecsSent = 0;
	GCFOS_UsefulTime						timenow;
	GCFOS_REQUEST_INFORM_ACTIVE_HASHES		InformActiveHashes;
	int										retry;
	UINT16									sendsize;
	bool									deleted_rec;
	GCFOS_CLIENT_CACHE_ENTRY				cacheentry;
	MDB_cursor								*c_hashes;

	if(!m_bEnableLocalBlockCache || !gcfosdb::EnvironmentInitialized())
		return true; // nothing to do

	memset(&restart_hash, 0, sizeof(restart_hash));

	rc = gcfosdb::BeginTxn(&txn);
	if(rc != 0)
		{
		DEBUGLOG(("UpdateLocalBlockCache: failed to begin txn %d\n", rc));
		return false;
		}

	InformActiveHashes.type = GCFOS_REQ_INFORM_ACTIVE_HASHES; // this does not change
	InformActiveHashes.count = 0;

	EnterCriticalSection(&m_priv->m_csAccess);
	for(retry = 0; retry < 5; retry++)
		{
		rc = m_statics->m_db_blocks.createCursor(&c_blocks, txn, 0);
		if(rc != 0)
			{
			DEBUGLOG(("UpdateLocalBlockCache: failed to create cursor %d\n", rc));
			gcfosdb::AbortTxn(txn);
			LeaveCriticalSection(&m_priv->m_csAccess);
			return false;
			}
		memcpy(&BlockEntry.hash, &restart_hash, GCFOS_BLOCK_HASH_LEN);
		rc = m_statics->m_db_blocks.get(c_blocks, &BlockEntry, MDB_SET_RANGE);
		if(rc != 0)
			{
			DEBUGLOG(("UpdateLocalBlockCache: failed to get initial record %d\n", rc));
			break;
			}

		while(rc == 0)
			{
			RecsRead++;
			deleted_rec = false;
			if(timenow.AsDays() - BlockEntry.last_ref > 45)
				{
				rc = m_statics->m_db_blocks.erase(c_blocks);
				deleted_rec = true;
				if(rc != 0)
					{
					DEBUGLOG(("UpdateLocalBlockCache: failed to erase cursor %d\n", rc));
					m_statics->m_db_blocks.closeCursor(c_blocks);
					gcfosdb::AbortTxn(txn);
					LeaveCriticalSection(&m_priv->m_csAccess);
					return false;
					}
				RecsModified++;
				RecsDeleted++;
				if(RecsModified > 500)
					{
					RecsModified = 0;
					m_statics->m_db_blocks.closeCursor(c_blocks);
					rc = gcfosdb::CommitTxn(&txn);
					if(rc != 0)
						{
						break; // db has likely been resized, restart again (this will prompt retry)
						}
					// update our restart point
					memcpy(&restart_hash, &BlockEntry.hash, GCFOS_BLOCK_HASH_LEN);
					rc = gcfosdb::BeginTxn(&txn);
					if(rc != 0)
						{
						DEBUGLOG(("UpdateLocalBlockCache: failed to (re)begin txn %d\n", rc));
						LeaveCriticalSection(&m_priv->m_csAccess);
						return false;
						}
					retry = 0; // reset retry count as this was a successful update
					break; // this will get a new cursor
					}
				}

			if(!deleted_rec && m_bBlockPurgingEnabled
			&& ((BlockEntry.hash[0] ^ (BYTE)timenow.GetUsefulValue()) & 0x1f) == 0)
				{
				memcpy(&InformActiveHashes.hashes[InformActiveHashes.count * GCFOS_BLOCK_HASH_LEN], &BlockEntry.hash, GCFOS_BLOCK_HASH_LEN);
				InformActiveHashes.count++;
				RecsSent++;
				}
			rc = m_statics->m_db_blocks.getNext(c_blocks, &BlockEntry);
			if((rc != 0 && InformActiveHashes.count > 0) || InformActiveHashes.count == GCFOS_INFORM_ACTIVE_HASHES_COUNT)
				{
				sendsize = sizeof(GCFOS_REQUEST_INFORM_ACTIVE_HASHES);

				if(sendBlock(m_priv->m_srv, (char *)&InformActiveHashes, sendsize, 0) != sendsize)
					{
					DEBUGLOG(("UpdateLocalBlockCache: failed to send to server %d\n", WSAGetLastError()));
					m_statics->m_db_blocks.closeCursor(c_blocks);
					gcfosdb::AbortTxn(txn);
					LeaveCriticalSection(&m_priv->m_csAccess);
					return false;
					}
				InformActiveHashes.count = 0;
				}
			}

		if(rc == gcfosdb_NOTFOUND)
			break;
		}

	DEBUGLOG(("GCFOS_Client::UpdateLocalBlockCache: %I64u read, %I64u sent, %I64u deleted\n", RecsRead, RecsSent, RecsDeleted));
	LeaveCriticalSection(&m_priv->m_csAccess);

	memset(&restart_hash, 0, sizeof(restart_hash));
	RecsRead = 0;
	// leave RecsModified left set previously (this will cause txn to be committed earlier)
	RecsDeleted = 0;
	for(retry = 0; retry < 5; retry++)
		{
		rc = m_statics->m_db_hashes.createCursor(&c_hashes, txn, 0);
		if(rc != 0)
			{
			DEBUGLOG(("UpdateLocalBlockCache: failed to create hashes cursor %d\n", rc));
			if(gcfosdb::CommitTxn(&txn) != 0)
				{
				gcfosdb::AbortTxn(txn);
				}
			return false;
			}
		memcpy(&cacheentry.filehash, &restart_hash, GCFOS_FILENAME_HASH_LEN);
		rc = m_statics->m_db_hashes.get(c_hashes, &cacheentry, MDB_SET_RANGE);
		if(rc != 0)
			{
			DEBUGLOG(("UpdateLocalBlockCache: failed to get initial hashes record %d\n", rc));
			break;
			}
		while(rc == 0)
			{
			RecsRead++;
			deleted_rec = false;
			if(timenow.AsDays() - cacheentry.last_ref > 15)
				{
				rc = m_statics->m_db_hashes.erase(c_hashes);
				deleted_rec = true;
				if(rc != 0)
					{
					if(rc == MDB_MAP_FULL)
						{
						rc = gcfosdb::ResizeLMDB(&txn);
						break; // db has been resized, restart again (this will prompt retry)
						}

					DEBUGLOG(("UpdateLocalBlockCache: failed to erase hashes cursor %d\n", rc));
					m_statics->m_db_hashes.closeCursor(c_hashes);
					gcfosdb::AbortTxn(txn);
					return false;
					}
				RecsModified++;
				RecsDeleted++;
				if(RecsModified > 500)
					{
					RecsModified = 0;
					m_statics->m_db_hashes.closeCursor(c_hashes);
					rc = gcfosdb::CommitTxn(&txn);
					if(rc != 0)
						{
						break; // db has likely been resized, restart again (this will prompt retry)
						}
					// update our restart point
					memcpy(&restart_hash, &cacheentry.filehash, GCFOS_FILENAME_HASH_LEN);
					rc = gcfosdb::BeginTxn(&txn);
					if(rc != 0)
						{
						DEBUGLOG(("UpdateLocalBlockCache: failed to (re)begin txn for hashes %d\n", rc));
						return false;
						}
					retry = 0; // reset retry count as this was a successful update
					break; // this will get a new cursor
					}
				}
			rc = m_statics->m_db_hashes.getNext(c_hashes, &cacheentry);
			}
		if(rc == gcfosdb_NOTFOUND)
			break;
		}
		
	rc = gcfosdb::CommitTxn(&txn);
	if(rc != 0)
		{
		DEBUGLOG(("GCFOS_Client::UpdateLocalBlockCache: WARNING - failed to commit final txn, %d\n", rc));
		}
	DEBUGLOG(("GCFOS_Client::UpdateLocalBlockCache: %I64u file hashes read, %I64u deleted\n", RecsRead, RecsDeleted));
	return true;
	}

UINT32 GCFOS_Client::GetHashDataLengthForFileSize(INT64 filesize)
	{
	UINT32			SizeOfHashes;

	SizeOfHashes = (UINT32)(filesize / (UINT64)GCFOS_BLOCK_SIZE) * GCFOS_BLOCK_HASH_LEN;
	if(filesize % GCFOS_BLOCK_SIZE > 0)
		{
		if(filesize % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
			{
			SizeOfHashes += (filesize % GCFOS_BLOCK_SIZE);
			}
		else
			{
			SizeOfHashes += GCFOS_BLOCK_HASH_LEN;
			}
		}
	return SizeOfHashes;
	}

INT64 GCFOS_Client::GetBlockHashesForFile(FILEHANDLE hFile, LPCTSTR filename, LPBYTE hashdata, UINT32 hashdata_size)
	{
	LPBYTE			buffer;
	UINT32			SizeOfHashes;
	DWORD			dwRead;
	UINT32			local_hashsize;
	UINT32			stragglersize;
	int				startindex;
	Ipp8u			filenamehash[GCFOS_FILENAME_HASH_LEN];
	int				rc;
	MDB_txn			*txn;
	PGCFOS_CLIENT_CACHE_ENTRY cacheentry = NULL;
	UINT32			extra_len;
	UINT64			SizeOfFile;
	LPBYTE			pOuthash;
	GCFOS_UsefulTime timenow;
	int				ctxSize;
	IppsHashState*	ctx1;
	bool			bSuccess;
	bool			bFileRecentlyModified = false;
	FILETIME		ft_c;
	UINT64			i64ft;
	LPBYTE			pCurHash;
	UINT32			HashBlocksRemaining;
	GCFOS_LOCAL_BLOCK_ENTRY BlockEntry;
	LPBYTE			value_ref;
	WIN32_FILE_ATTRIBUTE_DATA attr;

	if(hFile == INVALID_HANDLE_VALUE || hFile == NULL)
		{
		return -15;
		}

#ifdef _WIN32
	SYSTEMTIME		st;
	BY_HANDLE_FILE_INFORMATION fileinfo;
	if(!GetFileInformationByHandle(hFile, &fileinfo))
		{
		return -2;
		}
	attr.nFileSizeHigh = fileinfo.nFileSizeHigh;
	attr.nFileSizeLow = fileinfo.nFileSizeLow;
	attr.ftLastWriteTime = fileinfo.ftLastWriteTime;
#else
	if(!GetFileAttributesEx(filename,GetFileExInfoStandard, &attr))
		{
		return -2;
		}
#endif

	SizeOfFile = ((UINT64)attr.nFileSizeHigh << 32ULL) + attr.nFileSizeLow;

	if(SizeOfFile < GCFOS_MINIMUM_BLOCK_SIZE)
		{
		return -12;
		}

	if(!GetHashForFilename(filename, filenamehash))
		return -6;

	SizeOfHashes = GetHashDataLengthForFileSize(SizeOfFile);
	if(SizeOfHashes != hashdata_size)
		return -13; // sanity check -- buffer passed in is not correct size

#ifdef _WIN32
	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft_c);
#else
	time_t t_now;
	time(&t_now);
	time_t_to_FILETIME(t_now, &ft_c);
#endif//_WIN32
	i64ft = ((UINT64)ft_c.dwHighDateTime << 32ULL) + ft_c.dwLowDateTime;
	i64ft -= (_DAY * 7);
	// i64ft is now a FILETIME that represents 7-days ago

	if(CompareFileTime(&attr.ftLastWriteTime, (LPFILETIME)&i64ft) > 0)
		{
		bFileRecentlyModified = true;
		}

	if(m_bEnableExtendedLocalBlockCache && !bFileRecentlyModified)
		{
		rc = gcfosdb::BeginTxn(&txn, 0); // can't(?) be read-only as we are directly modifying the pages (for last_ref update)
		if(rc != 0)
			{
			DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to begin txn %d\n", rc));
			return -7;
			}
		extra_len = 0;
		cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY) malloc(sizeof(GCFOS_CLIENT_CACHE_ENTRY));

		memcpy(&cacheentry->filehash, &filenamehash, GCFOS_FILENAME_HASH_LEN);
		if(m_statics->m_db_hashes.find(cacheentry, txn, &extra_len, &value_ref) == 0)
			{
			if(memcmp(&cacheentry->ft, &attr.ftLastWriteTime, sizeof(FILETIME)) == 0
			&& cacheentry->size == attr.nFileSizeLow
			&& extra_len == hashdata_size)
				{// this only compares the lower part of the filesize (close enough to guarantee that it's not been modified)
				free(cacheentry);
				cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY)(value_ref - m_statics->m_db_hashes.GetDataStart());
				memcpy(hashdata, (LPBYTE)cacheentry + m_statics->m_db_hashes.GetRecSize(), hashdata_size);
				if(cacheentry->last_ref != timenow.AsDays())
					{
					cacheentry->last_ref = timenow.AsDays();
					// We have to update the references to these blocks (age)
					if(m_bBlockPurgingEnabled)
						{
						HashBlocksRemaining = (UINT32)(SizeOfFile / (UINT64)GCFOS_BLOCK_SIZE);
						if(SizeOfFile % GCFOS_BLOCK_SIZE > 0)
							{
							if(SizeOfFile % GCFOS_BLOCK_SIZE >= GCFOS_MINIMUM_BLOCK_SIZE)
								HashBlocksRemaining++;
							}
						for(pCurHash = hashdata; HashBlocksRemaining > 0; HashBlocksRemaining--)
							{
							memcpy(&BlockEntry.hash, pCurHash, GCFOS_BLOCK_HASH_LEN);
							rc = m_statics->m_db_blocks.find(&BlockEntry, txn);
							if(rc == 0)
								{
								if(BlockEntry.last_ref != timenow.AsDays())
									{
									BlockEntry.last_ref = timenow.AsDays();
									rc = m_statics->m_db_blocks.insert(&BlockEntry, &txn);
									if(rc != 0)
										{
										DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to update local block last-ref %d\n", rc));
										break;
										}
									}
								}
							pCurHash += GCFOS_BLOCK_HASH_LEN;
							}
						if(gcfosdb::CommitTxn(&txn) != 0)
							{
							DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile warning, commit failed (likely resized)\n"));
							gcfosdb::AbortTxn(txn);
							}
						}
					else
						{
						gcfosdb::AbortTxn(txn);
						}
					}
				else
					{
					gcfosdb::AbortTxn(txn);
					}
				return SizeOfFile;
				}
			}
		// don't keep the txn open as this is a long operation
		gcfosdb::AbortTxn(txn);
		}
	else
		{
		cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY) malloc(sizeof(GCFOS_CLIENT_CACHE_ENTRY));
		memset(cacheentry, 0, sizeof(GCFOS_CLIENT_CACHE_ENTRY));
		memcpy(&cacheentry->filehash, &filenamehash, GCFOS_FILENAME_HASH_LEN);
		}

	buffer = (LPBYTE)VirtualAlloc(NULL, GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(buffer == NULL)
		{
		DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile - VirtualAlloc failed\n"));
		free(cacheentry);
		return -4;
		}

	ippsHashGetSize(&ctxSize);
	ctx1=(IppsHashState*)( new Ipp8u [ctxSize]);
	ippsHashInit(ctx1, IPP_ALG_HASH_SHA1);

	startindex = 0;
	pOuthash = hashdata;

	bSuccess = true;
#ifdef _WIN32
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
#else
	rewind(hFile);
#endif//_WIN32
	while(bSuccess)
		{
		if(ReadFile(hFile, buffer, GCFOS_BLOCKS_PER_QUERY * GCFOS_BLOCK_SIZE, &dwRead, NULL))
			{
			if(dwRead == 0)
				break; // file all read
			ippsHashUpdate(buffer, dwRead, ctx1);
			if(dwRead % GCFOS_BLOCK_SIZE > 0
			&& dwRead % GCFOS_BLOCK_SIZE < GCFOS_MINIMUM_BLOCK_SIZE)
				{
				stragglersize = (dwRead % GCFOS_BLOCK_SIZE);
				if(dwRead < GCFOS_MINIMUM_BLOCK_SIZE)
					{
					// just the straggler (not a whole block read)
					memcpy(pOuthash, buffer, stragglersize);
					break;
					}
				else if(StoreBlocks(buffer, dwRead - stragglersize, pOuthash, &local_hashsize))
					{
					pOuthash += local_hashsize;
					memcpy(pOuthash, buffer + dwRead - stragglersize, stragglersize);
					break;
					}
				else
					{
					DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile - StoreBlocks failed\n"));
					bSuccess = false;
					break;
					}
				}
			else
				{
				if(!StoreBlocks(buffer, dwRead, pOuthash, &local_hashsize))
					{
					DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile - StoreBlocks failed\n"));
					bSuccess = false;
					break;
					}
				}
			pOuthash += local_hashsize;
			}
		else
			{
			DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile - ReadFile failed: %u\n", GetLastError()));
			bSuccess = false;
			break;
			}
		}

#ifdef _WIN32
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
#else
	rewind(hFile);
#endif//_WIN32

	if(bSuccess)
		{
		ippsHashFinal(cacheentry->SHA1, ctx1);
		// there's no point in setting the validation key as block caching is only used on local-style GCFOS
		// where validation keys are not used
		memset(&cacheentry->validationKey, 0, GCFOS_VALIDATION_KEY_LEN);
//		dwPos = DetermineOffsetForValidationKey(m_priv->m_ClientID, cacheentry->SHA1, (UINT32)SizeOfFile);
//		SetFilePointer(hFile, dwPos, NULL, FILE_BEGIN);
//		ReadFile(hFile, cacheentry->validationKey, GCFOS_VALIDATION_KEY_LEN, &dwRead, NULL);
		}

	delete[] (Ipp8u*)ctx1;
	ctx1 = NULL;

	// update record in db with new hash-chain info
	if(bSuccess && m_bEnableExtendedLocalBlockCache)
		{
		rc = gcfosdb::BeginTxn(&txn, 0);
		if(rc == 0)
			{
			// filehash has already been set.  Set rest of fields now
			memcpy(&cacheentry->ft, &attr.ftLastWriteTime, sizeof(FILETIME));
			cacheentry->last_ref = timenow.AsDays();
			cacheentry->size = (UINT32)SizeOfFile;
			if(!bFileRecentlyModified)
				{
				extra_len = SizeOfHashes;
				cacheentry = (PGCFOS_CLIENT_CACHE_ENTRY) realloc(cacheentry, sizeof(GCFOS_CLIENT_CACHE_ENTRY) + extra_len);
				memcpy((LPBYTE)cacheentry + m_statics->m_db_hashes.GetRecSize(), hashdata, SizeOfHashes);
				}
			else
				{
				extra_len = 0;
				// don't write any "extended" block-chain to db
				}
			rc = m_statics->m_db_hashes.insert(cacheentry, &txn, extra_len);
			if(rc != 0)
				{
				if(rc == MDB_MAP_FULL)
					{
					// try again (it's not been resized)
					rc = m_statics->m_db_hashes.insert(cacheentry, &txn, extra_len);
					if(rc != 0)
						{
						DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to insert (post resize) new rec %d\n", rc));
						gcfosdb::AbortTxn(txn);
						}
					}
				else
					{
					DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to insert new rec %d\n", rc));
					gcfosdb::AbortTxn(txn);
					}
				}
			else
				{
				rc = gcfosdb::CommitTxn(&txn);
				if(rc == MDB_MAP_FULL)
					{
					rc = m_statics->m_db_hashes.insert(cacheentry, &txn, extra_len);
					if(rc != 0)
						{
						DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to commit (post resize) new rec %d\n", rc));
						}
					if(gcfosdb::CommitTxn(&txn) != 0)
						{
						DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to commit (post resize) new rec %d\n", rc));
						gcfosdb::AbortTxn(txn);
						}
					}
				else if(rc != 0)
					{
					DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile commit failed %d\n", rc));
					gcfosdb::AbortTxn(txn);
					}
				}
			}
		else
			{
			DEBUGLOG(("GCFOS_Client::GetBlockHashesForFile failed to begin (new) txn %d\n", rc));
			}
		}

	VirtualFree(buffer, NULL, MEM_RELEASE);
	free(cacheentry);
	if(!bSuccess)
		{
		return -5;
		}

	return SizeOfFile;
	}

bool GCFOS_Client::ValidateLocalBlockCache()
	{
	GCFOS_LOCAL_BLOCK_ENTRY					BlockEntry;
	MDB_cursor								*c_blocks;
	MDB_txn									*txn = NULL;
	int										rc;
	UINT64									RecsRead = 0;
	GCFOS_REQUEST_QUERY_BLOCKS				QueryBlocks;
	GCFOS_RESPONSE_QUERY_BLOCKS				QueryResponse;
	int										i = 0, j;
	DWORD									dwLen;

	if(!m_bEnableLocalBlockCache || !gcfosdb::EnvironmentInitialized())
		return false;

	rc = gcfosdb::BeginTxn(&txn, MDB_RDONLY);
	if(rc != 0)
		{
		DEBUGLOG(("ValidateLocalBlockCache: failed to begin txn %d\n", rc));
		return false;
		}

	EnterCriticalSection(&m_priv->m_csAccess);
	rc = m_statics->m_db_blocks.createCursor(&c_blocks, txn, 0);
	if(rc != 0)
		{
		DEBUGLOG(("ValidateLocalBlockCache: failed to create cursor %d\n", rc));
		gcfosdb::AbortTxn(txn);
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	rc = m_statics->m_db_blocks.get(c_blocks, &BlockEntry, MDB_FIRST);
	if(rc != 0)
		{
		DEBUGLOG(("ValidateLocalBlockCache: failed to get initial record %d\n", rc));
		gcfosdb::AbortTxn(txn);
		LeaveCriticalSection(&m_priv->m_csAccess);
		return false;
		}

	QueryBlocks.type = GCFOS_REQ_QUERY_BLOCKS;
	while(true)
		{
		if(rc == 0)
			{
			RecsRead++;
			memcpy(QueryBlocks.hashes + (i * GCFOS_BLOCK_HASH_LEN), BlockEntry.hash, GCFOS_BLOCK_HASH_LEN);
			i++;
			}
		if((rc != 0 && i > 0) || i == GCFOS_BLOCKS_PER_QUERY)
			{
			if(i != GCFOS_BLOCKS_PER_QUERY)
				{
				// set sentinel
				memset(QueryBlocks.hashes + (i * GCFOS_BLOCK_HASH_LEN), 0, GCFOS_BLOCK_HASH_LEN);
				}
			dwLen = sendBlock(m_priv->m_srv, (char *)&QueryBlocks, sizeof(QueryBlocks), 0);
			if(dwLen != sizeof(QueryBlocks))
				{
				LeaveCriticalSection(&m_priv->m_csAccess);
				DEBUGLOG(("GCFOS_Client::ValidateLocalBlockCache failed sending Query Blocks %d:%u\n", dwLen, WSAGetLastError()));
				return false;
				}

			dwLen = recvBlock(m_priv->m_srv, (char *)&QueryResponse, sizeof(QueryResponse), 0);
			if(dwLen != sizeof(QueryResponse))
				{
				DEBUGLOG(("GCFOS_Client::ValidateLocalBlockCache invalid length received %d:%u\n", dwLen, WSAGetLastError()));
				LeaveCriticalSection(&m_priv->m_csAccess);
				return false;
				}
			for(j = 0; j < i; j++)
				{
				if(!QueryResponse.present[j])
					{
					DEBUGLOG(("GCFOS_Client::ValidateLocalBlockCache -- non-present block located\n"));
					LeaveCriticalSection(&m_priv->m_csAccess);
					return false;
					}
				}
			i = 0;
			}
		
		if(rc != 0)
			break;

		rc = m_statics->m_db_blocks.getNext(c_blocks, &BlockEntry);
		}

	if(rc != gcfosdb_NOTFOUND)
		{
		}

	DEBUGLOG(("GCFOS_Client::ValidateLocalBlockCache: %I64u read\n", RecsRead));
	LeaveCriticalSection(&m_priv->m_csAccess);

	return true;
	}



   
 
 
 
             
    
 
     

