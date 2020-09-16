#include <tchar.h>
#include <Windows.h>

#include "InetClient.h"
#include "CppException.h"

#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <algorithm>
#include <iostream>
#include <fstream>

#include <WinInet.h>
#include <Winineti.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Ole32.lib")

#include <QRandomGenerator>

InetClient::InetClient(void)
{
	m_bUsePrevRND = false;
	m_bConnected  = false;
    m_hInternet   = m_hSession = nullptr;
	
    m_szSSLCert[IC_SSL_CERT_BUF_SIZE - 1] = '\0';
    m_sUserAgent.assign("NSIS_Inetc (Mozilla)");
    m_quant = "0";

}

InetClient::~InetClient(void)
{
	this -> Disconnect();
}

bool InetClient::Connect(const std::string &host,
                         int port = INTERNET_DEFAULT_HTTP_PORT,
                         DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG)
{
	m_bConnected = true;
	
	// Clear from preceding client usage if we forgot to disconnect:
	Disconnect();

	m_bConnected = true;
	
	// INTERNET_OPEN_TYPE_PRECONFIG - retrieves the proxy or direct configuration from the registry.
	// After the calling application has finished using the HINTERNET handle returned by InternetOpen, it must be closed using the InternetCloseHandle function.
    // Like all other aspects of the WinINet API, this function cannot be safely called from within DllMain or the constructors and destructors of global objects.
    if((m_hInternet = InternetOpenA(m_sUserAgent.c_str(), dwAccessType, nullptr, nullptr, 0)) == nullptr)
    {
        m_dwErr = GetLastError();
        m_bConnected = false;
    }
    
	// Like all other aspects of the WinINet API, this function cannot be safely called from within DllMain or the constructors and destructors of global objects.
    m_hSession = InternetConnectA(m_hInternet, host.c_str(), port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if( m_hSession == nullptr )
    {
        m_dwErr = GetLastError();
        m_bConnected = false;
        TCHAR lpszMessage[1024];
        _sntprintf_s(lpszMessage, 1024, _TRUNCATE, TEXT("InternetConnect failed with code 0x%X"), m_dwErr);
        throw new CppException(lpszMessage, m_dwErr);
    }

    return m_bConnected;
}

bool InetClient::Disconnect()
{
    if (m_bConnected)
    {
        // The function terminates any pending operations on the handle and discards any outstanding data.
        if(m_hSession != nullptr)
		{
			if( InternetCloseHandle(m_hSession) != NULL )
			{
                m_hSession   = nullptr;
				m_bConnected = false;
			}
			else
				m_dwErr = GetLastError();
		}
        if(m_hInternet != nullptr)
		{
			if( InternetCloseHandle(m_hInternet) != NULL )
			{
                m_hInternet  = nullptr;
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

bool InetClient::ParseURL(const std::string &url, InetClient::Scheme &scheme, std::string &host, unsigned int &port, std::string &query)
{
	std::string remains;
	
	// SplitURLScheme:
	{
    std::string delimiter("://");
    size_t delimiterIndex = url.find(delimiter);

	const bool noDelimiterFound		 = ( delimiterIndex == std::string::npos );
    const bool noDataBeforeDelimiter = ( delimiterIndex == 0 );
    const bool noDataAfterDelimiter  = ( delimiterIndex + delimiter.length() >= url.length() );

    if ( noDelimiterFound || noDataBeforeDelimiter || noDataAfterDelimiter )
        return false;

	std::string schemeStr = url.substr(0, delimiterIndex);
	std::transform(schemeStr.begin(), schemeStr.end(), schemeStr.begin(), ::tolower);

    if (schemeStr == "http")
	{
        scheme = Scheme::HTTP;
	}
	else
    if (schemeStr == "https")
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
    const size_t colonIndex = remains.find(':');
    const size_t slashIndex = remains.find('/');

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
        query = "/";
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
        return "GET";
    case RequestMethod::POST:
        return "POST";
    }
	
    return "";
}

typedef DWORD (WINAPI *pCertNameToStrA)(DWORD dwCertEncodingType, PCERT_NAME_BLOB pName, DWORD dwStrType, LPSTR psz, DWORD csz);
typedef void  (WINAPI *pCertFreeCertificateChain)(PCCERT_CHAIN_CONTEXT pChainContext);

bool InetClient::ObtainCertificate(LPCTSTR lpszDomainName)
{
    if((m_hInternet = InternetOpenA(m_sUserAgent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0)) == nullptr)
    {
        m_dwErr = GetLastError();
        m_bConnected = false;
    }
    return true;
}

bool InetClient::SendRequest(const std::string &url,
                             std::string &response,
                             const RequestMethod requestMethod /*= RequestMethod::GET*/,
                             const std::string &postData /*= _T("")*/,
                             bool bGetSSLCert /*= false*/)
{
    Scheme			scheme;
	std::string		host;
    unsigned int	port;
	std::string		query;
    
	if( ! ParseURL(url, scheme, host, port, query) )
	{
		return false;
	}
    
    DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG;
    
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

    HINTERNET hRequest = HttpOpenRequestA(m_hSession,
                                          GetRequestMethod(requestMethod).c_str(),
                                          query.c_str(),
                                          HTTP_VERSIONA,
                                          nullptr,
                                          nullptr,
                                          dwRequestFlags,
                                          0);



    if (hRequest == nullptr)
    {
        m_dwErr = GetLastError();
        Disconnect();
        TCHAR lpszMessage[1024];
        _sntprintf_s(lpszMessage, 1024, _TRUNCATE, TEXT("HttpOpenRequest failed with code 0x%X"), m_dwErr);
        throw new CppException(lpszMessage, m_dwErr);
    }
    
	BOOL retSend = FALSE;
    if (requestMethod == RequestMethod::POST)
    {
        char head[48] = "Content-Type: application/x-www-form-urlencoded";
		std::string headers = head;
        
        retSend = HttpSendRequestA(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()), LPVOID(postData.c_str()), static_cast<DWORD>(postData.length()));
    }
    else
	if (requestMethod == RequestMethod::GET)
	{
        retSend = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
	}

    if (retSend == NULL)
    {
        m_dwErr = GetLastError();
        InternetCloseHandle(hRequest);
        Disconnect();

        TCHAR lpszMessage[1024];
        _sntprintf_s(lpszMessage,
                     1024,
                     _TRUNCATE,
                     TEXT("HttpSendRequest failed. %s"),
                     CppException::GetFormatMessage(m_dwErr).c_str());
        throw new CppException(lpszMessage, m_dwErr);
    }

    DWORD statusCode = 0;
    DWORD length = sizeof(DWORD);
    HttpQueryInfo(hRequest,
                  HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                  &statusCode,
                  &length,
                  nullptr);

    if(statusCode != 200) {
        m_dwErr = GetLastError();
        InternetCloseHandle(hRequest);
        Disconnect();
        TCHAR lpszMessage[1024] = {0};
        _sntprintf_s(lpszMessage, 1024, _TRUNCATE, TEXT("Bad status code %d"), statusCode);
        throw new CppException(lpszMessage, m_dwErr);
    }

	if (bGetSSLCert)
	{
        PCCERT_CHAIN_CONTEXT CertCtxPtr = nullptr;
		
		// V568 It's odd that 'sizeof()' operator evaluates the size of a pointer to a class, but not the size of the 'CertCtx' class object.
		// Checked in debugger that InternetQueryOptions sets pointer to an address of some allocated struct:
		DWORD cbCertSizePtr = sizeof(CertCtxPtr);
		
		// Retrieves the server’s certificate-chain context as a duplicated PCCERT_CHAIN_CONTEXT.
		// You may pass this duplicated context to any Crypto API function which takes a PCCERT_CHAIN_CONTEXT.
		// You must call CertFreeCertificateChain on the returned PCCERT_CHAIN_CONTEXT when you are done with the certificate-chain context.
		// Version: Requires Internet Explorer 8.0.
        if ( InternetQueryOption(hRequest,
                                 INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT,
                                 reinterpret_cast<LPVOID>(&CertCtxPtr),
                                 &cbCertSizePtr))
		{
			PCCERT_CHAIN_CONTEXT pChainContext = CertCtxPtr;
            CERT_SIMPLE_CHAIN *simpleCertificateChainWithinContext = nullptr;
			
            pCertFreeCertificateChain fCertFreeCertificateChain = nullptr;

            if (pChainContext->rgpChain != nullptr)
			{
				simpleCertificateChainWithinContext=pChainContext->rgpChain[0];
				if  (simpleCertificateChainWithinContext->cElement > 0)
				{
                    PCCERT_CONTEXT pCertContext = simpleCertificateChainWithinContext->rgpElement[0]->pCertContext;
                    // Retrieve certificate issuer and save it into m_szSSLCert for future comparison:
                    CertNameToStrA(X509_ASN_ENCODING,
                                    &pCertContext->pCertInfo->Issuer,
                                    CERT_X500_NAME_STR,
                                    m_szSSLCert,
                                    IC_SSL_CERT_BUF_SIZE);
				}
			}
		
        if( fCertFreeCertificateChain != nullptr )
			fCertFreeCertificateChain(CertCtxPtr);

        CertCtxPtr = nullptr;
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

    ret = SendRequest(url, response, RequestMethod::GET, "", false);

    return ret;
}

bool InetClient::SendGetRequestWithSSLCert(const std::string &url, std::string &response, std::string &strCertificate)
{
	bool ret = false;
	
	for (int i = 0; i < IC_MAX_TRIES; i++)
	{
		// SendRequest get SSL cert and saves it in m_szSSLCert:
        if ( ret = SendRequest(url, response, RequestMethod::GET, "", true) )
		{
			strCertificate = m_szSSLCert;
			break;
		}
		
		if (i < IC_MAX_TRIES - 1)
            Sleep(IC_TRIES_DELAY);
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
            Sleep(IC_TRIES_DELAY);
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
    unsigned int	port;
	std::string		query;

	if( ! ParseURL(url, scheme, host, port, query) )
	{
		return false;
	}

    DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG;

    HINTERNET hInternet = InternetOpenA(m_sUserAgent.c_str(), dwAccessType, nullptr, nullptr, 0);
    if (hInternet == nullptr)
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

    char szHeader[20] = "Accept: */*\r\n\r\n";

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), szHeader, sizeof(szHeader) / sizeof(TCHAR) - 1, dwRequestFlags, 0);
    if (hConnect == nullptr)
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
        return nullptr;
}

// ------------------------------------
// Inet related functions from URLManager (ex Onion)
void InetClient::gen_random(char *s, const int len)
{
	const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
        quint32 size = QRandomGenerator::global()->generate();
		s[i] = alphanum[size % (sizeof(alphanum) - 1)];
	}
    
	s[len] = 0;

}

void InetClient::ProcessURL(char *url)
{
	std::string str = url;

	switch (url[0])
	{
		case 'a':
			if (str.find("a:") == 0)
			{
                str.erase(0, 2);
                m_action = str;
                CreateRawUrl(url, "F=1&T=1&NT=%s&N=%s", str.c_str());
			} break;
		case 'b':
			{
				if (str.find("b:") == 0)
				{
                    str.erase(0, 2);
                    CreateRawUrl(url, "%sscript=ipb.php&UID=%s&quant=%s&%s&rnd=%s", str.c_str());
				}
			} break;
		case 'p':
			{
				if (str.find("p3:") == 0)
				{
					str.erase(0,3);
                    CreateRawUrl(url, "%sscript=postdata3.php&UID=%s&quant=%s&%s&rnd=%s", str.c_str());
				}
				else
				{
					if (str.find("p4:") == 0)
					{
						str.erase(0, 3);
                        CreateRawUrl(url, "%sscript=postdata4.php&UID=%s&quant=%s&%s&rnd=%s", str.c_str());
					}
					else
					{
						if (str.find("px:") == 0)
						{
							str.erase(0, 3);
                            CreateRawUrl(url, "%sscript=pixel.php&UID=%s&quant=%s&%s&rnd=%s", str.c_str());
						}
						else
						{
							if (str.find("pf:") == 0)
							{
                                CreateRawUrl(url, "%sscript=fuse.php&UID=%s&quant=%s&%s&rnd=%s", "");
							}
							else
							{
								if (str.find("pt:") == 0)
								{
                                    CreateRawUrl(url, "%sscript=posttest.php&UID=%s&quant=%s&%s&rnd=%s", "");
								}
								else
								{
									if (str.find("pa:") == 0)
									{
                                        CreateRawUrl(url, "%sscript=addr.php&UID=%s&quant=%s&%s&rnd=%s", "");
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
                    CreateRawUrl(url, "%sscript=optin.php&UID=%s&quant=%s&f=%s&rnd=%s", str.c_str());
				}

			} break;
		case 'm':
			{
				if (str.find("m:") == 0)
				{
					str.erase(0, 2);
                    CreateRawUrl(url, "%sscript=info.php&UID=%s&quant=%s&%s&rnd=%s", str.c_str());
				}
				
			} break;
		case 'c':
			{
				if ( str.find("c3:") == 0)
				{
                    CreateRawUrl(url, "%sscript=cf3.php&UID=%s&quant=%s&%s&rnd=%s", "");
				}
			} break;
		case 'r':
			{
				
				if ( str.find("rk1:") == 0)
				{
                    CreateRawUrl(url, "%sscript=relevant.exe&UID=%s&quant=%s&%s&rnd=%s", "");
				}
			} break;
	}
	
	for (unsigned int i = 0; i < str.length(); i++) 
	{
		str[i] = 0;
	}
	
}

void InetClient::CreateRawUrl(char *url, const char *tpl, const char *param)
{
    char szPureURL[2048];
    size_t cbPureURL = 0;

    sprintf_s(
        szPureURL,
        2048,
        tpl,
        m_quant.c_str(),
        param
    );

    cbPureURL = strlen(szPureURL);

    m_RequestPlain.assign(szPureURL);

    std::string strQueryEncrypted = URLCipher::WrapperEncrypt(reinterpret_cast<unsigned char*>(szPureURL),
                                                              cbPureURL,
                                                              m_DomainKey.c_str());

    std::string strURI = "https://";
    strURI += m_DomainName;

    strURI += "/?";
	strURI += strQueryEncrypted;

    sprintf_s(url, 1024, "%s", strURI.c_str());
	
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
                pbuff[ *dwResultSize ] = param[pindex][j];
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

const char *InetClient::getDomain()
{
    return m_DomainName.c_str();
}

std::string InetClient::SendReport(int id)
{
	std::string response;
    char url[1024] = { 0 };
	
    sprintf_s(url, "a:%i", id);
	
	ProcessURL(url);

    m_RequestEncrypted.assign(url);
	
	if (!SendGetRequest(url, response))
	{
        response = "error";
	}

	return response;
}

/************************************************************************/
// send ipb.php
/************************************************************************/
std::string InetClient::SendReportWithParam(const char *szPath, const char *szParam)
{
	std::string response;
    char url[1024] = { 0 };
	
    sprintf_s(url, "%s:%s", szPath, szParam);
	
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
    std::string url = "https://";
	
	url += getDomain();
	
	// !!! SendGetRequest makes three attempts now:
	if ( ! SendGetRequest(url.c_str(), response))
	{
        Sleep(1000);
		
		if ( ! SendGetRequest(url.c_str(), response))
		{
			response = SendReport(2350); 
			
			// ! some hostings return '1', some return "1\r\n" in response:
			if (!(response.length() > 0 && response.length() < 4 && response[0] == '1'))
			{
				
                MessageBoxA(nullptr, "Internet connection not found.", "Error", MB_OK | MB_ICONERROR);
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

    char url[1024] = { 0 };
	
    sprintf_s(url, "a:%i", action);
	
	ProcessURL(url);
	
	if ( SendGetRequestWithSSLCert(url, response, strCertificate) )
	{
        if( strCertificate.find("C=US, S=CA, L=San Francisco, O=\"CloudFlare, Inc.\", CN=CloudFlare Inc ECC CA-2") != std::string::npos) {
			return true;
		} else {
            if( strCertificate.find("C=US, S=CA, L=San Francisco, O=\"CloudFlare, Inc.\", CN=CloudFlare Inc RSA CA-1") != std::string::npos) {
				return true;
			} else {
                if( strCertificate.find("C=US, ST=CA, L=San Francisco, O=CloudFlare, Inc., CN=CloudFlare") != std::string::npos) {
					return true;
				} else {
                    if( strCertificate.find("C=US, O=Let's Encrypt, CN=Let's Encrypt") != std::string::npos) {
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
    std::string url = "https://";

	url += getDomain();

	// !!! SendGetRequest makes three attempts now:
	if (!SendGetRequestWithSSLCert(url.c_str(), response, strCertificate))
	{
        Sleep(1000);

		if (!SendGetRequestWithSSLCert(url.c_str(), response, strCertificate))
		{
			response = SendReport(2350); 

			// ! some hostings return '1', some return "1\r\n" in response:
			if (!(response.length() > 0 && response.length() < 4 && response[0] == '1'))
			{
                MessageBoxA(nullptr, "Internet connection not found.", "Error", MB_OK | MB_ICONERROR);
				return false;
			}
		}
	}
	
    if( strCertificate.find("C=US, S=CA, L=San Francisco, O=\"CloudFlare, Inc.\", CN=CloudFlare Inc ECC CA-2") != std::string::npos)
	{
		SSLSuccess = true;
    }
    else
	{
        if( strCertificate.find("C=US, S=CA, L=San Francisco, O=\"CloudFlare, Inc.\", CN=CloudFlare Inc RSA CA-1") != std::string::npos)
		{
			SSLSuccess = true;
        }
        else
		{
            if( strCertificate.find("C=US, ST=CA, L=San Francisco, O=CloudFlare, Inc., CN=CloudFlare") != std::string::npos)
			{
				SSLSuccess = true;
            }
            else
			{
                if( strCertificate.find("C=US, O=Let's Encrypt, CN=Let's Encrypt") != std::string::npos)
				{
					SSLSuccess = true;
				}
			}
		}
	}

	return true;
}


std::string InetClient::GenerateGuid()
{
    GUID guid;
    HRESULT hCreateGuid = CoCreateGuid(&guid);
    if(hCreateGuid != ERROR_SUCCESS)
    {
        throw new CppException(TEXT("CoCreateGuid failed"), GetLastError());
    }

    char szBuf[256];

    sprintf_s(szBuf,
              256,
              "%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
              guid.Data1,
              guid.Data2,
              guid.Data3,
              guid.Data4[0],
              guid.Data4[1],
              guid.Data4[2],
              guid.Data4[3],
              guid.Data4[4],
              guid.Data4[5],
              guid.Data4[6],
              guid.Data4[7]);

    return std::string(szBuf);
}


std::string InetClient::GenerateQuant()
{
    try {
        InetClient::GenerateGuid();

        __int64 iQuant = 1234567890;
        char buff[0x100];

        m_Response = SendReport(1 + m_DomainOffset);

        std::string squant(m_Response);
        squant.erase(0, squant.find_first_not_of("\t\n\v\f\r "));
        squant.erase(squant.find_last_not_of("\t\n\v\f\r ") + 1);

        if (squant.empty())
        {
            throw new CppException(TEXT("Request with action '1' returned empty string"), 1);
        }

        if ( squant.length() > 16 || squant.length() < 3 )
        {
            throw new CppException(TEXT("Response string must be grather than 3 and less than 16"), 1);
        }

        iQuant =_atoi64(squant.c_str());
        __int64 dig2 = iQuant %100;
        if (dig2 < 26)
        {
            iQuant = iQuant + 8923 - dig2 * 3;
        }
        else
        {
            if (dig2 < 51)
            {
                iQuant = iQuant + dig2 * 4;
            }
            else
            {
                if (dig2 < 76)
                {
                    iQuant = iQuant + dig2 * 3 - 5;
                }
                else
                {
                    iQuant = iQuant - dig2 + 10000;
                }
            }
        }

        sprintf_s(buff, 0x100, "%lld", iQuant);
        return std::string(buff);

    } catch(CppException *ex) {
        throw new CppException(TEXT("GenerateQuant failed"), ex->m_dwErrno, ex);
    }
}
