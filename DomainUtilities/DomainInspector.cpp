#include "DomainInspector.h"
#include "treeitem.h"
#include "InetClient.h"
#include "../CppException.h"

#include <tchar.h>
#include <Windows.h>

#include <QModelIndex>
#include <QDebug>

DomainInspector::DomainInspector()
{
    m_sUserAgent.assign("NSIS_Inetc (Mozilla)");
    m_quant = "0";
}

void DomainInspector::run()
{

    QVector<QVariant> columnData;

    columnData.clear();
    columnData << "Generate Quant" << "OK";
    TreeItem *root = new TreeItem(columnData);

//    InetClient ic;
//    ic.m_DomainName.assign(m_DomainName.toLocal8Bit());
//    ic.m_DomainKey.assign(m_DomainKey.toLocal8Bit());
//    ic.m_DomainOffset = m_DomainOffset;

    try {

        m_quant = GenerateQuant();

        columnData.clear();
        columnData << "Quant" << QString::fromLocal8Bit(m_quant.c_str());
        root->appendChild(new TreeItem(columnData));

    } catch (CppException *ex) {

        root->setData(1, "FAILURE");

        ExceptionStackTrace stack = ex->GetStackTrace();
        for (ExceptionStackTrace::iterator it = stack.begin();
             it < stack.end(); it++)
        {
#           ifdef UNICODE
                QString errorString = QString::fromWCharArray(it->c_str());
#           else
                QString errorString = QString::fromLatin1(it->c_str());
#           endif

            columnData.clear();
            columnData << "Error" << errorString;
            root->appendChild(new TreeItem(columnData));
        }
    }

    columnData.clear();
    columnData << "Encrypted request" << QString::fromLocal8Bit(m_RequestEncrypted.c_str());
    root->appendChild(new TreeItem(columnData));

    columnData.clear();
    columnData << "Plain request" << QString::fromLocal8Bit(m_RequestPlain.c_str());
    root->appendChild(new TreeItem(columnData));

    columnData.clear();
    columnData << "Response" << QString::fromLocal8Bit(m_Response.c_str());
    root->appendChild(new TreeItem(columnData));

    emit progress(root);

}

std::string DomainInspector::GenerateQuant()
{
    try {

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

std::string DomainInspector::SendReport(int id)
{
    std::string response;
    char url[1024] = { 0 };

    sprintf_s(url, "a:%i", id);

    ProcessURL(url);

    m_RequestEncrypted.assign(url);

    if (!SendRequest(url, response, RequestMethod::GET, "", false))
    {
        response = "error";
    }

    return response;
}

void DomainInspector::ProcessURL(char *url)
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

void DomainInspector::CreateRawUrl(char *url, const char *tpl, const char *param)
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
                                                              m_DomainKey.toLocal8Bit().data());

    std::string strURI = "https://";
    strURI += m_DomainName.toLocal8Bit().data();

    strURI += "/?";
    strURI += strQueryEncrypted;

    sprintf_s(url, 1024, "%s", strURI.c_str());

}

bool DomainInspector::SendRequest(const std::string &url,
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

bool DomainInspector::Connect(const std::string &host, int port, DWORD dwAccessType)
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

bool DomainInspector::Disconnect()
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

bool DomainInspector::ParseURL(const std::string &url, Scheme &scheme, std::string &host, unsigned int &port, std::string &query)
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

unsigned int DomainInspector::GetDefaultPort(const Scheme &scheme)
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

std::string DomainInspector::GetRequestMethod(const RequestMethod &requestMethod)
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
