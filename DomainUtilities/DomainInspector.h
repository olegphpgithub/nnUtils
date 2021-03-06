#ifndef DOMAININSPECTOR_H
#define DOMAININSPECTOR_H

#include <tchar.h>
#include <Windows.h>
#include <WinInet.h>
#include <Winineti.h>

#include <QThread>

class QModelIndex;
class TreeItem;

class DomainInspector : public QThread
{
    Q_OBJECT

public:
    DomainInspector();
    void run();
    std::string GenerateQuant();
    TreeItem *rootItem;
    QString m_DomainName;
    QString m_DomainKey;
    unsigned int m_DomainOffset = 0;

    HINTERNET		m_hInternet;
    HINTERNET		m_hSession;
    DWORD			m_dwErr;
    QString m_UserAgent;
    bool			m_bConnected;

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

    enum EncodeMethod {
        HEX,
        BASE64
    } m_encodeMethod;

    enum MessageFormat {
        SCRIPT,
        SHORT,
    } m_messageFormat;

    std::string m_action;
    std::string m_UID;
    std::string m_quant;
    std::string m_RND;
    std::string m_RequestPlain;
    QString m_RequestEncrypted;
    std::string m_Response;

    std::string SendReport(int id);
    bool SendRequest(const std::string &url,
                                 std::string &response,
                                 const RequestMethod requestMethod /*= RequestMethod::GET*/,
                                 const std::string &postData /*= _T("")*/,
                                 bool bGetSSLCert /*= false*/);
    bool Connect(const std::string &host,
                             int port = INTERNET_DEFAULT_HTTP_PORT,
                             DWORD dwAccessType = INTERNET_OPEN_TYPE_PRECONFIG);
    bool Disconnect();
    bool ParseURL(const std::string &url, Scheme &scheme, std::string &host, unsigned int &port, std::string &query);
    static std::string WrapperEncrypt(const unsigned char *secure_data,
                                      const uint32_t secure_len,
                                      const char *secret_key,
                                      EncodeMethod enc_method);
    static std::string URLEncode(const std::string &value);
    unsigned int	GetDefaultPort(const Scheme &scheme);
    std::string		GetRequestMethod(const RequestMethod &requestMethod);

signals:
    void progress(TreeItem *status);
};

Q_DECLARE_METATYPE(DomainInspector::EncodeMethod);

#endif // DOMAININSPECTOR_H
