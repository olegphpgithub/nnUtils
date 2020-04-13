#pragma once

class URLCipher
{
public:
    static std::string URLCipher::WrapperEncrypt(const unsigned char *secure_data, const int secure_len, const char *secret_key);
    static std::string URLCipher::DownloaderDecrypt(std::string edata, const char *secret_key);
};
