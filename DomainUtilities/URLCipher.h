#pragma once

#include <string>

class URLCipher
{
public:
    static std::string WrapperEncrypt(const unsigned char *secure_data,
                                      const uint32_t secure_len,
                                      const char *secret_key);
    static std::string DownloaderDecrypt(std::string edata,
                                         const char *secret_key);
    static std::string URLEncode(const std::string &value);
};
