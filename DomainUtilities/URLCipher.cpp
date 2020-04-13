#include "URLCipher.h"
#include "TinyAES.h"
#include "Base64.h"

#include <Windows.h>
#include <WinInet.h>


std::string URLCipher::WrapperEncrypt(const unsigned char *secure_data,
                                      const uint32_t secure_len,
                                      const char *secret_key)
{
    TinyAES aes;

    uint32_t size_aligned = secure_len + 15;
    size_aligned = size_aligned / 16;
    size_aligned = size_aligned * 16;
    uint8_t *inbuff = new uint8_t[size_aligned];
    memset(inbuff, 0xAA, size_aligned);
    memcpy_s(inbuff, size_aligned, secure_data, secure_len);

    TinyAES::AES_ctx ctx;
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    memcpy_s(key, strlen(secret_key), secret_key, strlen(secret_key));
    aes.AES_init_ctx_iv(&ctx, key, iv);
    SecureZeroMemory(key, 32);

    for (uint32_t i = 0; i < size_aligned; i+= 16)
    {
        for (uint32_t j = 0; j < 16; j++)
        {
            inbuff[i+j] = inbuff[i+j] ^ 0xAA;
        }
        aes.AES_CBC_encrypt_buffer(&ctx, inbuff + i, 16);
    }
    SecureZeroMemory(ctx.RoundKey, sizeof(ctx.RoundKey));
    SecureZeroMemory(ctx.Iv, sizeof(ctx.Iv));
    
    std::string edata = Base64::base64_encode(inbuff, size_aligned);
    edata = URLEncode(edata);
	delete [] inbuff;
    return edata;
}


std::string URLCipher::DownloaderDecrypt(std::string edata, const char *secret_key)
{
    TinyAES aes;
    std::string rdata;

    TinyAES::AES_ctx ctx;
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    memcpy_s(key, strlen(secret_key), secret_key, strlen(secret_key));
    aes.AES_init_ctx_iv(&ctx, key, iv);
    SecureZeroMemory(key, 32);

    std::vector<unsigned char> raw = Base64::base64_decode(edata);

    if (raw.size() < 16) {
        rdata.assign("error");
        return rdata;
    }

	if (raw.size() % 16 != 0) {
		rdata.assign("error");
		return rdata;
	}

    for (uint32_t i = 0; i < raw.size(); i += 16)
    {
        aes.AES_CBC_decrypt_buffer(&ctx, reinterpret_cast<unsigned char*>(&raw[i]), 16);
    }

    for (unsigned i = 16 ; i < raw.size(); i++)
    {
        // copy only correct chars
        if (( raw[i] >= 0x10 )&&( raw[i] <= 0x7F ))
        {
            rdata += raw[i];
        }
    }

    raw.clear();
    return rdata;
}


std::string URLCipher::URLEncode(const std::string &value)
{
    const char DEC2HEX[16 + 1] = "0123456789ABCDEF";

    std::string escaped = "";

    for(unsigned int i = 0; i < value.length(); i++)
    {
        if( value[i] == '%' || value[i] == '$' || value[i] == '&' || value[i] == '+' || value[i] == ','  ||
            value[i] == '/' || value[i] == ':' || value[i] == '[' || value[i] == ']' || value[i] == '\\' ||
            value[i] == ';' || value[i] == '=' || value[i] == '?' || value[i] == '@' || value[i] == '#'  ||
            value[i] < 0x20 || value[i] > 0x7E )
        {
            escaped += '%';
            escaped += DEC2HEX[ (value[i] >> 4) & 0x0F];
            escaped += DEC2HEX[ value[i] & 0x0F];
        }
        else
        {
            if(value[i] == ' ')
            {
                escaped += '+';
            }
            else
            {
                escaped += value[i];
            }
        }
    }

    return escaped;
}
