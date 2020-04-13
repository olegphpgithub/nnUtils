#ifndef _AES_H_
#define _AES_H_

#if _MSC_VER < 1900
	#include "stdint.h"
#endif // _MSC_VER < 1900

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif


//#define AES128 1
//#define AES192 1
#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif


class TinyAES {

public:
    
    struct AES_ctx
    {
        uint8_t RoundKey[AES_keyExpSize];
        #if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
            uint8_t Iv[AES_BLOCKLEN];
        #endif
    };

    void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    #if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
        void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
        void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
    #endif

    #if defined(ECB) && (ECB == 1)
        // buffer size is exactly AES_BLOCKLEN bytes; 
        // you need only AES_init_ctx as IV is not used in ECB 
        // NB: ECB is considered insecure for most uses
        void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
        void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
    #endif // #if defined(ECB) && (ECB == !)


    #if defined(CBC) && (CBC == 1)
        // buffer size MUST be mutile of AES_BLOCKLEN;
        // Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
        // NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
        //        no IV should ever be reused with the same key 
        void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
        void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
    #endif // #if defined(CBC) && (CBC == 1)


    #if defined(CTR) && (CTR == 1)
        // Same function for encrypting as for decrypting. 
        // IV is incremented for every block, and used after encryption as XOR-compliment for output
        // Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
        // NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
        //        no IV should ever be reused with the same key 
        void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
    #endif // #if defined(CTR) && (CTR == 1)

private:
    /*****************************************************************************/
    /* Private variables:                                                        */
    /*****************************************************************************/
    // state - array holding the intermediate results during decryption.
    typedef uint8_t state_t[4][4];

    static const uint8_t TinyAES::sbox[256];
    static const uint8_t TinyAES::rsbox[256];
    static const uint8_t TinyAES::Rcon[11];

    void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key);
    void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);
    void SubBytes(state_t* state);
    void ShiftRows(state_t* state);
    uint8_t xtime(uint8_t x);
    void MixColumns(state_t* state);
    void InvMixColumns(state_t* state);
    void InvSubBytes(state_t* state);
    void InvShiftRows(state_t* state);
    void Cipher(state_t* state, const uint8_t* RoundKey);
    void InvCipher(state_t* state, const uint8_t* RoundKey);
    void XorWithIv(uint8_t* buf, const uint8_t* Iv);
};

#endif //_AES_H_
