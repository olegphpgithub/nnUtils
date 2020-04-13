#pragma once
#include <vector>

class Base64
{
public:
    static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
    static std::vector<unsigned char> base64_decode(std::string const& encoded_string);
};
