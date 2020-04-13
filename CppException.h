#pragma once

#include <iostream>
#include <windows.h>

#define ERROR_REPORTING 1

#if ERROR_REPORTING == 1
    #define RAISE_APPLICATION_ERROR(ERROR, ERRNO) \
        throw new CppException(TEXT(__FILE__), __LINE__, ERROR, ERRNO)
#else if ERROR_REPORTING == 0
    #define RAISE_APPLICATION_ERROR(ERROR, ERRNO) \
        throw new CppException(ERROR, ERRNO)
#endif

class CppException
{
public:
    CppException(HRESULT hr);
    CppException(LPCTSTR error, HRESULT hr);
    CppException(LPCTSTR file, int line, LPCTSTR error, HRESULT hr);
    ~CppException(void);
    
    void CppInitialize(void);
    
    static void log(HRESULT hr);
    
    TCHAR *wcFilePath;
    int iLineCode;
    TCHAR *wcError;
    HRESULT herr;
};
