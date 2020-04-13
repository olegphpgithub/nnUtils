#include "CppException.h"

#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <fstream>

using namespace std;


CppException::~CppException(void)
{
    
}

CppException::CppException(LPCTSTR file, int line,
    LPCTSTR error, HRESULT hr) {
    
    CppInitialize();
    
    size_t sizeInWords = 0;
    
    size_t bcfile = 0;
    StringCchLength(file, STRSAFE_MAX_CCH, &bcfile);
    bcfile++;
    wcFilePath=(TCHAR *) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, bcfile * sizeof(TCHAR));
    StringCchCopy(wcFilePath, bcfile, file);
    
    iLineCode = line;
    
    size_t wcerror = 0;
    StringCchLength(error, STRSAFE_MAX_CCH, &wcerror);
    size_t bcerror = (wcerror + 1) * sizeof(TCHAR);
    wcError = (TCHAR *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, bcerror);
    StringCbCopy(wcError, bcerror, error);
    
    herr = hr;
    
}


CppException::CppException(LPCTSTR error, HRESULT hr) {
    
    CppInitialize();
    
    size_t wcerror = 0;
    StringCchLength(error, STRSAFE_MAX_CCH, &wcerror);
    size_t bcerror = (wcerror + 1) * sizeof(TCHAR);
    wcError = (TCHAR *)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, bcerror);
    StringCbCopy(wcError, bcerror, error);

    herr = hr;
    
}


void CppException::CppInitialize(void) {
    wcFilePath = NULL;
    iLineCode = 0;
    herr = S_OK;
}


void CppException::log(HRESULT hr) {
    
    
}