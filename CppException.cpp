#include "CppException.h"

#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <fstream>


CppException::CppException(CppException &obj)
                           : m_iLineCode(obj.m_iLineCode),
                           m_dwErrno(obj.m_dwErrno),
                           m_stack(obj.m_stack)
{
    _tcscpy_s(m_szFilePath, MAX_PATH, obj.m_szFilePath);
    
    if (obj.m_szError != NULL)
    {
        m_szError = new TCHAR[_tcslen(obj.m_szError) + 1];
        _tcscpy_s(m_szError, _tcslen(obj.m_szError) + 1, obj.m_szError);
    }
    else
    {
        m_szError = new TCHAR[1];
        m_szError[0] = TEXT('\0');
    }
}

CppException::~CppException(void)
{
    if (m_szError != NULL)
    {
        delete []m_szError;
    }
    if (m_stack != NULL)
    {
        delete m_stack;
    }
}

CppException::CppException(LPCTSTR file,
                           int line,
                           LPCTSTR errmess,
                           DWORD errcode,
                           CppException *stack)
                           : m_iLineCode(line),
                           m_dwErrno(errcode),
                           m_stack(stack)
{
    if(file != NULL)
    {
        _tcscpy_s(m_szFilePath, MAX_PATH, file);
    }
    else
    {
        memset(m_szFilePath, 0, MAX_PATH * sizeof(TCHAR));
    }
    
    if(errmess != NULL)
    {
        m_szError = new TCHAR[_tcslen(errmess) + 1];
        _tcscpy_s(m_szError, _tcslen(errmess) + 1, errmess);
    }
    else
    {
        m_szError = new TCHAR[0];
        m_szError[0] = TEXT('\0');
    }
}


CppException::CppException(LPCTSTR errmess,
                           DWORD errcode,
                           CppException *stack)
                           : m_dwErrno(errcode),
                           m_stack(stack)
{
    memset(m_szFilePath, 0, MAX_PATH * sizeof(TCHAR));
    
    m_iLineCode = 0;
    
    if(errmess != NULL)
    {
        m_szError = new TCHAR[_tcslen(errmess) + 1];
        _tcscpy_s(m_szError, _tcslen(errmess) + 1, errmess);
    } else {
        m_szError = new TCHAR(0);
    }
}


std::vector<std::basic_string<TCHAR> > CppException::GetStackTrace()
{
    std::vector<std::basic_string<TCHAR> > stack_trace;
    if (m_stack != NULL)
    {
        stack_trace = m_stack->GetStackTrace();
    }
    if( (_tcslen(m_szFilePath) > 0) && (m_iLineCode > 0) )
    {
        LPCTSTR szFormat = TEXT("%s:%d: %s: 0x%08lX");
        TCHAR szMessage[1024];
        _sntprintf_s(szMessage,
            1024,
            _TRUNCATE,
            szFormat,
            m_szFilePath,
            m_iLineCode,
            m_szError,
            m_dwErrno);
        stack_trace.insert(stack_trace.begin(), szMessage);
    }
    else
    {
        LPCTSTR szFormat = TEXT("%s: 0x%08lX");
        TCHAR szMessage[1024];
        _sntprintf_s(szMessage,
            1024,
            _TRUNCATE,
            szFormat,
            m_szError,
            m_dwErrno);
        stack_trace.insert(stack_trace.begin(), szMessage);
    }
    return stack_trace;
}


std::basic_string<TCHAR> CppException::GetFormatMessage(DWORD errcode)
{
    LPTSTR lpszMsgBuf = NULL;

    if( (errcode >= 12001) && (errcode <= 12156) )
    {
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_HMODULE |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            GetModuleHandle(TEXT("WinInet.dll")),
            errcode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpszMsgBuf,
            0,
            NULL);
    }
    else
    {
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errcode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpszMsgBuf,
            0,
            NULL);
    }

    std::basic_string<TCHAR> mess(TEXT(""));
    if(lpszMsgBuf != NULL)
    {
        mess.assign(lpszMsgBuf);
        mess.erase(0, mess.find_first_not_of(TEXT("\t\n\v\f\r ")));
        mess.erase(mess.find_last_not_of(TEXT("\t\n\v\f\r ")) + 1);
        LocalFree(lpszMsgBuf);
    }
    return mess;
}
