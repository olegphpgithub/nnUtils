#include "OwnershipMutexThread.h"

#include <QDebug>

OwnershipMutexThread::OwnershipMutexThread(QObject *parent) : QThread(parent)
{

}

void OwnershipMutexThread::run()
{
    emit submitLog("Please wait...");
    DWORD dwWaitResult = WaitForSingleObject(m_hMutex, INFINITE);
    emit submitResult(true);

    switch (dwWaitResult)
    {

    case WAIT_OBJECT_0:
        emit submitLog("The thread got ownership of the mutex");

        WaitForSingleObject(m_hSemaphore, INFINITE);
        ReleaseMutex(m_hSemaphore);

        if (ReleaseMutex(m_hMutex))
        {
            emit submitLog("The thread released ownership of the mutex object");
        }
        else
        {
            emit submitLog("Could no released ownership of the mutex object");
        }
        break;

    case WAIT_ABANDONED:
        emit submitLog("The thread got ownership of an abandoned mutex");
        emit submitResult(false);
    }

}

void OwnershipMutexThread::setMutexHandle(HANDLE handle)
{
    m_hMutex = handle;
}

void OwnershipMutexThread::setSemaphoreHandle(HANDLE handle)
{
    m_hSemaphore = handle;
}
