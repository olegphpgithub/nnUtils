#include "OwnershipMutexThread.h"

OwnershipMutexThread::OwnershipMutexThread(QObject *parent) : QThread(parent)
{

}

void OwnershipMutexThread::run()
{
    DWORD dwWaitResult = WaitForSingleObject(m_hMutex, INFINITE);

    switch (dwWaitResult)
    {

    case WAIT_OBJECT_0:
        emit QString("The thread got ownership of the mutex");

        WaitForSingleObject(m_hSemaphore, INFINITE);
        ReleaseMutex(m_hSemaphore);

        if (ReleaseMutex(m_hMutex))
        {
            emit QString("The thread released ownership of the mutex object");
        }
        else
        {
            emit QString("Could no released ownership of the mutex object");
        }
        break;

    case WAIT_ABANDONED:
        emit QString("The thread got ownership of an abandoned mutex");

    }

}

void OwnershipMutexThread::setMutexHandle(HANDLE handle)
{
    m_hMutex = handle;
}
