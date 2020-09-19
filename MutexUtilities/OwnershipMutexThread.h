#ifndef OWNERSHIPMUTEXTHREAD_H
#define OWNERSHIPMUTEXTHREAD_H

#include <QThread>

#include <Windows.h>

class OwnershipMutexThread : public QThread
{
    Q_OBJECT
    HANDLE m_hMutex;
    HANDLE m_hSemaphore;
public:
    explicit OwnershipMutexThread(QObject *parent = nullptr);
    void run();
    void setMutexHandle(HANDLE handle);
    void setSemaphoreHandle(HANDLE handle);
signals:
    void submitLog(QString);
    void submitResult(bool);
};

#endif // OWNERSHIPMUTEXTHREAD_H
