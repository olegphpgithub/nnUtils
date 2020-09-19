#include "formmutexutility.h"
#include "ui_formmutexutility.h"

#include "CppException.h"
#include "MutexUtilities/OwnershipMutexThread.h"

#include <QMessageBox>

FormMutexUtility::FormMutexUtility(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormMutexUtility)
{
    ui->setupUi(this);

    connect(ui->createMutexPushButton,
            SIGNAL(pressed()),
            this,
            SLOT(CreateNamedMutex())
            );

    connect(ui->openMutexPushButton,
            SIGNAL(pressed()),
            this,
            SLOT(OpenNamedMutex())
            );

    connect(ui->ownershipMutexPushButton,
            SIGNAL(pressed()),
            this,
            SLOT(OwnershipMutex())
            );

    connect(ui->releaseMutexPushButton,
            SIGNAL(pressed()),
            this,
            SLOT(ReleaseNamedMutex())
            );

    m_hMutex = NULL;
    m_hSemaphore = NULL;
}

FormMutexUtility::~FormMutexUtility()
{
    delete ui;
}

void FormMutexUtility::log(QString logString)
{
    ui->resultTextEdit->append(logString);
}

void FormMutexUtility::CreateNamedMutex()
{
    ui->createMutexPushButton->setEnabled(false);
    ui->ownershipMutexPushButton->setEnabled(true);
    ui->releaseMutexPushButton->setEnabled(false);
    wchar_t *lpcwMutexName;
    uint32_t cchMutexName = ui->mutexNameLineEdit->text().length() + 1;
    lpcwMutexName = new wchar_t[cchMutexName];
    ZeroMemory(lpcwMutexName, cchMutexName * sizeof(wchar_t));
    ui->mutexNameLineEdit->text().toWCharArray(lpcwMutexName);
    m_hMutex = ::CreateMutexW(NULL, FALSE, lpcwMutexName);
    ui->createMutexPushButton->setEnabled(false);
    delete []lpcwMutexName;
}

void FormMutexUtility::OpenNamedMutex()
{
    wchar_t *lpcwMutexName;
    uint32_t cchMutexName = ui->mutexNameLineEdit->text().length() + 1;
    lpcwMutexName = new wchar_t[cchMutexName];
    ZeroMemory(lpcwMutexName, cchMutexName * sizeof(wchar_t));
    ui->mutexNameLineEdit->text().toWCharArray(lpcwMutexName);
    m_hMutex = ::OpenMutexW(SYNCHRONIZE, FALSE, lpcwMutexName);

    DWORD dwLastError = GetLastError();
    if(dwLastError != ERROR_SUCCESS)
    {
        m_hMutex = NULL;
        QString lastError = QString::fromStdWString(CppException::GetFormatMessage(dwLastError));
        QMessageBox messageBox(QMessageBox::Critical, QString(tr("Critical error")), tr("Could not open named mutex."), QMessageBox::Cancel);
        messageBox.setDetailedText(lastError);
        messageBox.exec();
    }

    if(m_hMutex != INVALID_HANDLE_VALUE)
    {
        log("Mutex was opened succussfully");
        ui->createMutexPushButton->setEnabled(false);
        ui->ownershipMutexPushButton->setEnabled(true);
        ui->releaseMutexPushButton->setEnabled(false);
    }
}

void FormMutexUtility::OwnershipMutex()
{
    ui->ownershipMutexPushButton->setEnabled(false);
    ui->releaseMutexPushButton->setEnabled(true);
    m_hSemaphore = CreateMutexW(NULL, TRUE, NULL);
    OwnershipMutexThread *thread = new OwnershipMutexThread(this);
    connect(thread, SIGNAL(submitLog(QString)), this, SLOT(log(QString)));
    thread->setMutexHandle(m_hMutex);
    thread->setSemaphoreHandle(m_hSemaphore);
    thread->start();
}

void FormMutexUtility::ReleaseNamedMutex()
{
    ui->ownershipMutexPushButton->setEnabled(true);
    ui->releaseMutexPushButton->setEnabled(false);
    ReleaseMutex(m_hSemaphore);
}
