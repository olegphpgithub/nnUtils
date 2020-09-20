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

    connect(ui->CloseMutexPushButton,
            SIGNAL(pressed()),
            this,
            SLOT(CloseNamedMutex())
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

    wchar_t *lpcwMutexName;
    uint32_t cchMutexName = ui->mutexNameLineEdit->text().length() + 1;
    lpcwMutexName = new wchar_t[cchMutexName];
    ZeroMemory(lpcwMutexName, cchMutexName * sizeof(wchar_t));
    ui->mutexNameLineEdit->text().toWCharArray(lpcwMutexName);
    m_hMutex = ::CreateMutexW(NULL, FALSE, lpcwMutexName);
    DWORD dwLastError = GetLastError();
    if (dwLastError != ERROR_SUCCESS)
    {
        m_hMutex = NULL;
        QString lastError = QString::fromStdWString(CppException::GetFormatMessage(dwLastError));
        QMessageBox messageBox(QMessageBox::Critical, QString(tr("Critical error")), tr("Could not open named mutex."), QMessageBox::Cancel);
        messageBox.setDetailedText(lastError);
        messageBox.exec();
    }
    else
    {
        log("Mutex was created succussfully");
        ui->createMutexPushButton->setEnabled(false);
        ui->openMutexPushButton->setEnabled(false);
        ui->CloseMutexPushButton->setEnabled(true);
        ui->ownershipMutexPushButton->setEnabled(true);
        ui->releaseMutexPushButton->setEnabled(false);
    }
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
    if (dwLastError != ERROR_SUCCESS)
    {
        m_hMutex = NULL;
        QString lastError = QString::fromStdWString(CppException::GetFormatMessage(dwLastError));
        QMessageBox messageBox(QMessageBox::Critical, QString(tr("Critical error")), tr("Could not open named mutex."), QMessageBox::Cancel);
        messageBox.setDetailedText(lastError);
        messageBox.exec();
    }
    else
    {
        log("Mutex was opened succussfully");
        ui->createMutexPushButton->setEnabled(false);
        ui->openMutexPushButton->setEnabled(false);
        ui->CloseMutexPushButton->setEnabled(true);
        ui->ownershipMutexPushButton->setEnabled(true);
        ui->releaseMutexPushButton->setEnabled(false);
    }
}

void FormMutexUtility::CloseNamedMutex()
{
    CloseHandle(m_hMutex);
    ui->createMutexPushButton->setEnabled(true);
    ui->openMutexPushButton->setEnabled(true);
    ui->CloseMutexPushButton->setEnabled(false);
    ui->ownershipMutexPushButton->setEnabled(false);
    ui->releaseMutexPushButton->setEnabled(false);
}

void FormMutexUtility::OwnershipMutex()
{
    ui->ownershipMutexPushButton->setEnabled(false);
    m_hSemaphore = CreateMutexW(NULL, TRUE, NULL);
    OwnershipMutexThread *thread = new OwnershipMutexThread(this);
    connect(thread, SIGNAL(submitLog(QString)), this, SLOT(log(QString)));
    connect(thread, SIGNAL(submitResult(bool)), this, SLOT(OwnershipGotten(bool)));
    thread->setMutexHandle(m_hMutex);
    thread->setSemaphoreHandle(m_hSemaphore);
    thread->start();
}

void FormMutexUtility::OwnershipGotten(bool result)
{
    if(result)
    {
        ui->releaseMutexPushButton->setEnabled(true);
    }
    else
    {
        ui->ownershipMutexPushButton->setEnabled(true);
        ui->releaseMutexPushButton->setEnabled(false);
    }
}

void FormMutexUtility::ReleaseNamedMutex()
{
    ui->ownershipMutexPushButton->setEnabled(true);
    ui->releaseMutexPushButton->setEnabled(false);
    ReleaseMutex(m_hSemaphore);
}
