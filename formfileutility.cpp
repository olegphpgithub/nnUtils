#include "formfileutility.h"
#include "ui_formfileutility.h"

#include <QtGui>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>

#include <Windows.h>

FormFileUtility::FormFileUtility(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormFileUtility)
{
    ui->setupUi(this);
    connect(ui->chooseFileToolButton,
            SIGNAL(pressed()),
            this,
            SLOT(ChooseFile())
            );
    connect(ui->lockFilePushButton,
            SIGNAL(pressed()),
            this,
            SLOT(LockFile()));
    m_hFile = nullptr;
}

FormFileUtility::~FormFileUtility()
{
    delete ui;
}

void FormFileUtility::ChooseFile()
{
    QString fileName = QFileDialog::getOpenFileName(
        this,
        tr("Choose a file"),
        "",
        tr("All files (*)")
        );
    if(!(fileName.isNull() || fileName.isEmpty())) {
        ui->chooseFileLineEdit->setText(fileName);
    }
    ui->chooseFileLineEdit->setFocus();
}

void FormFileUtility::LockFile()
{
    QString fileName = ui->chooseFileLineEdit->text();

    if(fileName.isNull() || fileName.isEmpty())
    {
        QMessageBox::critical(this,
                              tr("User error"),
                              tr("The file name must be specified."),
                              QMessageBox::Cancel);
        return;
    }

    if(!QFileInfo::exists(fileName))
    {
        QMessageBox::critical(this,
                              tr("User error"),
                              tr("File was not found."),
                              QMessageBox::Cancel);
        return;
    }

    if(m_hFile == nullptr)
    {
        ui->chooseFileLineEdit->setEnabled(false);
        ui->chooseFileToolButton->setEnabled(false);

        wchar_t lpszFileName[MAX_PATH] = {0};
        fileName.toWCharArray(lpszFileName);
        m_hFile = ::CreateFileW(
            lpszFileName,
            GENERIC_READ,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );
        if(m_hFile != nullptr && m_hFile != INVALID_HANDLE_VALUE)
        {
            DWORD dwFileSize = ::GetFileSize(m_hFile, nullptr);
            OVERLAPPED sOverlapped;
            sOverlapped.Offset = 0;
            sOverlapped.OffsetHigh = 0;
            BOOL OK = ::LockFileEx(
                m_hFile,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                dwFileSize,
                0,
                &sOverlapped
            );
            if(OK)
            {
                ui->lockFilePushButton->setText(tr("Unlock file"));
                return;
            }
            else
            {
                ::CloseHandle(m_hFile);
                m_hFile = nullptr;
            }
        }
    } else {
        ::CloseHandle(m_hFile);
        ui->lockFilePushButton->setText(tr("Lock file"));
        m_hFile = nullptr;

        ui->chooseFileLineEdit->setEnabled(true);
        ui->chooseFileToolButton->setEnabled(true);
    }
}
