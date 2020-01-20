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

    if(!QFileInfo::exists(fileName))
    {
        QMessageBox::critical(this,
                              tr("Critical error"),
                              tr("File was not found."),
                              QMessageBox::Cancel);
        return;
    }

    if(m_hFile == nullptr)
    {
        wchar_t lpszFileName[MAX_PATH] = {0};
        fileName.toWCharArray(lpszFileName);
        m_hFile = ::CreateFileW(lpszFileName,
                            GENERIC_WRITE,
                            0,
                            nullptr,
                            OPEN_EXISTING,
                            0,
                            nullptr);
        // DWORD dwLastError = GetLastError();
        if(m_hFile != nullptr && m_hFile != INVALID_HANDLE_VALUE)
        {
            ui->lockFilePushButton->setText(tr("Unlock file"));
            return;
        }
    } else {
        ::CloseHandle(m_hFile);
        ui->lockFilePushButton->setText(tr("Lock file"));
        m_hFile = nullptr;
    }
}
