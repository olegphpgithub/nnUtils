#include "formmutexutility.h"
#include "ui_formmutexutility.h"

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
}

FormMutexUtility::~FormMutexUtility()
{
    delete ui;
}

void FormMutexUtility::CreateNamedMutex()
{
    wchar_t *lpcwMutexName;
    uint32_t cchMutexName = ui->mutexNameLineEdit->text().length() + 1;
    lpcwMutexName = new wchar_t[cchMutexName];
    ZeroMemory(lpcwMutexName, cchMutexName * sizeof(wchar_t));
    ui->mutexNameLineEdit->text().toWCharArray(lpcwMutexName);
    m_hMutex = ::CreateMutexW(NULL, FALSE, lpcwMutexName);
    ui->createMutexPushButton->setEnabled(false);
    delete []lpcwMutexName;
}
