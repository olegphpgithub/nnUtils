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
            SLOT(CreateMutex())
            );
}

FormMutexUtility::~FormMutexUtility()
{
    delete ui;
}

void FormMutexUtility::CreateNamedMutex()
{
    wchar_t *lpcwMutexName;
    lpcwMutexName = new wchar_t[ui->mutexNameLineEdit->text().length() + 1];
    ui->mutexNameLineEdit->text().toWCharArray(lpcwMutexName);
    m_hMutex = ::CreateMutexW(NULL, FALSE, lpcwMutexName);
    ui->createMutexPushButton->setEnabled(false);
    delete []lpcwMutexName;
}
