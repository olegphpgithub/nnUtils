#include "formmutexutility.h"
#include "ui_formmutexutility.h"

FormMutexUtility::FormMutexUtility(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormMutexUtility)
{
    ui->setupUi(this);
}

FormMutexUtility::~FormMutexUtility()
{
    delete ui;
}
