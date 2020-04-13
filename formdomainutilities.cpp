#include "formdomainutilities.h"
#include "ui_formdomainutilities.h"

FormDomainUtilities::FormDomainUtilities(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormDomainUtilities)
{
    ui->setupUi(this);
}

FormDomainUtilities::~FormDomainUtilities()
{
    delete ui;
}
