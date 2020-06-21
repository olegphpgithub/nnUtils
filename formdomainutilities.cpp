#include "formdomainutilities.h"
#include "ui_formdomainutilities.h"

#include "CppException.h"
#include "DomainUtilities/InetClient.h"


#include <QtWidgets>
#include <QNetworkAccessManager>
#include <QNetworkReply>

FormDomainUtilities::FormDomainUtilities(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormDomainUtilities)
{
    ui->setupUi(this);

    connect(ui->validateDomainPushButton,
            SIGNAL(clicked(bool)),
            this,
            SLOT(ValidateDomain()));

    connect(&m_manager,
            SIGNAL(finished( QNetworkReply*)),
            this,
            SLOT(onFinished(QNetworkReply*)));
}

FormDomainUtilities::~FormDomainUtilities()
{
    delete ui;
}

void FormDomainUtilities::ValidateDomain()
{
    ui->resultTextEdit->append(tr("Please wait..."));

    try {
        InetClient ic;
        ic.m_DomainName.assign(ui->domainNameLineEdit->text().toLocal8Bit());
        ic.m_DomainKey.assign(ui->domainKeyLineEdit->text().toLocal8Bit());
        ic.m_DomainOffset = ui->domainOffsetSpinBox->value();
        ic.m_quant = ic.GenerateQuant();
        QString quant = QString::fromLocal8Bit(ic.m_quant.c_str());
        QString report(tr("Quant: %1"));
        report = report.arg(quant);
        ui->resultTextEdit->append(tr("Quant generation was successful."));
        ui->resultTextEdit->append(report);
    } catch (CppException *ex) {
        ExceptionStackTrace stack = ex->GetStackTrace();
        for (ExceptionStackTrace::iterator it = stack.begin();
             it < stack.end(); it++)
        {
#           ifdef UNICODE
                ui->resultTextEdit->append(QString::fromWCharArray(it->c_str()));
#           else
                ui->resultTextEdit->append(QString::fromLatin1(it->c_str()));
#           endif
        }
    }

}

void FormDomainUtilities::onFinished(QNetworkReply *reply)
{
    if(reply->error() == QNetworkReply::NoError) {
        QString data = QString::fromUtf8( reply->readAll() );
        ui->resultTextEdit->append(data);

        ui->resultTextEdit->append(tr("Ready!"));
    } else {
        ui->resultTextEdit->append(reply->errorString());
    }
    reply->deleteLater();
}
