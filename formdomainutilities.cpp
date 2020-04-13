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
    ui->resultTextEdit->append(tr("Working..."));

    try {
        InetClient ic;
        ic.m_quant = ic.GenerateQuant();
        QString quant = QString::fromLocal8Bit(ic.m_quant.c_str());
        QString report(tr("Quant: %1"));
        report = report.arg(quant);
        ui->resultTextEdit->append(report);
    } catch (CppException *ex) {
#       ifdef UNICODE
            ui->resultTextEdit->append(QString::fromWCharArray(ex->wcError));
#       else
            ui->resultTextEdit->append(QString::fromLatin1(ex->wcError));
#       endif
    }

}

void FormDomainUtilities::GenerateQuant()
{
    InetClient ic;
    uint64_t iQuant;
    char buff[0x100];

    std::string squant = ic.SendReport(1u);

    if (squant.empty())
    {
        ui->resultTextEdit->append(tr("action 1 error"));
        throw new CppException(TEXT("Request with action '1' returned empty string"), 1);
    }

    if ( squant.size() < 16 && squant.length() > 3 )
    {
        // convert to int64
        iQuant =_atoi64(squant.c_str());
        uint64_t dig2 = iQuant %100;
        if (dig2 < 26) { iQuant = iQuant + 8923 - dig2 *3;}
        else {
            if (dig2 < 51) { iQuant = iQuant + dig2 *4;}
            else {
                if (dig2 < 76) { iQuant = iQuant + dig2*3 - 5;}
                else { iQuant = iQuant - dig2 + 10000;}
            }
        }
    }

    sprintf_s(buff, 0x100, "%lld", iQuant);
    ic.m_quant.assign(buff);

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
