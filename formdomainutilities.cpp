#include "formdomainutilities.h"
#include "ui_formdomainutilities.h"

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
    InetClient ic;
    ic.SendReport(1u);
    // std::string response;
    // ic.SendRequest("https://www.google.com", response, InetClient::GET, "", false);
    // MessageBoxA(NULL, response.c_str(), "2", MB_OK);
    // ui->resultTextEdit->append()
}

void FormDomainUtilities::replyFinished()
{

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
