#include "formdomaininspector.h"
#include "ui_formdomaininspector.h"

#include "CppException.h"
#include "treemodel.h"
#include "treeitem.h"
#include "DomainUtilities/InetClient.h"
#include "DomainUtilities/DomainInspector.h"

#include <QtWidgets>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QDebug>

FormDomainInspector::FormDomainInspector(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormDomainInspector)
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

    connect(ui->resultTreeView,
            SIGNAL(activated(const QModelIndex&)),
            this,
            SLOT(onActivated(const QModelIndex&)));

    QTextOption option = textDocument.defaultTextOption();
    option.setFlags(option.flags() | QTextOption::ShowTabsAndSpaces);
    option.setFlags(option.flags() | QTextOption::ShowLineAndParagraphSeparators);
    textDocument.setDefaultTextOption(option);
    textDocument.setDefaultFont(QFont(QString("Courier New")));
    ui->resultTextEdit->setDocument(&textDocument);
}

FormDomainInspector::~FormDomainInspector()
{
    delete ui;
}

void FormDomainInspector::ValidateDomain()
{
    treeModel = new TreeModel();
    DomainInspector *domainInspector = new DomainInspector();
    domainInspector->m_DomainName = ui->domainNameLineEdit->text();
    domainInspector->m_DomainKey = ui->domainKeyLineEdit->text();
    domainInspector->m_DomainOffset = ui->domainOffsetSpinBox->value();
    domainInspector->m_encodeMethod = DomainInspector::HEX;
    domainInspector->m_messageFormat = DomainInspector::SHORT;
    QObject::connect(domainInspector, SIGNAL(progress(TreeItem*)), this, SLOT(progress(TreeItem*)));
    QObject::connect(domainInspector, SIGNAL(finished()), domainInspector, SLOT(deleteLater()));
    domainInspector->start();
}

void FormDomainInspector::progress(TreeItem *index)
{
    if(index != nullptr)
    {
        treeModel->rootItem->appendChild(index);
        ui->resultTreeView->setModel(nullptr);
        ui->resultTreeView->setModel(treeModel);
    }
}

void FormDomainInspector::onFinished(QNetworkReply *reply)
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

void FormDomainInspector::onActivated(const QModelIndex &index)
{
    QModelIndex desiredIndex(index.model()->index(index.row(), 1, index.parent()));
    TreeItem *item = static_cast<TreeItem*>(desiredIndex.internalPointer());
    QString raw(item->data(1).toString());
    textDocument.setPlainText(raw);
}
