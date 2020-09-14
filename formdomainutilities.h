#ifndef FORMDOMAINUTILITIES_H
#define FORMDOMAINUTILITIES_H

#include <QWidget>
#include <QNetworkAccessManager>
#include <QTextDocument>

namespace Ui {
class FormDomainUtilities;
}

class QNetworkReply;
class TreeModel;
class TreeItem;

class FormDomainUtilities : public QWidget
{
    Q_OBJECT

public:
    explicit FormDomainUtilities(QWidget *parent = nullptr);
    ~FormDomainUtilities();
    TreeModel *treeModel;
    QTextDocument textDocument;

public slots:
    void ValidateDomain();
    void onFinished(QNetworkReply *reply);
    void onActivated(const QModelIndex &index);
    void progress(TreeItem *index);

private:
    Ui::FormDomainUtilities *ui;
    QNetworkAccessManager m_manager;
};

#endif // FORMDOMAINUTILITIES_H
