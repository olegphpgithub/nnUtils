#ifndef FORMDOMAININSPECTOR_H
#define FORMDOMAININSPECTOR_H

#include <QWidget>
#include <QNetworkAccessManager>
#include <QTextDocument>

namespace Ui {
class FormDomainInspector;
}

class QNetworkReply;
class TreeModel;
class TreeItem;

class FormDomainInspector : public QWidget
{
    Q_OBJECT

public:
    explicit FormDomainInspector(QWidget *parent = nullptr);
    ~FormDomainInspector();
    TreeModel *treeModel;
    QTextDocument textDocument;

public slots:
    void ValidateDomain();
    void onFinished(QNetworkReply *reply);
    void onActivated(const QModelIndex &index);
    void progress(TreeItem *index);

private:
    Ui::FormDomainInspector *ui;
    QNetworkAccessManager m_manager;
};

#endif // FORMDOMAININSPECTOR_H
