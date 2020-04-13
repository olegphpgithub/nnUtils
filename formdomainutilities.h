#ifndef FORMDOMAINUTILITIES_H
#define FORMDOMAINUTILITIES_H

#include <QWidget>
#include <QNetworkAccessManager>

namespace Ui {
class FormDomainUtilities;
}

class QNetworkReply;

class FormDomainUtilities : public QWidget
{
    Q_OBJECT

public:
    explicit FormDomainUtilities(QWidget *parent = nullptr);
    ~FormDomainUtilities();

public slots:
    void ValidateDomain();
    void replyFinished();
    void onFinished(QNetworkReply *reply);

private:
    Ui::FormDomainUtilities *ui;
    QNetworkAccessManager m_manager;
};

#endif // FORMDOMAINUTILITIES_H
