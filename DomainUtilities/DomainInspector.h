#ifndef DOMAININSPECTOR_H
#define DOMAININSPECTOR_H

#include <QThread>

class QModelIndex;
class TreeItem;

class DomainInspector : public QThread
{
    Q_OBJECT

public:
    DomainInspector();
    void run();
    TreeItem *rootItem;
    QString m_DomainName;
    QString m_DomainKey;
    unsigned int m_DomainOffset = 0;

    enum EncodeMethod {
        HEX,
        BASE64
    } m_encodeMethod;

    enum MessageFormat {
        SCRIPT,
        SHORT,
    } m_messageFormat;

signals:
    void progress(TreeItem *status);
};

#endif // DOMAININSPECTOR_H
