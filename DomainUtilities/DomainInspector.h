#ifndef DOMAININSPECTOR_H
#define DOMAININSPECTOR_H

#include <QThread>

class QModelIndex;

class DomainInspector : public QThread
{
    Q_OBJECT
public:
    DomainInspector();
    void run();

signals:
    //void progress(QModelIndex status);
};

#endif // DOMAININSPECTOR_H
