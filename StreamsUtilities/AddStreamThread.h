#ifndef ADDSTREAMTHREAD_H
#define ADDSTREAMTHREAD_H

#include <QThread>

class AddStreamThread : public QThread
{
    Q_OBJECT
    QString m_sPath;
    QStringList getFilesListToProcess();
    QString GetRandomString(unsigned int randomStringLength);
public:
    explicit AddStreamThread(QObject *parent = nullptr);
    void run();
    void setPath(const QString &path);
signals:
    void submitLog(QString);
    void submitResult(bool);
};

#endif // ADDSTREAMTHREAD_H
