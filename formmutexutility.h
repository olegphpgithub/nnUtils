#ifndef FORMMUTEXUTILITY_H
#define FORMMUTEXUTILITY_H

#include <QWidget>

#include <Windows.h>

namespace Ui {
class FormMutexUtility;
}

class FormMutexUtility : public QWidget
{
    Q_OBJECT

public:
    explicit FormMutexUtility(QWidget *parent = nullptr);
    ~FormMutexUtility();

public slots:
    void log(QString logString);
    void CreateNamedMutex();
    void OpenNamedMutex();
    void CloseNamedMutex();
    void OwnershipMutex();
    void ReleaseNamedMutex();
    void OwnershipGotten(bool result);

private:
    Ui::FormMutexUtility *ui;
    HANDLE m_hMutex;
    HANDLE m_hSemaphore;
};

#endif // FORMMUTEXUTILITY_H
