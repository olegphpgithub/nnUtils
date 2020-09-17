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
    void CreateNamedMutex();

private:
    Ui::FormMutexUtility *ui;
    HANDLE m_hMutex;
};

#endif // FORMMUTEXUTILITY_H
