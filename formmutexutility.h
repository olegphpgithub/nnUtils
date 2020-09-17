#ifndef FORMMUTEXUTILITY_H
#define FORMMUTEXUTILITY_H

#include <QWidget>

namespace Ui {
class FormMutexUtility;
}

class FormMutexUtility : public QWidget
{
    Q_OBJECT

public:
    explicit FormMutexUtility(QWidget *parent = nullptr);
    ~FormMutexUtility();

private:
    Ui::FormMutexUtility *ui;
};

#endif // FORMMUTEXUTILITY_H
