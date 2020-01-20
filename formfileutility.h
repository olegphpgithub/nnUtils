#ifndef FORMFILEUTILITY_H
#define FORMFILEUTILITY_H

#include <QWidget>

class QLockFile;

namespace Ui {
class FormFileUtility;
}

class FormFileUtility : public QWidget
{
    Q_OBJECT

public:
    explicit FormFileUtility(QWidget *parent = nullptr);
    ~FormFileUtility();

public slots:
    void ChooseFile();
    void LockFile();

private:
    Ui::FormFileUtility *ui;
    void *m_hFile;
};

#endif // FORMFILEUTILITY_H
