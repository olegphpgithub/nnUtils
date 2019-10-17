#ifndef FORMSTREAMEDITOR_H
#define FORMSTREAMEDITOR_H

#include <QWidget>

namespace Ui {
class FormStreamEditor;
}

class FormStreamEditor : public QWidget
{
    Q_OBJECT

public:
    explicit FormStreamEditor(QWidget *parent = nullptr);
    ~FormStreamEditor();

public slots:
    void ChoosePathToExeFiles();
    void AddStream();

private:
    Ui::FormStreamEditor *ui;
    QStringList getFilesListToProcess();
    QString GetRandomString(unsigned int randomStringLength);
};

#endif // FORMSTREAMEDITOR_H
