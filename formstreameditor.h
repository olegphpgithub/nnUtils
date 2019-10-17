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
    QStringList getFilesListToProcess();
    void AddStream();

private:
    Ui::FormStreamEditor *ui;
};

#endif // FORMSTREAMEDITOR_H
