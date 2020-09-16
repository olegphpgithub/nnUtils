#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class QStackedWidget;

class FormFileUtility;
class FormDomainInspector;
class FormStreamEditor;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void DisplayAlternateDataStreamEditor();
    void DisplayLockFileUtility();
    void DisplayDomainInspector();

private:
    Ui::MainWindow *ui;

    QStackedWidget *stackedWidget;

    FormFileUtility *formFileUtility;
    FormStreamEditor *formStreamEditor;
    FormDomainInspector *formDomainInspector;
};
#endif // MAINWINDOW_H
