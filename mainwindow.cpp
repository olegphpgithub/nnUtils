#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "formstreameditor.h"
#include "formfileutility.h"
#include "formdomaininspector.h"

#include <QStackedWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->actionLockFileUtility, SIGNAL(triggered()), this, SLOT(DisplayLockFileUtility()));
    connect(ui->actionADSEditor, SIGNAL(triggered()), this, SLOT(DisplayAlternateDataStreamEditor()));
    connect(ui->actionCheckDomainUtility, SIGNAL(triggered()), this, SLOT(DisplayDomainInspector()));

    formFileUtility = new FormFileUtility();
    formDomainInspector = new FormDomainInspector();
    formStreamEditor = new FormStreamEditor();

    stackedWidget = new QStackedWidget();
    stackedWidget->addWidget(formFileUtility);
    stackedWidget->addWidget(formDomainInspector);
    stackedWidget->addWidget(formStreamEditor);
    setCentralWidget(stackedWidget);

    DisplayDomainInspector();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::DisplayAlternateDataStreamEditor()
{
    stackedWidget->setCurrentWidget(formStreamEditor);
}

void MainWindow::DisplayLockFileUtility()
{
    stackedWidget->setCurrentWidget(formFileUtility);
}

void MainWindow::DisplayDomainInspector()
{
    stackedWidget->setCurrentWidget(formDomainInspector);
}
