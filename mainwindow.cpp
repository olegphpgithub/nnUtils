#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "formstreameditor.h"
#include "formfileutility.h"
#include "formdomainutilities.h"

#include <QStackedWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->actionLockFileUtility, SIGNAL(triggered()), this, SLOT(DisplayLockFileUtility()));
    connect(ui->actionADSEditor, SIGNAL(triggered()), this, SLOT(DisplayAlternateDataStreamEditor()));
    connect(ui->actionCheckDomainUtility, SIGNAL(triggered()), this, SLOT(DisplayCheckDomainUtility()));

    formFileUtility = new FormFileUtility();
    formDomainUtilities = new FormDomainUtilities();
    formStreamEditor = new FormStreamEditor();

    stackedWidget = new QStackedWidget();
    stackedWidget->addWidget(formFileUtility);
    stackedWidget->addWidget(formDomainUtilities);
    stackedWidget->addWidget(formStreamEditor);
    setCentralWidget(stackedWidget);

    DisplayCheckDomainUtility();
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

void MainWindow::DisplayCheckDomainUtility()
{
    stackedWidget->setCurrentWidget(formDomainUtilities);
}
