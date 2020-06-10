#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "formstreameditor.h"
#include "formfileutility.h"
#include "formdomainutilities.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    DisplayAlternateDataStreamEditor();
    connect(ui->actionLockFileUtility, SIGNAL(triggered()), this, SLOT(DisplayLockFileUtility()));
    connect(ui->actionADSEditor, SIGNAL(triggered()), this, SLOT(DisplayAlternateDataStreamEditor()));
    connect(ui->actionCheckDomainUtility, SIGNAL(triggered()), this, SLOT(DisplayCheckDomainUtility()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::DisplayAlternateDataStreamEditor()
{
    setCentralWidget(new FormStreamEditor());
}

void MainWindow::DisplayLockFileUtility()
{
    setCentralWidget(new FormFileUtility());
}

void MainWindow::DisplayCheckDomainUtility()
{
    setCentralWidget(new FormDomainUtilities());
}
