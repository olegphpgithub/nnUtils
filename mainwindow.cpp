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

    // FormStreamEditor *fse = new FormStreamEditor();
    // setCentralWidget(fse);

    // FormFileUtility *f = new FormFileUtility();
    // setCentralWidget(f);

    FormDomainUtilities *f = new FormDomainUtilities();
    setCentralWidget(f);

}

MainWindow::~MainWindow()
{
    delete ui;
}

