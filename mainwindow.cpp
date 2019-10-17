#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "formstreameditor.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    FormStreamEditor *fse = new FormStreamEditor();
    setCentralWidget(fse);
}

MainWindow::~MainWindow()
{
    delete ui;
}

