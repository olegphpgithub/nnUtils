#include "formstreameditor.h"
#include "ui_formstreameditor.h"

#include "StreamsUtilities/AddStreamThread.cpp"

#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>

FormStreamEditor::FormStreamEditor(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FormStreamEditor)
{
    ui->setupUi(this);
    connect(ui->pushButton, SIGNAL(pressed()), this, SLOT(AddStream()));
    connect(
        ui->pathToExeFilesToolButton,
        SIGNAL(pressed()),
        this,
        SLOT(ChoosePathToExeFiles())
    );
}

FormStreamEditor::~FormStreamEditor()
{
    delete ui;
}

void FormStreamEditor::log(QString logString)
{
    ui->resultTextEdit->append(logString);
}

void FormStreamEditor::ChoosePathToExeFiles()
{

    QString fileName = QFileDialog::getExistingDirectory(
        this,
        tr("Choose directory"),
        ui->pathToExeFilesLineEdit->text(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
        );
    if(!(fileName.isNull() || fileName.isEmpty())) {
        ui->pathToExeFilesLineEdit->setText(fileName);
    }
    ui->pathToExeFilesLineEdit->setFocus();

}

void FormStreamEditor::AddStream()
{
    if(ui->pathToExeFilesLineEdit->text().isNull()
            || ui->pathToExeFilesLineEdit->text().isEmpty()
    )
    {
        QMessageBox::critical(this,
                              tr("User Error"),
                              tr("Choose the directory."),
                              QMessageBox::Cancel
                              );
        return;
    }
    QDir dir(ui->pathToExeFilesLineEdit->text());
    if(!dir.exists()) {
        QMessageBox::critical(this,
                              tr("User Error"),
                              tr("Directory doesn't exists."),
                              QMessageBox::Cancel
                              );
        return;
    }

    AddStreamThread *thread = new AddStreamThread();
    thread->setPath(ui->pathToExeFilesLineEdit->text());
    connect(thread, SIGNAL(submitLog(QString)), this, SLOT(log(QString)));
    thread->start();

}
