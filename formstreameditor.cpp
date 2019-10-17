#include "formstreameditor.h"
#include "ui_formstreameditor.h"
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

QStringList FormStreamEditor::getFilesListToProcess()
{
    QStringList filesList;
    QDir dir(ui->pathToExeFilesLineEdit->text());
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);

    QFileInfoList list = dir.entryInfoList();
    for (int i = 0; i < list.size(); ++i) {
        QFileInfo fileInfo = list.at(i);
        filesList.append(fileInfo.absoluteFilePath());
    }

    return filesList;
}

QString FormStreamEditor::GetRandomString(unsigned int randomStringLength)
{
   const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

   QString randomString;
   for(unsigned int i=0; i<randomStringLength; ++i)
   {
       int index = qrand() % possibleCharacters.length();
       QChar nextChar = possibleCharacters.at(index);
       randomString.append(nextChar);
   }
   return randomString;
}

void FormStreamEditor::AddStream()
{
    try {
        if(ui->pathToExeFilesLineEdit->text().isNull()
                || ui->pathToExeFilesLineEdit->text().isEmpty()
        )
        {
            throw new QString(tr("Choose the directory."));
        }
        QDir dir(ui->pathToExeFilesLineEdit->text());
        if(!dir.exists()) {
            throw new QString(tr("Directory doesn't exists."));
        }
        QStringList fileStringList = getFilesListToProcess();
        for (int i = 0; i < fileStringList.size(); i++) {
            QString filePathString(fileStringList.at(1));
            QString fileStreamNameString("%1:%2");
            fileStreamNameString =
                    fileStreamNameString.arg(fileStringList.at(i));
            fileStreamNameString =
                    fileStreamNameString.arg("Zone.Identifier:$DATA");
            QFile file(fileStreamNameString);
            if(file.open(QIODevice::WriteOnly | QIODevice::Text))
            {
                QFileInfo fileInfo(filePathString);
                QString fileNameString(fileInfo.fileName());
                QString hostUrlString("HostUrl=https://%1.amazonaws.com/%2");
                QString randomString = GetRandomString(12);
                hostUrlString = hostUrlString.arg(randomString);
                hostUrlString = hostUrlString.arg(fileNameString);
                QTextStream outputTextStream(&file);
                outputTextStream << "[ZoneTransfer]" << "\n";
                outputTextStream << "ZoneId=3" << "\n";
                // outputTextStream << "ReferrerUrl=https://korzuno.s3.eu-north-1.amazonaws.com/index.html" << "\n";
                outputTextStream << hostUrlString << "\n";
            }
        }
        ui->protocolPlainTextEdit->appendPlainText(tr("The operation is completed."));
    } catch(QString *exception) {
        QMessageBox::critical(this, tr("Critical Error"), *exception, QMessageBox::Cancel);
        delete exception;
    }
}
