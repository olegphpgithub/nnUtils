#include "AddStreamThread.h"

#include <QDir>
#include <QTextStream>

AddStreamThread::AddStreamThread(QObject *parent) : QThread(parent)
{

}

void AddStreamThread::run()
{
    emit submitLog("Please wait...");
    QStringList fileStringList = getFilesListToProcess();
    for (int i = 0; i < fileStringList.size(); i++) {
        QString filePathString(fileStringList.at(0));
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
            // outputTextStream << "ReferrerUrl=https://bucket.s3.eu-north-1.amazonaws.com/index.html" << "\n";
            outputTextStream << hostUrlString << "\n";
        }
    }
    emit submitLog(tr("The operation is completed."));

}

void AddStreamThread::setPath(const QString &path)
{
    m_sPath = path;
}

QStringList AddStreamThread::getFilesListToProcess()
{
    QStringList filesList;
    QDir dir(m_sPath);
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);

    QFileInfoList list = dir.entryInfoList();
    for (int i = 0; i < list.size(); ++i) {
        QFileInfo fileInfo = list.at(i);
        filesList.append(fileInfo.absoluteFilePath());
    }

    return filesList;
}

QString AddStreamThread::GetRandomString(unsigned int randomStringLength)
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
