#include "DomainInspector.h"
#include "treeitem.h"
#include "InetClient.h"

#include <QModelIndex>
#include <QDebug>

DomainInspector::DomainInspector()
{

}

void DomainInspector::run()
{

    QVector<QVariant> columnData;
    TreeItem *root;

    try {

        InetClient ic;

        ic.m_DomainName.assign(m_DomainName.toLocal8Bit());
        ic.m_DomainKey.assign(m_DomainKey.toLocal8Bit());
        ic.m_DomainOffset = m_DomainOffset;
        ic.m_quant = ic.GenerateQuant();
        QString quant = QString::fromLocal8Bit(ic.m_quant.c_str());

        columnData.clear();
        columnData << "Generate Quant" << "OK";
        root = new TreeItem(columnData);

        columnData.clear();
        columnData << "Quant" << quant;
        TreeItem *item = new TreeItem(columnData);
        root->appendChild(item);

    } catch (CppException *ex) {

        columnData << "Generate Quant" << "FAILURE";
        root = new TreeItem(columnData);

        ExceptionStackTrace stack = ex->GetStackTrace();
        for (ExceptionStackTrace::iterator it = stack.begin();
             it < stack.end(); it++)
        {
#           ifdef UNICODE
                QString errorString = QString::fromWCharArray(it->c_str());
#           else
                QString errorString = QString::fromLatin1(it->c_str());
#           endif

            columnData.clear();
            columnData << "Error" << errorString;
            TreeItem *item = new TreeItem(columnData);
            root->appendChild(item);
        }
    }

    emit progress(root);

}
