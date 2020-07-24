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

        columnData << m_DomainName << "OK";
        root = new TreeItem(columnData);

        columnData.clear();
        columnData << "Generate Quant" << "OK";
        TreeItem *item = new TreeItem(columnData);
        root->appendChild(item);

        columnData.clear();
        columnData << "Quant" << quant;
        TreeItem *subItem = new TreeItem(columnData);
        item->appendChild(subItem);

    } catch (CppException *ex) {

        columnData << m_DomainName << "FAILURE";
        root = new TreeItem(columnData);

        columnData.clear();
        columnData << "Generate Quant" << "FAILURE";
        TreeItem *item = new TreeItem(columnData);
        root->appendChild(item);

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
            TreeItem *subItem = new TreeItem(columnData);
            item->appendChild(subItem);
        }
    }

    emit progress(root);
}
