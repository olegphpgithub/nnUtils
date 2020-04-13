#ifndef FORMDOMAINUTILITIES_H
#define FORMDOMAINUTILITIES_H

#include <QWidget>

namespace Ui {
class FormDomainUtilities;
}

class FormDomainUtilities : public QWidget
{
    Q_OBJECT

public:
    explicit FormDomainUtilities(QWidget *parent = nullptr);
    ~FormDomainUtilities();

private:
    Ui::FormDomainUtilities *ui;
};

#endif // FORMDOMAINUTILITIES_H
