#ifndef ITEMEDITDIALOG_H
#define ITEMEDITDIALOG_H

#include <QDialog>
#include "SecretItem.h"
namespace Ui {
class itemEditDialog;
}

class itemEditDialog : public QDialog
{
    Q_OBJECT

public:
    explicit itemEditDialog(QWidget *parent,SecretItem* item,const char* type);
    ~itemEditDialog();

private:
    Ui::itemEditDialog *ui;
};

#endif // ITEMEDITDIALOG_H
