#ifndef ITEMSEARCHDIALOG_H
#define ITEMSEARCHDIALOG_H

#include <QDialog>

namespace Ui {
class itemSearchDialog;
}

class itemSearchDialog : public QDialog
{
    Q_OBJECT

public:
    explicit itemSearchDialog(QWidget *parent,QString* str);
    ~itemSearchDialog();

private:
    Ui::itemSearchDialog *ui;
};

#endif // ITEMSEARCHDIALOG_H
