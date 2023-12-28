#include "itemsearchdialog.h"
#include "ui_itemsearchdialog.h"

itemSearchDialog::itemSearchDialog(QWidget *parent,QString* str) :
    QDialog(parent),
    ui(new Ui::itemSearchDialog)
{
    setWindowFlags(windowFlags()&~Qt::WindowContextHelpButtonHint);
    ui->setupUi(this);
    connect(ui->cancelBtn,&QPushButton::clicked,[=](){reject();});
    connect(ui->okBtn,&QPushButton::clicked,[=](){str->operator=(ui->lineEdit->text());accept();});
}

itemSearchDialog::~itemSearchDialog()
{
    delete ui;
}
