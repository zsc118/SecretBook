#include "logindialog.h"
#include "ui_logindialog.h"
#include "secret.h"
loginDialog::loginDialog(char* Key,QWidget *parent) :
    QDialog(parent),
    ui(new Ui::loginDialog)
{
    setWindowFlags(windowFlags()&~Qt::WindowContextHelpButtonHint);
    ui->setupUi(this);
    connect(ui->cancelBtn,&QPushButton::clicked,[=](){reject();});
    connect(ui->okBtn,&QPushButton::clicked,[=](){
        QByteArray accArr(ui->accEd->text().toUtf8()),pwArr(ui->pwEd->text().toUtf8());
        MD5(Key,accArr.data(),accArr.length());
        MD5(Key+16,pwArr.data(),pwArr.length());
        accept();
    });
}
loginDialog::~loginDialog()
{
    delete ui;
}
