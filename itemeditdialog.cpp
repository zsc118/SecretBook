#include "itemeditdialog.h"
#include "ui_itemeditdialog.h"
#include <QMessageBox>
#define SECRET_WARNING(flag,str) if(flag){QMessageBox::critical(this,type,str);return;}
itemEditDialog::itemEditDialog(QWidget *parent,SecretItem* item,const char* type) :
    QDialog(parent),
    ui(new Ui::itemEditDialog)
{
    setWindowFlags(windowFlags()&~Qt::WindowContextHelpButtonHint);
    ui->setupUi(this);
    ui->pltEdit->setText(item->text());
    ui->pwEdit->setText(item->GetPassword());
    ui->accEdit->setText(item->GetAccount());
    ui->linkEdit->setText(item->GetLinkAddress());
    ui->numberChk->setChecked(item->GetNumberState());
    ui->lowerChk->setChecked(item->GetLowerState());
    ui->upperChk->setChecked(item->GetUpperState());
    ui->symbolChk->setChecked(item->GetSymbolState());
    ui->md5lenEdit->setText(QString::number(item->GetMD5Length()));
    ui->allowedEdit->setText(item->GetAllowedOtherStr());
    connect(ui->cancelBtn,&QPushButton::clicked,[=](){reject();});
    //connect(ui->cancelBtn,&QPushButton::clicked,this,&QDialog::rejected);
    connect(ui->okBtn,&QPushButton::clicked,[=](){
        unsigned md5len(ui->md5lenEdit->text().toUInt());
        SECRET_WARNING(!md5len,"密码长度限制输入有误！")
        QString allowedStr(ui->allowedEdit->text());
        bool num(ui->numberChk->isChecked()),upp(ui->upperChk->isChecked()),low(ui->lowerChk->isChecked()),sym(ui->symbolChk->isChecked());
        SECRET_WARNING(!num&&!upp&&!low&&!sym&&!allowedStr.length(),"允许字符集不能为空！")
        item->SetNumberState(num);
        item->SetUpperState(upp);
        item->SetLowerState(low);
        item->SetSymbolState(sym);
        item->SetAllowedOtherStr(allowedStr);
        item->SetMD5Length(md5len);
        item->SetPlatform(ui->pltEdit->text());
        item->SetAccount(ui->accEdit->text());
        item->SetPassword(ui->pwEdit->text());
        item->SetLinkAddress(ui->linkEdit->text());
        item->generateMD5();
        accept();
    });
    //connect(ui->cancelBtn,&QPushButton::clicked,this,&QDialog::accepted);
}

itemEditDialog::~itemEditDialog()
{
    delete ui;
}
