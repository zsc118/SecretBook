#include "SecretList.h"
#include "itemeditdialog.h"
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include "itemsearchdialog.h"
void SecretList::init(RC4_file_read &fp, unsigned itemNum)
{
    while (itemNum--)
        addItem(new SecretItem(this, fp));
}
SecretList::SecretList(QWidget *parent) : QListWidget(parent)
{
    setSortingEnabled(true);
    /*connect(this, &QListWidget::itemDoubleClicked, [=](){
        SecretItem* item=(SecretItem*)currentItem();
        QString str(item->GetMD5());
        QMessageBox::information(this,"MD5密码",str);
        QApplication::clipboard()->setText(str);
    });*/
    connect(this,&SecretList::itemClicked,this,&SecretList::handleItemClicked);
}
void SecretList::openCurrentLink()
{
    QDesktopServices::openUrl(((SecretItem*)currentItem())->link);
}
void SecretList::handleItemClicked(QListWidgetItem *item)
{
    Qt::KeyboardModifiers modifiers(QGuiApplication::keyboardModifiers());
    if(modifiers.testFlag(Qt::ControlModifier))QDesktopServices::openUrl(((SecretItem*)item)->link);
}
void SecretList::clearAll()
{
    unsigned n(count());
    while(n--)delete (SecretItem*)takeItem(0);
}
void SecretList::scSecretItem()
{
    QString str;
    itemSearchDialog dlg(this,&str);
    if(dlg.exec()==QDialog::Rejected)return;
    const int m(currentRow()),n(count());
    int i(m);
    QListWidgetItem* it(item(++i%=n));
    if(it->text().contains(str,Qt::CaseInsensitive)){setCurrentRow(i);return;}
    while(i!=m)if((it=item(++i%=n))->text().contains(str,Qt::CaseInsensitive)){setCurrentRow(i);return;}
    QMessageBox::warning(this,"查找","没有包含“"+str+"”的项！");
}
void SecretList::cgSecretItem()
{
    SecretItem* it=(SecretItem*)currentItem();
    itemEditDialog dlg(this,it,"修改密码");
    dlg.exec();
}
void SecretList::addSecretItem()
{
    SecretItem *item = new SecretItem(this);
    itemEditDialog dialog(this, item, "添加密码");
    if (dialog.exec() == QDialog::Accepted)
        addItem(item);
    else
        delete item;
}
void SecretList::save(RC4_file_write &fp)
{
    unsigned n(count());
    while(n)((SecretItem*)item(--n))->save(fp);
}
void SecretList::rmSecretItem()
{
    if(QMessageBox::question(this,"删除密码","确定要删除吗？\n删除后不可恢复。")==QMessageBox::No)return;
    SecretItem* it=(SecretItem*)currentItem();
    removeItemWidget(it);
    delete it;
}
