#include "mainwindow.h"
#include <QListWidget>
#include <unistd.h>
#include <stdio.h>
#include "secret.h"
#include <QFileDialog>
#include <QStandardPaths>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QMenuBar>
#include <QStatusBar>
#include <QLabel>
#include <QByteArray>
#include "logindialog.h"
char fileName[45];
//char*const fileNamePtr(fileName+4);
//#include <QDebug>
#define RESET_ACTION_ENABLED(flag) cgAct->setEnabled(flag);rmAct->setEnabled(flag);md5Act->setEnabled(flag);linkAct->setEnabled(flag);accAct->setEnabled(flag);
#define JUDGE_ACTION_ENABLED if(list->count()){RESET_ACTION_ENABLED(true)}else{RESET_ACTION_ENABLED(false)}
//#define SHOW_STATUS SecretItem* it((SecretItem*)list->currentItem());lStatus->setText(it->GetAccount());rStatus->setText(it->GetPassword());
//#define JUDGE_ACTION_SHOW if(list->count()){RESET_ACTION_ENABLED(true) SHOW_STATUS}else{RESET_ACTION_ENABLED(false)}
//QLabel*lStatus,*rStatus;
#define LIMIT_MOD_CIRCLE(x) while((x)&0x03ffffff){*p++=str[(x)>>26];(x)<<=6;}
#define NEXT_LIMIT_MOD_CIRCLE ++p1; LIMIT_MOD_CIRCLE(*p1) ++p2; LIMIT_MOD_CIRCLE(*p2)
void getFileName(const char* key)
{
    static char key_cpy[32];
    const static char str[]="1234567890qwertyuiopas(dfghjklzxcvbnmQWERTYUIO)PASDFGHJKLZXCVBNM";
    //static uint64_t &key0(*(uint64_t*)(void*)key_cpy),&key1(*(uint64_t*)(void*)(key_cpy+4)),&key2(*(uint64_t*)(void*)(key_cpy+8)),&key3(*(uint64_t*)(void*)(key_cpy+12)),&key4(*(uint64_t*)(void*)(key_cpy+16)),&key5(*(uint64_t*)(void*)(key_cpy+20)),&key6(*(uint64_t*)(void*)(key_cpy+24)),&key7(*(uint64_t*)(void*)(key_cpy+28));
    static uint32_t*const s1((uint32_t*)(void*)key_cpy),*const s2((uint32_t*)(void*)(key_cpy+2));
    uint8_t i(32);
    char*p(key_cpy);
    do *p++=*key++;while(--i);
    //p=fileNamePtr;
    p=fileName;
    uint32_t*p1(s1),*p2(s2);
    LIMIT_MOD_CIRCLE(*p1) LIMIT_MOD_CIRCLE(*p2) NEXT_LIMIT_MOD_CIRCLE NEXT_LIMIT_MOD_CIRCLE NEXT_LIMIT_MOD_CIRCLE NEXT_LIMIT_MOD_CIRCLE NEXT_LIMIT_MOD_CIRCLE NEXT_LIMIT_MOD_CIRCLE ++p1; LIMIT_MOD_CIRCLE(*p1)
    //LIMIT_MOD_CIRCLE(key0) LIMIT_MOD_CIRCLE(key1) LIMIT_MOD_CIRCLE(key2) LIMIT_MOD_CIRCLE(key3) LIMIT_MOD_CIRCLE(key4) LIMIT_MOD_CIRCLE(key5) LIMIT_MOD_CIRCLE(key6) LIMIT_MOD_CIRCLE(key7)
    *p=str[*p1>>26];
    *++p='\0';
}
#define GET_ITEM_NUM(num) num=fp.get();(num<<=8)|=fp.get();
#define PUT_ITEM_NUM(num) fp.put(num>>8);fp.put(num&0xff);
MainWindow::MainWindow(char* Key,QWidget *parent)
    : QMainWindow(parent),key(Key)
{
    /*char*fileName_ptr(fileName);
    *fileName_ptr='d';
    *++fileName_ptr='a';
    *++fileName_ptr='t';
    *++fileName_ptr='a';
    *++fileName_ptr='/';
    *++fileName_ptr='a';
    *++fileName_ptr='/';*/
    setWindowIcon(QIcon("1.ico"));
    setWindowTitle("密码本");
    //key="\210\311\213\121\22\276\377\204\16\275\251\102\72\246\74\347\77\127\176\156\347\106\10\70\26\175\236\74\153\336\57\61\16\322\306\2\36\244\240\251\124\155\267\266\26\224\146\302\356\377\226\300\254\344\374\361\261\272\66\314\262\31\113\153\125\330\337\266\165\250\335\133\75\30\160\106\136\261\334\147\16\321\4\126\34\134\20\347\243\254\333\165\16\61\216\310\71\347\124\363\240\366\67\61\240\157\267\223\201\323\112\354\237\12\367\235\126\113\370\226\213\26\66\47\64\55\115\371\246\123\52\367\200\331\372\133\174\124\340\63\371\302\116\277\214\230\217\73\140\11\326\233\356\222\312\105\75\134\170\177\375\141\322\354\127\163\352\212\210\305\255\105\222\307\237\22\166\364\353\250\272\330\22\164\306\204\121\223\23\11\106\174\300\200\127\202\75\305\40\327\255\132\253\322\30\53\1\253\260\261\323\254\342\244\230\227\255\167\231\326\362\102\11\6\335\235\155\26\1\135\167\147\342\240\25\147\365\216\154\146\110\222\4\124\15\364\17\134\322\205\224\143\315\337\14\340";
    uint16_t itemNum;
    setFixedSize(600,800);
    list=new SecretList(this);
    getFileName(key);
    if(!access(fileName,R_OK))
    {
        RC4_file_read fp(fileName,key,key+32);
        GET_ITEM_NUM(itemNum)
        list->init(fp,itemNum);
    }
    else itemNum=0;
    setCentralWidget(list);
    QMenuBar* bar=menuBar();
    QMenu*fileMenu=bar->addMenu("文件");
    QAction*saveAct=fileMenu->addAction("保存");
    fileMenu->addSeparator();
    QAction*inAct(fileMenu->addAction("导入"));
    QAction*outAct(fileMenu->addAction("导出"));
    fileMenu->addSeparator();
    QAction*cgAccAct(fileMenu->addAction("切换账号"));
    QAction*cgPwAct(fileMenu->addAction("修改当前账号"));
    QMenu*editMenu=bar->addMenu("编辑");
    QAction* addAct=editMenu->addAction("添加");
    QAction* cgAct=editMenu->addAction("修改");
    QAction* rmAct=editMenu->addAction("删除");
    QAction* rmAllAct=editMenu->addAction("删除所有");
    editMenu->addSeparator();
    QAction* scAct=editMenu->addAction("查找");
    QMenu* showMenu=bar->addMenu("查看");
    QAction* md5Act=showMenu->addAction("查看密码");
    QAction* linkAct=showMenu->addAction("打开链接");
    QAction* accAct=showMenu->addAction("复制账号");
    QAction* pwCpyAcc=showMenu->addAction("复制密码");
    QMenu*helpMenu=bar->addMenu("帮助");
    QAction*aboutAct=helpMenu->addAction("关于密码本");
    /*QStatusBar* stBar=statusBar();
    stBar->addWidget(lStatus=new QLabel(this));
    stBar->addPermanentWidget(rStatus=new QLabel(this));*/
    JUDGE_ACTION_ENABLED
    auto resetActionsF=[=](){JUDGE_ACTION_ENABLED};
    connect(saveAct,&QAction::triggered,[=](){
        getFileName(key);
        unsigned num(list->count());
        if(num)
        {
            RC4_file_write fp(fileName,key,key+32);
            PUT_ITEM_NUM(num)
            list->save(fp);
        }
        else if(!access(fileName,F_OK))remove(fileName);
    });
    connect(inAct,&QAction::triggered,[=,&itemNum](){
        if(QMessageBox::question(this,"导入密码本","导入新的密码本将覆盖现有的密码本。\n确定要继续吗？")==QMessageBox::No)return;
        QByteArray arr(QFileDialog::getOpenFileName(this,"导入密码本",QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),"password Files (*.pwx)").toLocal8Bit());
        if(arr.isEmpty())return;
        FILE* file(fopen(arr.data(),"rb"));
        fread(key,1,32,file);
        RC4_file_read fp(file,key,key+32);
        GET_ITEM_NUM(itemNum)
        list->clearAll();
        list->init(fp,itemNum);
        JUDGE_ACTION_ENABLED
    });
    connect(outAct,&QAction::triggered,[=](){
        QByteArray arr(QFileDialog::getSaveFileName(this,"导出密码本",QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),"password Files (*.pwx)").toLocal8Bit());
        if(arr.isEmpty())return;
        if(!arr.endsWith(".pwx"))arr.append(".pwx",4);
        FILE* file(fopen(arr.data(),"wb"));
        fwrite(key,1,32,file);
        RC4_file_write fp(file,key,key+32);
        unsigned num(list->count());
        PUT_ITEM_NUM(num)
        list->save(fp);
    });
    connect(cgAccAct,&QAction::triggered,[=,&itemNum](){
        if(QMessageBox::question(this,"切换账号","切换账号将覆盖现有的密码本。\n确定要继续吗？")==QMessageBox::No)return;
        loginDialog Dlg(key,this);
        if(Dlg.exec()==QDialog::Rejected)return;
        getFileName(key);
        list->clearAll();
        if(!access(fileName,R_OK))
        {
            RC4_file_read fp(fileName,key,key+32);
            GET_ITEM_NUM(itemNum)
            list->init(fp,itemNum);
        }
    });
    connect(cgPwAct,&QAction::triggered,[=](){
        getFileName(key);
        loginDialog Dlg(key,this);
        if(Dlg.exec()==QDialog::Rejected)return;
        if(!access(fileName,F_OK))remove(fileName);
    });
    connect(addAct,&QAction::triggered,list,&SecretList::addSecretItem);
    connect(addAct,&QAction::triggered,this,resetActionsF);
    connect(cgAct,&QAction::triggered,list,&SecretList::cgSecretItem);
    connect(rmAct,&QAction::triggered,list,&SecretList::rmSecretItem);
    connect(rmAct,&QAction::triggered,this,resetActionsF);
    connect(rmAllAct,&QAction::triggered,list,&SecretList::clearAll);
    connect(rmAllAct,&QAction::triggered,this,resetActionsF);
    connect(scAct,&QAction::triggered,list,&SecretList::scSecretItem);
    connect(md5Act,&QAction::triggered,[=](){QMessageBox::information(this,"MD5密码",((SecretItem*)list->currentItem())->GetMD5());});
    connect(linkAct,&QAction::triggered,list,&SecretList::openCurrentLink);
    connect(accAct,&QAction::triggered,[=](){QApplication::clipboard()->setText(((SecretItem*)list->currentItem())->GetAccount());});
    connect(pwCpyAcc,&QAction::triggered,[=](){QApplication::clipboard()->setText(((SecretItem*)list->currentItem())->GetMD5());});
    connect(aboutAct,&QAction::triggered,[=](){QMessageBox::about(this, "关于密码本", "密码本是一个方便您存储、管理和保护个人密码的工具。\n通过使用密码本，您可以轻松地保存各种账号的登录密码、网站密码、应用程序密码等，并确保它们的安全。\n版本：1.0\n作者：zsc118\n发布日期：2023年12月28日");});
    QMenu* listMenu=new QMenu(this);
    listMenu->addAction(accAct);
    listMenu->addAction(md5Act);
    listMenu->addAction(linkAct);
    listMenu->addSeparator();
    listMenu->addAction(addAct);
    listMenu->addAction(cgAct);
    listMenu->addAction(rmAct);
    list->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(list,&SecretList::customContextMenuRequested,[=](){
        listMenu->exec(QCursor::pos());
    });
    connect(list,&QListWidget::itemDoubleClicked,cgAct,&QAction::triggered);
    //connect(list,&SecretList::currentRowChanged,[=](){JUDGE_ACTION_SHOW});
}

MainWindow::~MainWindow()
{
    unsigned num(list->count());
    getFileName(key);
    if(num)
    {
        RC4_file_write fp(fileName,key,key+32);
        PUT_ITEM_NUM(num)
        list->save(fp);
    }
    else if(!access(fileName,F_OK))remove(fileName);
}
