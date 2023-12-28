#include "mainwindow.h"
#include <QApplication>
#include "logindialog.h"

int main(int argc, char *argv[])
{
    char key[32];
    QApplication a(argc, argv);
    loginDialog loginDlg(key);
    if(loginDlg.exec()==QDialog::Rejected)return 0;
    MainWindow w(key);
    w.show();
    return a.exec();
}
