#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "SecretList.h"
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(char *Key,QWidget *parent = nullptr);
    ~MainWindow();

private:
    SecretList* list;
    char*key;
};
#endif // MAINWINDOW_H
