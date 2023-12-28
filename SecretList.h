#ifndef SECRET_LIST
#define SECRET_LIST
#include <QListWidget>
#include "SecretItem.h"
//#include <list>
#include <QMouseEvent>
class SecretList : public QListWidget
{
    Q_OBJECT

public:
    SecretList(QWidget *parent);
    void init(RC4_file_read &fp, unsigned itemNum);
    void addSecretItem();
    void save(RC4_file_write &fp);
    void rmSecretItem();
    void cgSecretItem();
    void scSecretItem();
    void clearAll();
    void handleItemClicked(QListWidgetItem *);
    void openCurrentLink();
};
#endif
