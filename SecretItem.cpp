#include "SecretItem.h"
#include <QFont>
#define RESIZE_ALLOWED_STRING     \
    if (allowedOtherStr)          \
        delete[] allowedOtherStr; \
    allowedOtherStr = new char[state & 0x3f];
static const QFont secretFont("华文宋体", 18);
//static uint8_t pre_state;
SecretItem::~SecretItem() noexcept
{
    if (allowedOtherStr)
        delete[] allowedOtherStr;
}
SecretItem::SecretItem(QListWidget *parent) noexcept : state(0xf300), allowedOtherStr(nullptr), QListWidgetItem(parent)
{
    setFont(secretFont);
}
SecretItem::SecretItem(QListWidget *parent, RC4_file_read &fp) noexcept : allowedOtherStr(nullptr), QListWidgetItem(parent)
{
    setFont(secretFont);
    uint8_t plLen(fp.get());
    uint8_t acLen(fp.get());
    uint8_t seLen(fp.get());
    uint8_t md5Len(fp.get());
    uint8_t linkLen(fp.get());
    state = fp.get();
    (state <<= 8) |= fp.get();
    if (state & 0x3f)
        fp.get(allowedOtherStr = new char[state & 0x3f], state & 0x3f);
    else
        allowedOtherStr=nullptr;
    QByteArray tmpArr(plLen,Qt::Uninitialized);
    fp.get(tmpArr.data(), plLen);
    setText(QString::fromUtf8(tmpArr));
    tmpArr.resize(acLen);
    fp.get(tmpArr.data(), acLen);
    account = QString::fromUtf8(tmpArr);
    tmpArr.resize(seLen);
    fp.get(tmpArr.data(), seLen);
    secret = QString::fromUtf8(tmpArr);
    tmpArr.resize(md5Len);
    fp.get(tmpArr.data(), md5Len);
    md5_code = QString::fromUtf8(tmpArr);
    tmpArr.resize(linkLen);
    fp.get(tmpArr.data(), linkLen);
    link = QString::fromUtf8(tmpArr);
}
SecretItem::SecretItem(const SecretItem &other) noexcept : secret(other.secret), md5_code(other.md5_code), QListWidgetItem(other), account(other.account), link(other.link)
{
    setFont(secretFont);
    if ((state & 0x3f) < (other.state & 0x3f))
    {
        state = other.state;
        RESIZE_ALLOWED_STRING
    }
    else
        state = other.state;
    memcpy(allowedOtherStr, other.allowedOtherStr, state & 0x3f);
}
void SecretItem::generateMD5() noexcept
{
    QByteArray Str(secret.toUtf8());
    static char allowedStr[140];
    char res[128];
    if (!(state & 0x3f))
    {
        MD5(res, Str.data(), Str.size(), SecretType(state >> 12), state >> 6 & 0x3f);
        md5_code = res;
        return;
    }
    char *allowedP(allowedStr), t, *otherAllowed(allowedOtherStr);
    uint8_t allowedLen(state & 0x3f);
    if (state & 0x1000)
    {
        *allowedP++ = t = '0';
        do
            *allowedP++ = ++t;
        while (t != '9');
        allowedLen += 10;
    }
    if (state & 0x4000)
    {
        *allowedP++ = t = 'a';
        do
            *allowedP++ = ++t;
        while (t != 'z');
        allowedLen += 26;
    }
    if (state & 0x2000)
    {
        *allowedP++ = t = 'A';
        do
            *allowedP++ = ++t;
        while (t != 'Z');
        allowedLen += 26;
    }
    if (state & 0x8000)
    {
        *allowedP++ = '!';
        *allowedP++ = '@';
        *allowedP++ = '#';
        *allowedP++ = '$';
        *allowedP++ = '%';
        *allowedP++ = '^';
        *allowedP++ = '&';
        *allowedP++ = '*';
        *allowedP++ = '(';
        *allowedP++ = ')';
        *allowedP++ = '_';
        *allowedP++ = '=';
        *allowedP++ = '<';
        *allowedP++ = '>';
        *allowedP++ = '?';
        allowedLen += 15;
    }
    t = state & 0x3f;
    do
        *allowedP++ = *otherAllowed++;
    while (--t);
    MD5(res, Str.data(), Str.length(), allowedStr, allowedLen, '\0', res + (state >> 6 & 0x3f));
    md5_code = res;
}
void SecretItem::save(RC4_file_write &fp) noexcept
{
    QByteArray plArr(text().toUtf8()), seArr(secret.toUtf8()), md5Arr(md5_code.toUtf8()), acArr(account.toUtf8()),linkArr(link.toString().toUtf8());
    fp.put(plArr.length());
    fp.put(acArr.length());
    fp.put(seArr.length());
    fp.put(md5Arr.length());
    fp.put(linkArr.length());
    fp.put(state>>8);
    fp.put(state&0xff);
    if (state & 0x3f)
        fp.put(allowedOtherStr, state & 0x3f);
    fp.put(plArr.data(), plArr.length());
    fp.put(acArr.data(), acArr.length());
    fp.put(seArr.data(), seArr.length());
    fp.put(md5Arr.data(), md5Arr.length());
    fp.put(linkArr.data(),linkArr.length());
}
void SecretItem::load(RC4_file_read &fp) noexcept
{
    uint8_t plLen(fp.get());
    uint8_t acLen(fp.get());
    uint8_t seLen(fp.get());
    uint8_t md5Len(fp.get());
    uint8_t linkLen(fp.get());
    state = fp.get();
    (state <<= 8) |= fp.get();
    if (state & 0x3f)
    {
        fp.get(allowedOtherStr = new char[state & 0x3f], state & 0x3f);
    }
    QByteArray tmpArr(plLen,Qt::Uninitialized);
    fp.get(tmpArr.data(), plLen);
    setText(QString::fromUtf8(tmpArr));
    tmpArr.resize(acLen);
    fp.get(tmpArr.data(), acLen);
    account = QString::fromUtf8(tmpArr);
    tmpArr.resize(seLen);
    fp.get(tmpArr.data(), seLen);
    secret = QString::fromUtf8(tmpArr);
    tmpArr.resize(md5Len);
    fp.get(tmpArr.data(), md5Len);
    md5_code = QString::fromUtf8(tmpArr);
    tmpArr.resize(linkLen);
    fp.get(tmpArr.data(), linkLen);
    link = QString::fromUtf8(tmpArr);
}
void SecretItem::SetAllowedOtherStr(const QString &s) noexcept
{
    if(s.isEmpty())
    {
        if(allowedOtherStr)delete[] allowedOtherStr;
        allowedOtherStr=nullptr;
        state &= 0xffc0;
        return;
    }
    uint8_t len(s.length() & 0xffc0 ? 0x3f : s.length());
    if ((state & 0x3f) < len)
    {
        (state &= 0xffc0) |= len;
        if (allowedOtherStr)
            delete[] allowedOtherStr;
        allowedOtherStr = new char[len];
    }
    memcpy(allowedOtherStr, s.toLatin1().data(), len);
}
