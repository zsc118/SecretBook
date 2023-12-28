#ifndef SECRET_ITEM
#define SECRET_ITEM
#include <stdint.h>
#include <QString>
#include "secret.h"
#include <QListWidgetItem>
#include <QUrl>
class SecretList;
class SecretItem : public QListWidgetItem
{
    friend class SecretList;

    uint16_t state;
    QString secret;
    QString account;
    QString md5_code;
    QUrl link;
    char *allowedOtherStr;
    uint8_t preLen;

public:
    void generateMD5() noexcept;
    void save(RC4_file_write &fp) noexcept;
    void load(RC4_file_read &fp) noexcept;
    SecretItem(QListWidget *parent) noexcept;
    SecretItem(QListWidget *parent, RC4_file_read &fp) noexcept;
    SecretItem(const SecretItem &other) noexcept;
    ~SecretItem() noexcept;
    inline QString &GetPassword() noexcept;
    inline QString &GetAccount() noexcept;
    inline QString &GetMD5() noexcept;
    inline QString GetLinkAddress() noexcept;
    inline void SetPassword(const QString &pass) noexcept;
    inline void SetAccount(const QString &acc) noexcept;
    inline void SetPlatform(const QString &plat) noexcept;
    inline void SetLinkAddress(const QString &plat) noexcept;
    inline void SetNumberState(bool numberAllowed) noexcept;
    inline void SetUpperState(bool upperLattersAllowed) noexcept;
    inline void SetLowerState(bool lowerLattersAllowed) noexcept;
    inline void SetSymbolState(bool symbolsAllowed) noexcept;
    inline bool GetNumberState() noexcept;
    inline bool GetUpperState() noexcept;
    inline bool GetLowerState() noexcept;
    inline bool GetSymbolState() noexcept;
    void SetAllowedOtherStr(const QString &s) noexcept;
    inline QString GetAllowedOtherStr() noexcept;
    inline void SetMD5Length(uint8_t len) noexcept;
    inline uint8_t GetMD5Length() noexcept;
    inline bool isValid() noexcept;
};
inline QString SecretItem::GetLinkAddress() noexcept
{return link.toString();}
inline void SecretItem::SetLinkAddress(const QString &address) noexcept
{link=address;}
inline QString &SecretItem::GetPassword() noexcept
{
    return secret;
}
inline QString &SecretItem::GetAccount() noexcept
{
    return account;
}
inline QString &SecretItem::GetMD5() noexcept
{
    return md5_code;
}
inline void SecretItem::SetPassword(const QString &pass) noexcept
{
    secret = pass;
}
inline void SecretItem::SetAccount(const QString &acc) noexcept
{
    account = acc;
}
inline void SecretItem::SetPlatform(const QString &plat) noexcept
{
    setText(plat);
}
inline void SecretItem::SetNumberState(bool numberAllowed) noexcept
{
    if (numberAllowed)
        state |= 0x1000;
    else
        state &= 0xefff;
}
inline void SecretItem::SetUpperState(bool upperLattersAllowed) noexcept
{
    if (upperLattersAllowed)
        state |= 0x2000;
    else
        state &= 0xdfff;
}
inline void SecretItem::SetLowerState(bool lowerLattersAllowed) noexcept
{
    if (lowerLattersAllowed)
        state |= 0x4000;
    else
        state &= 0xbfff;
}
inline void SecretItem::SetSymbolState(bool symbolsAllowed) noexcept
{
    if (symbolsAllowed)
        state |= 0x8000;
    else
        state &= 0x7fff;
}
inline bool SecretItem::GetNumberState() noexcept
{
    return state & 0x1000;
}
inline bool SecretItem::GetUpperState() noexcept
{
    return state & 0x2000;
}
inline bool SecretItem::GetLowerState() noexcept
{
    return state & 0x4000;
}
inline bool SecretItem::GetSymbolState() noexcept
{
    return state & 0x8000;
}
inline QString SecretItem::GetAllowedOtherStr() noexcept
{
    return QByteArray(allowedOtherStr, state & 0x3f);
}
inline void SecretItem::SetMD5Length(uint8_t len) noexcept
{
    (state &= 0xf03f) |= len & 0xc0 ? 0x0fc0 : len << 6;
}
inline uint8_t SecretItem::GetMD5Length() noexcept
{
    return (state & 0x0fc0) >> 6;
}
inline bool SecretItem::isValid() noexcept
{
    return state;
}
#endif
