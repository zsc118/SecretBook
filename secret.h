#ifndef _ZSC_SECRET
#define _ZSC_SECRET
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MD5_NUMBER_ALLOWED "0123456789"
#define MD5_UPPER_LETTER_ALLOWED "QWERTYUIOPASDFGHJKLZXCVBNM"
#define MD5_LOWER_LETTER_ALLOWED "qwertyuiopasdfghjklzxcvbnm"
#define MD5_SYMBOL_ALLOWED "!@#$%^&*()_=<>?"
#define MD5_ALL_ALLOWED MD5_NUMBER_ALLOWED MD5_LOWER_LETTER_ALLOWED MD5_UPPER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED
#define MD5_LENGTH_LIMIT
/*
 * MD5加密
 * @param res 加密结果
 * @param str 待加密数据
 * @param length 数据长度
 */
void MD5(void *res, const void *str, const uint64_t &length) noexcept;
typedef void (*SecretFunc)(void *, const void *, const uint64_t &);
/*
 * 密文处理
 * @param res 加密结果
 * @param str 待加密数据
 * @param len 数据长度
 * @param allowedStr 密文中允许的字符集
 * @param allowedLen {@code allowedStr}的长度
 * @param func 加密算法
 * @param endSign 结束符
 * @param resEnd 密文强制结束指针
 */
template <typename T>
void limitSecret(T *res, const void *str, const uint64_t &len, const T *allowedStr, unsigned allowedLen, SecretFunc func, T &&endSign = '\0', T *resEnd = nullptr) noexcept;

void MD5(char *res, const void *str, const uint64_t &len, const char *allowedStr, unsigned allowedLen, char &&endSign = '\0', char *resEnd = nullptr) noexcept;
/*
 * MD5加密
 * @param res 加密结果
 * @param str 待加密数据
 * @param len 数据长度
 * @param allowedStr 密文中允许的字符集
 */
template <typename T>
void MD5(T *res, const void *str, const uint64_t &len, const T *allowedStr) noexcept;
/*
 * 密文处理
 * @param res 加密结果
 * @param str 待加密数据
 * @param len 数据长度
 * @param allowedStr 密文中允许的字符集
 */
template <typename T>
void limitSecret(T *res, const void *str, const uint64_t &len, const T *allowedStr, SecretFunc func) noexcept;
// 1:数字
// 2:大写
// 3:小写
// 4:特殊字符
class SecretType
{
    friend void MD5(char *, const void *, const uint64_t &, char *, SecretType) noexcept;
    friend void MD5(char *, const void *, const uint64_t &, SecretType, unsigned) noexcept;
    uint8_t t;

public:
    SecretType(uint8_t type) : t(type) {}
    static const uint8_t Numbers = '\1';
    static const uint8_t UpperLetters = '\2';
    static const uint8_t LowerLetters = '\4';
    static const uint8_t Symbols = '\10';
    bool number() const noexcept { return t & '\1'; }
    bool upperLetter() const noexcept { return t & '\2'; }
    bool lowerLetter() const noexcept { return t & '\4'; }
    bool symbols() const noexcept { return t & '\10'; }
    bool operator==(const SecretType &other) const noexcept { return t == other.t; }
    void reverseNumber() noexcept { t ^= '\1'; }
    void reverseUpperLetter() noexcept { t ^= '\2'; }
    void reverseLowerLetter() noexcept { t ^= '\4'; }
    void reverseSymbols() noexcept { t ^= '\10'; }
    void setNumber(bool flag) noexcept
    {
        if (flag)
            t |= '\1';
        else
            t &= '\16';
    }
    void setUpperLetter(bool flag) noexcept
    {
        if (flag)
            t |= '\2';
        else
            t &= '\15';
    }
    void setLowerLetter(bool flag) noexcept
    {
        if (flag)
            t |= '\4';
        else
            t &= '\13';
    }
    void setSymbols(bool flag) noexcept
    {
        if (flag)
            t |= '\10';
        else
            t &= '\7';
    }
    SecretType(const SecretType &other) noexcept : t(other.t) {}
    SecretType &operator=(const SecretType &other) noexcept
    {
        t = other.t;
        return *this;
    }
    SecretType &operator=(uint8_t other) noexcept
    {
        t = other;
        return *this;
    }
};
/*
 * MD5加密
 * @param res 加密结果
 * @param str 待加密数据
 * @param len 数据长度
 * @param type 密文中允许的字符集类型
 */
void MD5(char *res, const void *str, const uint64_t &len, char *resEnd, SecretType type) noexcept;
/*
 * MD5加密
 * @param res 加密结果
 * @param str 待加密数据
 * @param len 数据长度
 * @param type 密文中允许的字符集类型
 * @param resLen 密文的最大长度
 */
void MD5(char *res, const void *str, const uint64_t &len, SecretType type, unsigned resLen = 10) noexcept;
/*
 * RC4加密
 * @param str 待加密数据
 * @param strEnd 数据结束位置
 * @param key 秘钥
 * @param keyEnd 秘钥结束位置
 */
void RC4(void *str, void *strEnd, const void *key, const void *keyEnd) noexcept;
class RC4_ptr
{
    uint8_t s[256], i, j;
    uint8_t *p;
    RC4_ptr(const RC4_ptr &) = delete;
    friend inline bool operator==(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator==(const void *, const RC4_ptr &) noexcept;
    friend inline bool operator!=(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator!=(const void *, const RC4_ptr &) noexcept;
    friend inline bool operator<(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator<(const void *, const RC4_ptr &) noexcept;
    friend inline bool operator<=(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator<=(const void *, const RC4_ptr &) noexcept;
    friend inline bool operator>(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator>(const void *, const RC4_ptr &) noexcept;
    friend inline bool operator>=(const RC4_ptr &, const void *) noexcept;
    friend inline bool operator>=(const void *, const RC4_ptr &) noexcept;

public:
    RC4_ptr(void *data, const void *key, const void *keyEnd) noexcept;
    uint8_t &operator*() noexcept
    {
        uint8_t t = s[++i];
        s[i] = s[j += t];
        s[j] = t;
        return *p ^= s[t += s[i]];
    }
    RC4_ptr &operator++() noexcept
    {
        ++p;
        return *this;
    }
};
inline bool operator==(const RC4_ptr &a, const void* b) noexcept
{
    return a.p == b;
}
inline bool operator==(const void *b, const RC4_ptr &a) noexcept
{
    return a.p == b;
}
inline bool operator!=(const RC4_ptr &a, const void *b) noexcept
{
    return a.p != b;
}
inline bool operator!=(const void *b, const RC4_ptr &a) noexcept
{
    return a.p != b;
}
inline bool operator<(const RC4_ptr &a, const void *b) noexcept
{
    return a.p < b;
}
inline bool operator<(const void *b, const RC4_ptr &a) noexcept
{
    return a.p > b;
}
inline bool operator<=(const RC4_ptr &a, const void *b) noexcept
{
    return a.p <= b;
}
inline bool operator<=(const void *b, const RC4_ptr &a) noexcept
{
    return a.p >= b;
}
inline bool operator>(const RC4_ptr &a, const void *b) noexcept
{
    return a.p > b;
}
inline bool operator>(const void *b, const RC4_ptr &a) noexcept
{
    return a.p < b;
}
inline bool operator>=(const RC4_ptr &a, const void *b) noexcept
{
    return a.p >= b;
}
inline bool operator>=(const void *b, const RC4_ptr &a) noexcept
{
    return a.p <= b;
}
class RC4_file_read
{
    FILE *file;
    uint8_t s[256], i, j;
    RC4_file_read(const RC4_file_read &) = delete;

public:
    RC4_file_read(const char *filename, const void *key, const void *keyEnd) noexcept;
    RC4_file_read(const char *filename, const void *key, const void *keyEnd, int filePos) noexcept;
    RC4_file_read(FILE *File, const void *key, const void *keyEnd) noexcept;
    ~RC4_file_read() noexcept;
    uint8_t get() noexcept;
    void get(void *memery, size_t size) noexcept;
    void getAll(void *memery) noexcept;
    bool isEmpty() const noexcept
    {
        return !file;
    }
    bool isEOF() const noexcept
    {
        return feof(file);
    }
};
class RC4_file_write
{
    FILE *file;
    uint8_t s[256], i, j;
    RC4_file_write(const RC4_file_write &) = delete;

public:
    RC4_file_write(const char *filename, const void *key, const void *keyEnd) noexcept;
    RC4_file_write(const char *filename, const void *key, const void *keyEnd, int filePos) noexcept;
    RC4_file_write(FILE *File, const void *key, const void *keyEnd) noexcept;
    ~RC4_file_write() noexcept;
    void put(const void *memery, size_t size) noexcept;
    void put(uint8_t data) noexcept;
    bool isEmpty() const noexcept
    {
        return !file;
    }
};
#endif
