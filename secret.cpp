#include "secret.h"
typedef uint8_t Byte;
static const char endSign('\0');
#define shift(x, n) (((x) << (n)) | ((x) >> (32 - (n)))) // 右移的时候，高位一定要补零，而不是补充符号位
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5_TEMP_SET_VALUE a = A, b = B, c = C, d = D, p_k = k, s_k = s;
#define MD5_CIRCLE(fun, My_g)         \
    i = '\020';                       \
    do                                \
    {                                 \
        f = fun(b, c, d);             \
        t = d;                        \
        d = c;                        \
        c = b;                        \
        --i;                          \
        sl = a + f + *(p_k++) + My_g; \
        sr = *s_k++;                  \
        b += shift(sl, sr);           \
        a = t;                        \
    } while (i);
#define MD5_RETURN_TEMP A += a, B += b, C += c, D += d;
#define MD5_ALL_CIRCLE(My_arr) MD5_CIRCLE(F, My_arr[i]) MD5_CIRCLE(G, My_arr[(5 * i + 1) & 15]) MD5_CIRCLE(H, My_arr[(3 * i + 5) & 15]) MD5_CIRCLE(I, My_arr[(7 * i) & 15])
#define MD5_DISPOSE(Arr)                   \
    MD5_TEMP_SET_VALUE MD5_ALL_CIRCLE(Arr) \
    MD5_RETURN_TEMP
static const uint32_t k[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
static const uint32_t s[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
void MD5(void *res, const void *str, const uint64_t &length) noexcept
{
    uint32_t &A(*(uint32_t *)res = 0x67452301), &B(*((uint32_t *)res + 1) = 0xefcdab89), &C(*((uint32_t *)res + 2) = 0x98badcfe), &D(*((uint32_t *)res + 3) = 0x10325476), a, b, c, d, t, f, sl, sr, arr[16];
    const uint32_t *M((const uint32_t *)str), *p_k, *s_k;
    Byte i, *arr_p((Byte *)arr);
    uint64_t len(length);
    while (len > 63)
    {
        MD5_DISPOSE(M)
        len -= 64;
        M += 16;
    }
    const Byte *m((const Byte *)M);
    if (len < 56)
    {
        i = 55 - len;
        if (len)
        {
            *arr_p = *m;
            while (--len)
                *++arr_p = *++m;
            *++arr_p = '\200';
        }
        else
            *arr_p = '\200';
        while (i--)
            *++arr_p = '\0';
        *(uint64_t *)(void *)++arr_p = length;
        MD5_DISPOSE(arr)
        return;
    }
    i = 63 - len;
    *arr_p = *m;
    while (--len)
        *++arr_p = *++m;
    *++arr_p = '\200';
    while (i--)
        *++arr_p = '\0';
    MD5_DISPOSE(arr)
    uint64_t *p((uint64_t *)arr);
    i = 6;
    *p = 0ull;
    do
        *++p = 0ull;
    while (--i);
    *++p = length;
    MD5_DISPOSE(arr)
}
#define LIMIT_JUDGE_RANGE \
    if (res == resEnd)    \
    {                     \
        *res = endSign;   \
        return;           \
    }
#define LIMIT_MOD_CIRCLE(x)                  \
    while (x >= allowedLen)                  \
    {                                        \
        *res++ = allowedStr[x % allowedLen]; \
        LIMIT_JUDGE_RANGE                    \
        x /= allowedLen;                     \
    }
#define LIMIT_START_CIRCLE(x)                \
    t = 0x8000000000000000;                  \
    while (!(t & x))                         \
    {                                        \
        *res++ = allowedStr[t % allowedLen]; \
        LIMIT_JUDGE_RANGE                    \
        if (!(t >>= 1))                      \
            break;                           \
    }
#define LIMIT_MOD(x)               \
    if (!(x & 0xffffffffffff0000)) \
    {                              \
        LIMIT_START_CIRCLE(x)      \
    }                              \
    LIMIT_MOD_CIRCLE(x)
#define LIMIT_SECRET(func)                       \
    Byte arr[16];                                \
    func((void *)arr, str, len);                 \
    uint64_t &a(*(uint64_t *)(void *)arr);       \
    uint64_t &b(*(uint64_t *)(void *)(arr + 4)); \
    uint64_t &c(*(uint64_t *)(void *)(arr + 8)); \
    uint64_t t;                                  \
    LIMIT_MOD(a)                                 \
    LIMIT_MOD(b)                                 \
    LIMIT_MOD(c)                                 \
    *res = allowedStr[c];                        \
    *++res = endSign;
void MD5(char *res, const void *str, const uint64_t &len, const char *allowedStr, unsigned allowedLen, char &&endSign, char *resEnd) noexcept
{
    LIMIT_SECRET(MD5)
}
#define CAL_STR_LENGTH                 \
    T endSign(0), *resEnd(allowedStr); \
    unsigned allowedLen(0);            \
    while (*resEnd++ != endSign)       \
        ++allowedLen;
/*template<typename T>
unsigned strlen(const T *str, T&& endSign) noexcept
{
    unsigned len = 0;
    while (*str++ != endSign)
        ++len;
    return len;
}*/
template <typename T>
void MD5(T *res, const void *str, const uint64_t &len, const T *allowedStr) noexcept
{
    CAL_STR_LENGTH
    LIMIT_SECRET(MD5)
}
template <typename T>
void limitSecret(T *res, const void *str, const uint64_t &len, const T *allowedStr, SecretFunc func) noexcept
{
    CAL_STR_LENGTH
    LIMIT_SECRET(func)
}
#define _SECRET_CLASS_DISPOSE switch (type.t){case '\1':allowedStr=MD5_NUMBER_ALLOWED;allowedLen=10;break;case '\2':allowedStr=MD5_UPPER_LETTER_ALLOWED;allowedLen=26;break;case '\3':allowedStr=MD5_NUMBER_ALLOWED MD5_UPPER_LETTER_ALLOWED;allowedLen=36;break;case '\4':allowedStr=MD5_LOWER_LETTER_ALLOWED;allowedLen=26;break;case '\5':allowedStr=MD5_NUMBER_ALLOWED MD5_LOWER_LETTER_ALLOWED;allowedLen=36;break;case '\6':allowedStr=MD5_LOWER_LETTER_ALLOWED MD5_UPPER_LETTER_ALLOWED;allowedLen=52;break;case '\7':allowedStr=MD5_NUMBER_ALLOWED MD5_LOWER_LETTER_ALLOWED MD5_UPPER_LETTER_ALLOWED;allowedLen=62;break;case '\10':allowedStr=MD5_SYMBOL_ALLOWED;allowedLen=15;break;case '\11':allowedStr=MD5_NUMBER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=25;break;case '\12':allowedStr=MD5_UPPER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=41;break;case '\13':allowedStr=MD5_NUMBER_ALLOWED MD5_UPPER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=51;break;case '\14':allowedStr=MD5_LOWER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=41;break;case '\15':allowedStr=MD5_NUMBER_ALLOWED MD5_LOWER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=51;break;case '\16':allowedStr=MD5_LOWER_LETTER_ALLOWED MD5_UPPER_LETTER_ALLOWED MD5_SYMBOL_ALLOWED;allowedLen=67;break;default:allowedStr=MD5_ALL_ALLOWED;allowedLen=77;}
#define SECRET_CLASS_DISPOSE         \
    const char *allowedStr;          \
    unsigned allowedLen;             \
    _SECRET_CLASS_DISPOSE
#define SECRET_CLASS_DISPOSE_LEN \
    char *resEnd(res + resLen);  \
    SECRET_CLASS_DISPOSE
void MD5(char *res, const void *str, const uint64_t &len, char *resEnd, SecretType type) noexcept
{
    SECRET_CLASS_DISPOSE
    LIMIT_SECRET(MD5)
}
void MD5(char *res, const void *str, const uint64_t &len, SecretType type, unsigned resLen) noexcept
{
    SECRET_CLASS_DISPOSE_LEN
    LIMIT_SECRET(MD5)
}

void RC4(void *str, void *strEnd, const void *key, const void *keyEnd) noexcept
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    static Byte s[256], k[256];
    Byte i('\0'), tmp, *s_p(s), *k_p(k), j('\0'), *str_p((Byte *)str);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
    while (str_p != strEnd)
    {
        j += tmp = s[++i];
        s[i] = s[j];
        s[j] = tmp;
        *str_p++ ^= s[tmp += s[i]];
    }
}
RC4_ptr::RC4_ptr(void *data, const void *key, const void *keyEnd) noexcept : p((uint8_t *)data), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
}
RC4_file_read::RC4_file_read(const char *filename, const void *key, const void *keyEnd) noexcept : file(fopen(filename, "rb")), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
}
RC4_file_read::~RC4_file_read() noexcept
{
    if (file)
        fclose(file);
}
uint8_t RC4_file_read::get() noexcept
{
    Byte t = s[++i];
    s[i] = s[j += t];
    s[j] = t;
    return fgetc(file) ^ s[t += s[i]];
}
void RC4_file_read::get(void *memery, size_t size) noexcept
{
    Byte t, *p((Byte *)memery);
    while(size--)
    {
        t = s[++i];
        s[i] = s[j += t];
        s[j] = t;
        *p++ = fgetc(file) ^ s[t += s[i]];
    }
}
void RC4_file_read::getAll(void *memery) noexcept
{
    Byte t, *p((Byte *)memery);
    while (!feof(file))
    {
        t = s[++i];
        s[i] = s[j += t];
        s[j] = t;
        *p++ = fgetc(file) ^ s[t += s[i]];
    }
}
RC4_file_read::RC4_file_read(const char *filename, const void *key, const void *keyEnd, int filePos) noexcept : file(fopen(filename, "rb")), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
    fseek(file, filePos, SEEK_SET);
}
RC4_file_write::RC4_file_write(const char *filename, const void *key, const void *keyEnd) noexcept : file(fopen(filename, "wb")), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
}
RC4_file_write::RC4_file_write(const char *filename, const void *key, const void *keyEnd, int filePos) noexcept : file(fopen(filename, "wb")), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
    fseek(file, filePos, SEEK_SET);
}
RC4_file_write::~RC4_file_write() noexcept
{
    if(file)
        fclose(file);
}
void RC4_file_write::put(const void *memery, size_t size) noexcept
{
    Byte t;
    const Byte *m((const Byte *)memery);
    while (size--)
    {
        t = s[++i];
        s[i] = s[j += t];
        s[j] = t;
        fputc(*m++ ^ s[t += s[i]], file);
    }
}
void RC4_file_write::put(uint8_t data) noexcept
{
    Byte t(s[++i]);
    s[i] = s[j += t];
    s[j] = t;
    fputc(data ^ s[t += s[i]], file);
}
RC4_file_write::RC4_file_write(FILE *File, const void *key, const void *keyEnd) noexcept : file(File), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
}
RC4_file_read::RC4_file_read(FILE *File, const void *key, const void *keyEnd) noexcept : file(File), i('\0'), j('\0')
{
    const Byte *Key((const Byte *)key), *key_p(Key);
    Byte k[256], tmp, *s_p(s), *k_p(k);
    do
    {
        *s_p++ = i;
        *k_p++ = *key_p;
        if (++key_p == keyEnd)
            key_p = Key;
    } while (++i);
    s_p = s;
    k_p = k;
    do
    {
        j += (tmp = *s_p) + *k_p++;
        *s_p++ = s[j];
        s[j] = tmp;
    } while (++i);
    j = '\0';
}
