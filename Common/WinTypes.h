typedef uint64_t UINT64;
typedef uint64_t *PUINT64;
typedef int64_t INT64;
typedef int64_t *PINT64;
typedef int64_t LONGLONG;
typedef int64_t *PLONGLONG;
typedef uint32_t UINT32;
typedef uint32_t *PUINT32;
typedef uint32_t UINT;
typedef uint32_t *PUINT;
typedef int32_t INT32;
typedef int32_t *PINT32;
typedef int32_t INT;
typedef int32_t *PINT;
typedef uint16_t UINT16;
typedef uint16_t *PUINT16;
typedef uint16_t USHORT;
typedef uint16_t WORD;
typedef uint16_t *LPWORD;
typedef uint16_t WCHAR;
typedef uint16_t *LPWSTR;
typedef uint16_t const *LPCWSTR;
typedef int16_t INT16;
typedef int16_t *PINT16;
typedef uint8_t BYTE;
typedef uint8_t *PBYTE;
typedef uint8_t *LPBYTE;
typedef uint8_t UCHAR;
typedef uint8_t *PUCHAR;
typedef char TCHAR;
typedef char CHAR;
typedef char *PCHAR;
typedef void* PVOID;
typedef void* LPVOID;
typedef char* LPSTR;
typedef char* LPTSTR;
typedef const char* LPCSTR;
typedef const char* LPCTSTR;
typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef uint32_t *PULONG;
typedef uint32_t *LPDWORD;
typedef int32_t LONG;
typedef void* HANDLE;
typedef uint32_t BOOL;
typedef LONG LSTATUS;
typedef uintptr_t ULONG_PTR;
typedef uintptr_t *PULONG_PTR;
typedef void *LPOVERLAPPED;
typedef struct _FILETIME {
    UINT32 dwLowDateTime;
    UINT32 dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

const int MAX_COMPUTERNAME_LENGTH = 15;
#define _tcsnicmp strncasecmp
#define _tcsncpy strncpy
#define _tcslen strlen
#define _tcscmp strcmp
#define _stprintf_s snprintf
#define sprintf_s snprintf
#define _tprintf_s printf
#define _tprintf printf
#define _tcscpy_s strcpy
#define _tcscpy strcpy
#define _tcscat strcat
#define _tcsncmp strncmp
#define _tcsicmp strcasecmp
#define _ttoi atoi
#define _totlower tolower
#define _totupper toupper
#define DeleteFile remove
#define _endthread(_x)
#define TRUE 1
#define FALSE 0
typedef FILE *FILEHANDLE;
const FILEHANDLE INVALID_HANDLE_VALUE = (FILEHANDLE)(intptr_t)-1;
const DWORD INFINITE = (DWORD)-1;
const int MAX_PATH = 260;
typedef HANDLE HKEY;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    int64_t QuadPart;
} LARGE_INTEGER;
#define __cdecl
#define _T(_x) _x
#define TEXT(_x) _x



