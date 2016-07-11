#ifndef _UNICODE
#define tobin tobin_A
#define tohex tohex_A
#else
#define tobin tobin_W
#define tohex tohex_W
#endif

void tohex_A(LPBYTE p, size_t len, char* out, bool reverse = false);
void tohex_W(LPBYTE p, size_t len, WCHAR* out, bool reverse = false);

void tobin_A(LPCSTR in, size_t len, LPBYTE p, bool reverse = false);
void tobin_W(LPWSTR in, size_t len, LPBYTE p, bool reverse = false);

