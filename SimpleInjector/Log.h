#pragma once

#include <stdio.h>

#ifdef _DEBUG

#define DebugPrint(fmt, ...) do{ wprintf(fmt, ##__VA_ARGS__);} while(0)
#define DebugLog(fmt, ...) do{ wprintf(L"<DEBUG> -- " fmt L"\n", ##__VA_ARGS__);} while(0)

#else

#define DebugPrint(fmt, ...) do{} while(0)
#define DebugLog(fmt, ...) do{} while(0)

#endif

#define Log(fmt, ...) do{ wprintf(L"<LOG> -- " fmt L"\n", ##__VA_ARGS__);} while(0)
#define ErrorLog(fmt, ...) do{ wprintf(L"<ERROR> Error 0x%08X -- " fmt L"\n", GetLastError(), ##__VA_ARGS__); exit(1);} while(0)
