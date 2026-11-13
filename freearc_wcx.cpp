/*
        bzip2dll / FreeArc WCX plugin for Total Commander
        Based on bzip2dll WCX skeleton by Christian Ghisler (support@ghisler.com)
        and FreeArc Unarc by Bulat Ziganshin (http://freearc.org)
*/

#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <io.h>
#include <wchar.h>
#include <errno.h>
#include <setjmp.h>
#include <new>

/******************************************************************************
** Error propagation - longjmp, NOT C++ exceptions.
**
** C++ exceptions MUST NOT be used: a 32-bit MinGW build that links both
** libgcc and libstdc++ statically cannot unwind (no FDE lookup), so
** __cxa_throw ends in std::terminate -> abort() -> the host process
** (Total Commander) dies.  FreeArc's library is additionally compiled with
** -fno-exceptions, so a throw could never propagate through it anyway.
**
** Instead every translation unit is compiled with "/FI fa_check.h", which
** redefines CHECK to call fa_jmp_raise(code, msg).  WCX entry points (and the
** decompression worker thread) push a *thread-local* jump frame and are
** unwound with longjmp; FreeArc decompression threads that have no frame are
** routed to UnarcQuit() instead of crashing the host.  One CHECK definition
** for both the plugin and the statically-linked unarc driver avoids ODR
** clashes now that they live in the same PE module.
******************************************************************************/
#if defined(_MSC_VER)
#  define FA_THREAD_LOCAL __declspec(thread)
#else
#  define FA_THREAD_LOCAL __thread
#endif

struct FaJmpFrame {
    jmp_buf buf;
    FaJmpFrame *prev;
    volatile int code;
};

static FA_THREAD_LOCAL FaJmpFrame *g_faJmpTop = NULL;

/* Implemented in the statically linked Unarc/unarcdll.cpp.  Declared here
   because fa_check.h is force-included before Common.h is reached. */
extern "C" void UnarcQuit (int errcode, char* errmsg);

extern "C" void fa_jmp_raise(int code, char *msg)
{
    FaJmpFrame *f = g_faJmpTop;
    if (f) {
        f->code = code;
        longjmp(f->buf, 1);
    }
    /* No WCX frame on this thread: it is a FreeArc decompression thread.
       UnarcQuit() reports the message and only longjmps when the current
       thread is the one that called setjmp(jumper).  Never call ExitProcess
       here - that would kill Total Commander. */
    UnarcQuit(code, msg && msg[0] ? msg : (char*)"archive data corrupted");
}

/* Push/pop helpers kept as macros so that setjmp() stays in the caller frame */
#define FA_JMP_PUSH(jf)     do { (jf).prev = g_faJmpTop; (jf).code = 0; g_faJmpTop = &(jf); } while (0)
#define FA_JMP_POP(jf)      do { g_faJmpTop = (jf).prev; } while (0)

#include "../FreeArc-master/Unarc/ArcStructure.h"
#include "../FreeArc-master/Compression/MultiThreading.h"
extern "C" {
#include "../FreeArc-master/Compression/External/C_External.h"
}

char inifilename[MAX_PATH] = "wcplugin.ini";
HINSTANCE g_hInst = NULL;
/* hinstUnarcDll is declared extern in Compression.h (pulled in via
   ArcStructure.h) and defined in CompressionLibrary.cpp, which searches this
   module for facompress*.dll.  We only assign it from DllMain below. */

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInst = hinstDLL;
        hinstUnarcDll = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

/* Error codes returned to calling application.  Only the codes this plugin
   can actually return are defined here; the WCX SDK's unused codes (small
   buffer, too many files, ...) have been dropped. */
#define E_END_ARCHIVE     10            /* No more files in archive */
#define E_NO_MEMORY       11            /* Not enough memory */
#define E_BAD_DATA        12            /* Data is bad */
#define E_BAD_ARCHIVE     13            /* CRC error in archive data */
#define E_UNKNOWN_FORMAT  14            /* Archive format unknown */
#define E_EOPEN           15            /* Cannot open existing file */
#define E_ECREATE         16            /* Cannot create file */
#define E_ECLOSE          17            /* Error closing file */
#define E_EREAD           18            /* Error reading from file */
#define E_EWRITE          19            /* Error writing to file */
#define E_EABORTED        21            /* Function aborted by user */
#define E_NO_FILES        22            /* No files found */
#define E_NOT_SUPPORTED   24            /* Function not supported */

/* flags for ProcessFile */
#define PK_SKIP            0            /* Skip this file */
#define PK_TEST            1            /* Test file integrity */
#define PK_EXTRACT         2            /* Extract to disk */

/* For PackFiles */
#define PK_PACK_MOVE_FILES 1    /* Delete original after packing        */
#define PK_PACK_SAVE_PATHS 2    /* Save path names of files             */

/* Returned by GetPackCaps */
#define PK_CAPS_NEW        1    /* Can create new archives              */
#define PK_CAPS_MODIFY     2    /* Can modify exisiting archives        */
#define PK_CAPS_MULTIPLE   4    /* Archive can contain multiple files   */
#define PK_CAPS_DELETE     8    /* Can delete files                     */
#define PK_CAPS_OPTIONS   16    /* Has options dialog                   */
#define PK_CAPS_BY_CONTENT 64   /* Can detect archive by its contents   */
#define PK_CAPS_SEARCHTEXT 128  /* Allow searching in this archive type */

#define BACKGROUND_UNPACK 1      /* Which operations are thread-safe?    */
#define BACKGROUND_PACK 2

typedef struct {
    char ArcName[260];
    char FileName[260];
    int Flags;
    int PackSize;
    int UnpSize;
    int HostOS;
    int FileCRC;
    int FileTime;
    int UnpVer;
    int Method;
    int FileAttr;
    char* CmtBuf;
    int CmtBufSize;
    int CmtSize;
    int CmtState;
} tHeaderData;

typedef struct {
    char ArcName[1024];
    char FileName[1024];
    int Flags;
    DWORD PackSize;
    int PackSizeHigh;
    DWORD UnpSize;
    int UnpSizeHigh;
    int HostOS;
    int FileCRC;
    int FileTime;
    int UnpVer;
    int Method;
    int FileAttr;
    char* CmtBuf;
    int CmtBufSize;
    int CmtSize;
    int CmtState;
    char Unused[1024];
} tHeaderDataEx;

typedef struct {
    WCHAR ArcNameW[1024];
    WCHAR FileNameW[1024];
    int Flags;
    DWORD PackSize;
    int PackSizeHigh;
    DWORD UnpSize;
    int UnpSizeHigh;
    int HostOS;
    int FileCRC;
    int FileTime;
    int UnpVer;
    int Method;
    int FileAttr;
    char* CmtBuf;
    int CmtBufSize;
    int CmtSize;
    int CmtState;
    char Unused[1024];
} tHeaderDataExW;

typedef struct {
    char* ArcName;
    int OpenMode;
    int OpenResult;
    char* CmtBuf;
    int CmtBufSize;
    int CmtSize;
    int CmtState;
} tOpenArchiveData;

typedef struct {
    WCHAR* ArcNameW;
    int OpenMode;
    int OpenResult;
    WCHAR* CmtBufW;
    int CmtBufSize;
    int CmtSize;
    int CmtState;
} tOpenArchiveDataW;

typedef struct {
    int size;
    DWORD PluginInterfaceVersionLow;
    DWORD PluginInterfaceVersionHi;
    char DefaultIniName[MAX_PATH];
} PackDefaultParamStruct;

/* Definition of callback functions called by the DLL */
typedef int (__stdcall *tChangeVolProc)(char *ArcName, int Mode);
typedef int (__stdcall *tChangeVolProcW)(WCHAR *ArcName, int Mode);
typedef int (__stdcall *tProcessDataProc)(unsigned char *Addr, int Size);
typedef int (__stdcall *tProcessDataProcW)(WCHAR *Addr, int Size);

#define PASSWORDBUF_SIZE 2000
#define MAX_ARCHIVES 32

struct SolidWorker;
struct KdfCacheEntry;

typedef struct {
    char ArchiveName[1024];
    WCHAR ArchiveNameW[1024];
    char ArchiveNameUtf8[4096];
    int ArchiveOpen;
    int OpenMode;
    int ArchiveDate;
    int UnpVer;
    ARCHIVE *arcinfo;
    DIRECTORY_BLOCK *dirblock;
    MYFILE *infile;              /* archive read handle owned by this slot, reused by every solid block */
    struct KdfCacheEntry *kdf_cache;   /* lazily allocated PBKDF2 result cache */
    int kdf_next;                      /* round-robin insertion cursor */
    int current_ctrl_block;
    int current_file_in_block;
    int current_data_block;
    bool header_read;
    char pwd[PASSWORDBUF_SIZE + 1];
    SolidWorker *worker;
    tChangeVolProc ChangeVolProc;
    tChangeVolProcW ChangeVolProcW;
    tProcessDataProc ProcessDataProc;
    tProcessDataProcW ProcessDataProcW;
} ArchiveRec;

static CRITICAL_SECTION slotcriticalsection;
static BOOL slotcriticalsectioninitialized = FALSE;
static BOOL externalCompressorsRegistered = FALSE;
static ArchiveRec ArchiveList[MAX_ARCHIVES + 1]; /* 0 for packing, 1..MAX_ARCHIVES for unpacking */

static char* strlcpy_safe(char* dst, const char* src, int maxlen)
{
    if (!dst || maxlen <= 0) return dst;
    if (!src) { dst[0] = 0; return dst; }
    if ((int)strlen(src) >= maxlen) {
        strncpy(dst, src, maxlen);
        dst[maxlen] = 0;
    } else {
        strcpy(dst, src);
    }
    return dst;
}

static WCHAR* wcslcpy_safe(WCHAR* dst, const WCHAR* src, int maxlen)
{
    if (!dst || maxlen <= 0) return dst;
    if (!src) { dst[0] = 0; return dst; }
    if ((int)wcslen(src) >= maxlen) {
        wcsncpy(dst, src, maxlen);
        dst[maxlen] = 0;
    } else {
        wcscpy(dst, src);
    }
    return dst;
}

static int MapFreeArcError(int code, bool isOpen)
{
    switch (code) {
        case FREEARC_OK:
        case FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED:
            return 0;
        case FREEARC_ERRCODE_NOT_ENOUGH_MEMORY:
            return E_NO_MEMORY;
        case FREEARC_ERRCODE_READ:
            return isOpen ? E_EOPEN : E_EREAD;
        case FREEARC_ERRCODE_WRITE:
            return E_EWRITE;
        case FREEARC_ERRCODE_BAD_CRC:
            return E_BAD_ARCHIVE;
        case FREEARC_ERRCODE_BAD_COMPRESSED_DATA:
            return E_BAD_DATA;
        case FREEARC_ERRCODE_BAD_HEADERS:
            return isOpen ? E_UNKNOWN_FORMAT : E_BAD_ARCHIVE;
        case FREEARC_ERRCODE_BAD_PASSWORD:
        case FREEARC_ERRCODE_OPERATION_TERMINATED:
            return E_EABORTED;
        case FREEARC_ERRCODE_INVALID_COMPRESSOR:
        case FREEARC_ERRCODE_NOT_IMPLEMENTED:
            return E_NOT_SUPPORTED;
        default:
            return isOpen ? E_UNKNOWN_FORMAT : E_BAD_ARCHIVE;
    }
}

static int UnixTimeToDosTime(time_t t)
{
    if (t <= 0) return 0;
    struct tm *fttm = localtime(&t);
    if (!fttm) return 0;
    int year = fttm->tm_year - 80;
    if (year < 0) year = 0;
    unsigned short time = (unsigned short)((fttm->tm_hour << 11) | (fttm->tm_min << 5) | ((fttm->tm_sec >> 1) & 0x1F));
    unsigned short date = (unsigned short)((year << 9) | ((fttm->tm_mon + 1) << 5) | fttm->tm_mday);
    return (((int)date) << 16) | time;
}

/* Forward declarations for functions defined later in this file. */
static bool FindArcExe(WCHAR *outExe, size_t maxLen);

static void EnsureExternalCompressorsRegistered()
{
    if (externalCompressorsRegistered) return;
    externalCompressorsRegistered = TRUE;

#ifdef _WIN64
    SetCompressionThreads(GetProcessorsCount());
#else
    /* A 32-bit host (32-bit TotalCmd is not /LARGEADDRESSAWARE) has only
       2 GB of user address space.  This must be a GLOBAL single thread:
       LZMA2/other codecs read GetCompressionThreads() themselves to size
       their internal dictionaries and to create their own worker threads,
       bypassing MTCompressor::NumThreads entirely.  Limiting only the latter
       leaves an inconsistent configuration that can hang on large solid
       blocks.  AllocateBuffers() additionally caps buffers by block size. */
    SetCompressionThreads(1);
#endif

    WCHAR iniPathW[MAX_PATH] = {0};
    bool found = false;

    if (g_hInst && GetModuleFileNameW(g_hInst, iniPathW, MAX_PATH)) {
        WCHAR *slash = wcsrchr(iniPathW, L'\\');
        if (slash) {
            wcscpy(slash + 1, L"arc.ini");
            found = file_exists(iniPathW) != 0;
        }
    }
    if (!found) {
        WCHAR arcExe[MAX_PATH] = {0};
        if (FindArcExe(arcExe, MAX_PATH)) {
            WCHAR *slash = wcsrchr(arcExe, L'\\');
            if (slash) {
                wcscpy(slash + 1, L"arc.ini");
                wcslcpy_safe(iniPathW, arcExe, MAX_PATH - 1);
                found = file_exists(iniPathW) != 0;
            }
        }
    }

    /* AddExternalCompressor() below can CHECK, which longjmps out of here.
       Without this frame we would leave a buffer leaked and, worse, unwind
       through UnarcQuit() with no active command.  `contents` is volatile so
       the handler can free it after the jump. */
    char *volatile contents = NULL;
    FaJmpFrame jf;
    FA_JMP_PUSH(jf);
    if (setjmp(jf.buf) != 0) {
        FA_JMP_POP(jf);
        free(contents);                 /* longjmp skips no destructor here */
        return;                         /* a malformed arc.ini is non-fatal */
    }

    if (found) {
        /* Read the file with plain Win32 calls instead of MYFILE: a MYFILE
           that is alive across a longjmp is never destroyed (longjmp does not
           run destructors), so its handle and three buffers leaked every time
           a malformed arc.ini made the parser raise. */
        HANDLE h = CreateFileW(iniPathW, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fsz;
            if (GetFileSizeEx(h, &fsz) && fsz.QuadPart > 0 &&
                fsz.QuadPart < 4 * 1024 * 1024) {
                DWORD want = (DWORD)fsz.QuadPart;
                contents = (char*)malloc((size_t)want + 2);
                if (contents) {
                    DWORD total = 0;
                    contents[0] = '\n';
                    while (total < want) {
                        DWORD got = 0;
                        if (!ReadFile(h, contents + 1 + total, want - total, &got, NULL) || got == 0)
                            break;
                        total += got;
                    }
                    if (total > 0) {
                        contents[total + 1] = '\0';
                        const char *ANY_HEADING = "\n[";
                        const char *EXT_HEADING = "[External compressor:";
                        ClearExternalCompressorsTable();
                        for (char *p, *section = strstr(contents, ANY_HEADING); section != NULL; section = p) {
                            section++;
                            p = strstr(section, ANY_HEADING);
                            if (p) *p = '\0';
                            if (start_with(section, (char*)EXT_HEADING)) {
                                AddExternalCompressor(section);
                            }
                        }
                    }
                    free(contents);
                    contents = NULL;
                }
            }
            CloseHandle(h);
        }
    }

    FA_JMP_POP(jf);
}

/******************************************************************************
** Password Prompt Dialog (in-memory Win32 dialog template)                  **
******************************************************************************/
struct PasswordDlgData {
    char *pwdBuf;
};

static INT_PTR CALLBACK PasswordDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
            SetFocus(GetDlgItem(hwndDlg, 101));
            return FALSE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                PasswordDlgData *data = (PasswordDlgData*)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);
                if (data && data->pwdBuf) {
                    WCHAR wbuf[PASSWORDBUF_SIZE] = {0};
                    GetDlgItemTextW(hwndDlg, 101, wbuf, PASSWORDBUF_SIZE - 1);
                    utf16_to_utf8(wbuf, data->pwdBuf);
                }
                EndDialog(hwndDlg, IDOK);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwndDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

static WORD* AlignDword(WORD* ptr)
{
    ULONG_PTR ul = (ULONG_PTR)ptr;
    ul = (ul + 3) & ~((ULONG_PTR)3);
    return (WORD*)ul;
}

static WORD* WriteWStr(WORD* ptr, const WCHAR* str)
{
    while ((*ptr++ = *str++) != 0) {}
    return ptr;
}

static bool PromptPassword(char *pwd)
{
    BYTE buf[1024];
    memset(buf, 0, sizeof(buf));
    DLGTEMPLATE *dlg = (DLGTEMPLATE*)buf;
    dlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_SETFONT;
    dlg->cdit = 4;
    dlg->x = 0; dlg->y = 0;
    dlg->cx = 200; dlg->cy = 75;

    WORD *p = (WORD*)(dlg + 1);
    *p++ = 0; // no menu
    *p++ = 0; // default dialog class
    p = WriteWStr(p, L"FreeArc Password Required");
    *p++ = 8; // font size
    p = WriteWStr(p, L"MS Shell Dlg");

    // 1. Static label
    p = AlignDword(p);
    DLGITEMTEMPLATE *item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
    item->x = 10; item->y = 10; item->cx = 180; item->cy = 12;
    item->id = 100;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0082; // Static
    p = WriteWStr(p, L"Enter decryption password:");
    *p++ = 0;

    // 2. Password Edit control (id = 101)
    p = AlignDword(p);
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL;
    item->x = 10; item->y = 24; item->cx = 180; item->cy = 14;
    item->id = 101;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0081; // Edit
    p = WriteWStr(p, L"");
    *p++ = 0;

    // 3. OK button (IDOK)
    p = AlignDword(p);
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON;
    item->x = 45; item->y = 48; item->cx = 50; item->cy = 15;
    item->id = IDOK;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0080; // Button
    p = WriteWStr(p, L"OK");
    *p++ = 0;

    // 4. Cancel button (IDCANCEL)
    p = AlignDword(p);
    item = (DLGITEMTEMPLATE*)p;
    item->style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
    item->x = 105; item->y = 48; item->cx = 50; item->cy = 15;
    item->id = IDCANCEL;
    p = (WORD*)(item + 1);
    *p++ = 0xFFFF; *p++ = 0x0080; // Button
    p = WriteWStr(p, L"Cancel");
    *p++ = 0;

    PasswordDlgData data = { pwd };
    INT_PTR res = DialogBoxIndirectParamW(g_hInst, dlg, GetActiveWindow(), PasswordDlgProc, (LPARAM)&data);
    return (res == IDOK);
}

/******************************************************************************
** Decryption key generation & PBKDF2 result cache                           **
******************************************************************************/
/* Every solid block (and every directory block) used to run Pbkdf2Hmac again,
   which is deliberately slow.  The derived key depends only on the password,
   salt, iteration count, key size and check code - normally identical for a
   whole archive - so keep a few results per archive slot and drop them on
   CloseArchive.  Non-encrypted archives pay nothing (lazy allocation). */
#define KDF_CACHE_SLOTS 4

struct KdfCacheEntry {
    bool valid;
    int keySize, saltSize, numIterations, checkCodeSize;
    BYTE salt[MAXKEYSIZE];
    BYTE checkCode[MAXKEYSIZE];
    BYTE key_and_checkCode[MAXKEYSIZE * 2];
    char pwd[PASSWORDBUF_SIZE + 1];
};

static bool KdfCacheValid(int saltSize, int numIterations, int checkCodeSize, int keySize)
{
    return saltSize >= 0 && saltSize <= MAXKEYSIZE &&
           checkCodeSize >= 0 && checkCodeSize <= MAXKEYSIZE &&
           keySize >= 0 && keySize <= MAXKEYSIZE &&
           keySize + checkCodeSize <= MAXKEYSIZE * 2;
}

static bool KdfLookup(ArchiveRec *arc, const BYTE *salt, int saltSize,
                      int numIterations, const BYTE *checkCode, int checkCodeSize,
                      int keySize, BYTE *out)
{
    if (!arc->kdf_cache || !KdfCacheValid(saltSize, numIterations, checkCodeSize, keySize))
        return false;
    for (int i = 0; i < KDF_CACHE_SLOTS; i++) {
        KdfCacheEntry &e = arc->kdf_cache[i];
        if (!e.valid || e.saltSize != saltSize || e.numIterations != numIterations ||
            e.checkCodeSize != checkCodeSize || e.keySize != keySize)
            continue;
        if (memcmp(e.salt, salt, saltSize) != 0 ||
            memcmp(e.checkCode, checkCode, checkCodeSize) != 0 ||
            strcmp(e.pwd, arc->pwd) != 0)
            continue;
        memcpy(out, e.key_and_checkCode, keySize + checkCodeSize);
        return true;
    }
    return false;
}

static void KdfStore(ArchiveRec *arc, const BYTE *salt, int saltSize,
                     int numIterations, const BYTE *checkCode, int checkCodeSize,
                     int keySize, const BYTE *key)
{
    if (!KdfCacheValid(saltSize, numIterations, checkCodeSize, keySize))
        return;   /* malformed parameters: stay on the original un-cached path */
    if (!arc->kdf_cache) {
        arc->kdf_cache = new (std::nothrow) KdfCacheEntry[KDF_CACHE_SLOTS]();
        if (!arc->kdf_cache) return;
    }
    KdfCacheEntry &e = arc->kdf_cache[arc->kdf_next++ % KDF_CACHE_SLOTS];
    e.valid = true;
    e.saltSize = saltSize;
    e.numIterations = numIterations;
    e.checkCodeSize = checkCodeSize;
    e.keySize = keySize;
    memcpy(e.salt, salt, saltSize);
    memcpy(e.checkCode, checkCode, checkCodeSize);
    memcpy(e.key_and_checkCode, key, keySize + checkCodeSize);
    strlcpy_safe(e.pwd, arc->pwd, PASSWORDBUF_SIZE);
}

static char* GenerateDecryptionForArchive(char* compressor, char* new_compressor, void* auxdata)
{
    ArchiveRec *arc = (ArchiveRec*)auxdata;
    if (!compressorIsEncrypted(compressor))
        return compressor;

    char new_method_buf[MAX_COMPRESSOR_STRLEN], *new_method = new_method_buf;
    CMETHOD cm[MAX_METHODS_IN_COMPRESSOR];
    int N = split(compressor, COMPRESSION_METHODS_DELIMITER, cm, MAX_METHODS_IN_COMPRESSOR);
    for (int i = 0; i < N; i++) {
        CMETHOD method = cm[i];
        if (CompressionService(method, (char*)"encryption?", 0, NULL, NULL) > 0) {
            int keySize = CompressionService(method, (char*)"keySize", 0, NULL, NULL);
            int error = 0;

            CPARAM param[MAX_PARAMETERS];
            int paramcnt = split(method, COMPRESSION_METHOD_PARAMETERS_DELIMITER, param, MAX_PARAMETERS - 1);

            char *saltStr = search_param(param + 1, (char*)"s");
            int saltSize = saltStr ? (int)strlen(saltStr) / 2 : 0;
            BYTE salt[MAXKEYSIZE];
            if (saltStr) decode16(saltStr, salt);

            char *checkCodeStr = search_param(param + 1, (char*)"c");
            int checkCodeSize = checkCodeStr ? (int)strlen(checkCodeStr) / 2 : 0;
            BYTE checkCode[MAXKEYSIZE];
            if (checkCodeStr) decode16(checkCodeStr, checkCode);

            char *numIterationsStr = search_param(param + 1, (char*)"n");
            int numIterations = numIterationsStr ? (int)parseInt(numIterationsStr, &error) : 1000;

            BYTE key_and_checkCode[MAXKEYSIZE * 2];

        retry:
            if (!KdfLookup(arc, salt, saltSize, numIterations, checkCode, checkCodeSize,
                           keySize, key_and_checkCode)) {
                Pbkdf2Hmac((BYTE*)arc->pwd, (int)strlen(arc->pwd), salt, saltSize,
                           numIterations, key_and_checkCode, keySize + checkCodeSize);

                if (memcmp(key_and_checkCode + keySize, checkCode, checkCodeSize) != 0) {
                    if (PromptPassword(arc->pwd))
                        goto retry;
                    CHECK(FREEARC_ERRCODE_BAD_PASSWORD, FALSE, (s, "ERROR: wrong password"));
                }
                KdfStore(arc, salt, saltSize, numIterations, checkCode, checkCodeSize,
                         keySize, key_and_checkCode);
            }

            char keyParam[MAXKEYSIZE * 2 + 2];
            keyParam[0] = 'k';
            encode16(key_and_checkCode, keySize, keyParam + 1);
            param[paramcnt++] = keyParam;
            param[paramcnt++] = NULL;

            join(param, COMPRESSION_METHOD_PARAMETERS_DELIMITER, new_method, (int)(endof(new_method_buf) - new_method));
            cm[i] = new_method;
            new_method += strlen(new_method) + 1;
        }
    }
    join(cm, COMPRESSION_METHODS_DELIMITER, new_compressor, MAX_COMPRESSOR_STRLEN);
    return new_compressor;
}

/******************************************************************************
** Solid Block Streaming Decompression Worker                                **
******************************************************************************/
struct SolidWorker {
    ArchiveRec *arc;             /* owns the shared archive read handle */
    DIRECTORY_BLOCK *dirblock;
    int ctrl_block_idx;
    int data_block_idx;
    int curfile;
    int end_file;

    int target_file;
    int target_op;
    WCHAR target_dest[MY_FILENAME_MAX];

    FILESIZE bytes_left;        /* archive read handle lives in arc->infile */
    char compressor_buf[MAX_COMPRESSOR_STRLEN];
    char *compressor_to_use;

    Thread thread;
    Event mainToWorkerEvent;
    Event workerToMainEvent;

    enum State { STATE_IDLE, STATE_PROGRESS, STATE_FILE_DONE, STATE_FINISHED };
    volatile State state;
    volatile int progress_bytes;                /* payload of the handshake visible to the main thread */
    volatile int pending_bytes;                 /* worker-only: decoded bytes not yet reported */
    DWORD last_progress_tick;                   /* worker-only: last report timestamp */
    volatile bool stop_requested;
    volatile bool abort_requested;
    volatile int file_err;

    /* Progress coalescing: the codec delivers ~256 KB per "write" callback and
       the original code performed a full event ping-pong for every chunk plus
       another one at file end.  Accumulate instead and only cross the thread
       boundary once ~1 MB has been decoded or 100 ms have elapsed (the time
       bound keeps cancellation responsive on slow codecs).  The accumulated
       remainder is folded into the FILE_DONE / FINISHED handshake, so the sum
       of all ProcessDataProc sizes still equals the file size exactly. */
    enum { PROGRESS_REPORT_BYTES = 1 << 20, PROGRESS_REPORT_MS = 100 };

    bool AccumulateProgress(int n)
    {
        pending_bytes += n;
        DWORD now = GetTickCount();
        if (pending_bytes < PROGRESS_REPORT_BYTES &&
            (DWORD)(now - last_progress_tick) < PROGRESS_REPORT_MS)
            return true;

        progress_bytes = pending_bytes;
        pending_bytes = 0;
        last_progress_tick = now;
        state = STATE_PROGRESS;
        workerToMainEvent.Signal();
        mainToWorkerEvent.Wait();
        return !(abort_requested || stop_requested);
    }

    void BeginFileDone()
    {
        progress_bytes = pending_bytes;
        pending_bytes = 0;
        last_progress_tick = GetTickCount();
        state = STATE_FILE_DONE;
    }

    bool file_opened;
    MYFILE outfile;
    FILESIZE bytes_to_write;
    CRC crc;

    SolidWorker(ArchiveRec *_arc, DIRECTORY_BLOCK *_dir, int _ctrl_idx, int _data_idx)
        : arc(_arc), dirblock(_dir), ctrl_block_idx(_ctrl_idx), data_block_idx(_data_idx)
    {
        curfile = dirblock->block_start(data_block_idx);
        end_file = dirblock->block_end(data_block_idx) - 1;
        while (curfile <= end_file && dirblock->size[curfile] == 0)
            curfile++;

        target_file = -1;
        target_op = PK_SKIP;
        target_dest[0] = 0;

        state = STATE_IDLE;
        progress_bytes = 0;
        pending_bytes = 0;
        last_progress_tick = GetTickCount();
        stop_requested = false;
        abort_requested = false;
        file_err = 0;
        file_opened = false;
        bytes_to_write = 0;
        crc = INIT_CRC;
        compressor_to_use = NULL;
    }

    int DecompressCallback(const char *what, void *buf, int size)
    {
        if (strequ(what, "read")) {
            if (stop_requested || abort_requested)
                return FREEARC_ERRCODE_OPERATION_TERMINATED;

            if (curfile < target_file) {
                progress_bytes = 0;
                state = STATE_PROGRESS;
                workerToMainEvent.Signal();
                mainToWorkerEvent.Wait();
                if (abort_requested || stop_requested) {
                    file_err = E_EABORTED;
                    stop_requested = true;
                    return FREEARC_ERRCODE_OPERATION_TERMINATED;
                }
            }

            int read_bytes = (int)mymin(bytes_left, (FILESIZE)size);
            if (read_bytes == 0) return 0;
            int len = ::read(arc->infile->handle, buf, read_bytes);
            if (len < 0) {
                file_err = E_EREAD;
                return FREEARC_ERRCODE_READ;
            }
            bytes_left -= len;
            return len;

        } else if (strequ(what, "write")) {
            if (stop_requested || abort_requested)
                return FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED;

            int origsize = size;
            uint8 *p = (uint8*)buf;

            while (size > 0) {
                while (curfile <= end_file && dirblock->size[curfile] == 0)
                    curfile++;
                if (curfile > end_file)
                    return FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED;

                if (!file_opened) {
                    while (!stop_requested && target_file < curfile) {
                        BeginFileDone();
                        workerToMainEvent.Signal();
                        mainToWorkerEvent.Wait();
                    }
                    if (stop_requested)
                        return FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED;

                    crc = INIT_CRC;
                    bytes_to_write = dirblock->size[curfile];
                    file_opened = true;

                    if (curfile == target_file && target_op == PK_EXTRACT) {
                        char utf8dest[MY_FILENAME_MAX * 4];
                        utf16_to_utf8(target_dest, utf8dest);
                        outfile.setname(utf8dest);
                        if (outfile.exists())
                            outfile.remove_readonly_attrib();
                        if (!outfile.tryOpen(WRITE_MODE)) {
                            file_err = E_ECREATE;
                            stop_requested = true;
                            return FREEARC_ERRCODE_WRITE;
                        }
                    }
                }

                int n = (int)mymin(bytes_to_write, (FILESIZE)size);
                if (curfile == target_file) {
                    crc = UpdateCRC(p, n, crc);
                    if (target_op == PK_EXTRACT && n > 0) {
                        if (::write(outfile.handle, p, n) != n) {
                            outfile.tryClose();
                            outfile.remove();
                            file_err = E_EWRITE;
                            stop_requested = true;
                            return FREEARC_ERRCODE_WRITE;
                        }
                    }
                    if (!AccumulateProgress(n)) {
                        if (target_op == PK_EXTRACT && outfile.isopen()) {
                            outfile.tryClose();
                            outfile.remove();
                        }
                        file_err = E_EABORTED;
                        stop_requested = true;
                        return FREEARC_ERRCODE_OPERATION_TERMINATED;
                    }
                }

                bytes_to_write -= n;
                p += n;
                size -= n;

                if (bytes_to_write == 0) {
                    file_opened = false;
                    if (curfile == target_file) {
                        if (target_op == PK_EXTRACT && outfile.isopen()) {
                            outfile.tryClose();
                            outfile.SetFileDateTime(dirblock->time[curfile]);
                        }
                        if ((crc ^ INIT_CRC) != dirblock->crc[curfile]) {
                            if (target_op == PK_EXTRACT)
                                outfile.remove();
                            file_err = E_BAD_ARCHIVE;
                        }
                    }
                    curfile++;
                    while (curfile <= end_file && dirblock->size[curfile] == 0)
                        curfile++;
                    if (curfile > end_file)
                        return FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED;
                    if (curfile > target_file) {
                        while (!stop_requested && target_file < curfile) {
                            BeginFileDone();
                            workerToMainEvent.Signal();
                            mainToWorkerEvent.Wait();
                        }
                        if (stop_requested)
                            return FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED;
                    }
                }
            }
            return origsize;
        }
        return FREEARC_ERRCODE_NOT_IMPLEMENTED;
    }
};

static int solid_decompress_callback(const char *what, void *buf, int size, void *auxdata)
{
    return ((SolidWorker*)auxdata)->DecompressCallback(what, buf, size);
}

static THREAD_FUNC_RET_TYPE THREAD_FUNC_CALL_TYPE solid_worker_thread(void *paramPtr)
{
    SolidWorker *w = (SolidWorker*)paramPtr;
    int result = FREEARC_OK;
    FaJmpFrame jf;
    FA_JMP_PUSH(jf);
    if (setjmp(jf.buf) != 0) {
        /* A CHECK (corrupt stream / bad data / bad password) fired inside
           Decompress() on this thread and longjmp'd back here.  Treat it as a
           decode error and fall through to the shared cleanup below. */
        result = jf.code ? jf.code : FREEARC_ERRCODE_GENERAL;
    } else {
        result = Decompress(w->compressor_to_use, solid_decompress_callback, w);
    }
    FA_JMP_POP(jf);

    if (w->file_opened) {
        if (w->outfile.isopen()) {
            w->outfile.tryClose();
            w->outfile.remove();
        }
        w->file_opened = false;
        if (w->file_err == 0 && !w->stop_requested)
            w->file_err = E_BAD_ARCHIVE;
    }
    if (result < 0 && result != FREEARC_ERRCODE_NO_MORE_DATA_REQUIRED && w->file_err == 0 && !w->stop_requested) {
        w->file_err = MapFreeArcError(result, false);
    }
    /* FINISHED also closes the last file: hand its unreported tail to the
       main thread so the progress total stays exact. */
    w->progress_bytes = w->pending_bytes;
    w->pending_bytes = 0;
    w->state = SolidWorker::STATE_FINISHED;
    w->workerToMainEvent.Signal();
    return 0;
}

static void StopSolidWorker(ArchiveRec *arc)
{
    if (!arc || !arc->worker) return;
    SolidWorker *w = arc->worker;
    if (w->thread.IsCreated()) {
        if (w->state != SolidWorker::STATE_FINISHED) {
            w->stop_requested = true;
            w->mainToWorkerEvent.Signal();
            while (w->state != SolidWorker::STATE_FINISHED) {
                w->workerToMainEvent.Wait();
                if (w->state != SolidWorker::STATE_FINISHED) {
                    w->stop_requested = true;
                    w->mainToWorkerEvent.Signal();
                }
            }
        }
        w->thread.Wait();
        w->thread.Close();
    }
    delete w;
    arc->worker = NULL;
}

static void CleanupArchiveSlot(ArchiveRec *arc)
{
    if (!arc) return;
    /* Stop the decoder first: it is the only user of the shared handle. */
    StopSolidWorker(arc);
    if (arc->infile) {
        arc->infile->tryClose();
        delete arc->infile;
        arc->infile = NULL;
    }
    if (arc->kdf_cache) {
        delete[] arc->kdf_cache;
        arc->kdf_cache = NULL;
    }
    arc->kdf_next = 0;
    if (arc->dirblock) {
        delete arc->dirblock;
        arc->dirblock = NULL;
    }
    if (arc->arcinfo) {
        delete arc->arcinfo;
        arc->arcinfo = NULL;
    }
    arc->ArchiveOpen = 0;
    arc->header_read = false;
}

static int CallProcessDataProc(ArchiveRec *arc, const WCHAR *fileNameW, int size)
{
    if (arc->ProcessDataProcW) {
        return arc->ProcessDataProcW((WCHAR*)fileNameW, size);
    } else if (arc->ProcessDataProc) {
        char fileNameA[1024] = {0};
        if (fileNameW) {
            WideCharToMultiByte(CP_ACP, 0, fileNameW, -1, fileNameA, sizeof(fileNameA) - 1, NULL, NULL);
        }
        return arc->ProcessDataProc(fileNameW ? (unsigned char*)fileNameA : NULL, size);
    }
    return 1;
}

/******************************************************************************
** WCX Exported Functions: OpenArchive / OpenArchiveW / CloseArchive         **
******************************************************************************/
static int OpenArchiveInternal(const WCHAR *arcNameW, int openMode, int *openResult, char *cmtBuf, int cmtBufSize, int *cmtSize, int *cmtState)
{
    EnsureExternalCompressorsRegistered();

    if (!slotcriticalsectioninitialized) {
        slotcriticalsectioninitialized = TRUE;
        InitializeCriticalSection(&slotcriticalsection);
    }

    int ArcHandle = 0;
    EnterCriticalSection(&slotcriticalsection);
    for (int i = 1; i <= MAX_ARCHIVES; i++) {
        if (ArchiveList[i].ArchiveOpen == 0) {
            ArcHandle = i;
            ArchiveList[i].ArchiveOpen = 1;
            break;
        }
    }
    LeaveCriticalSection(&slotcriticalsection);

    if (ArcHandle == 0) {
        *openResult = E_NO_MEMORY;
        return 0;
    }

    ArchiveRec *arc = &ArchiveList[ArcHandle];
    arc->OpenMode = openMode;
    arc->arcinfo = NULL;
    arc->dirblock = NULL;
    arc->infile = NULL;
    arc->worker = NULL;
    arc->kdf_cache = NULL;
    arc->kdf_next = 0;
    arc->current_ctrl_block = -1;
    arc->current_file_in_block = 0;
    arc->current_data_block = 0;
    arc->header_read = false;
    arc->UnpVer = 0;
    arc->pwd[0] = 0;

    wcslcpy_safe(arc->ArchiveNameW, arcNameW, 1023);
    WideCharToMultiByte(CP_ACP, 0, arcNameW, -1, arc->ArchiveName, sizeof(arc->ArchiveName) - 1, NULL, NULL);
    utf16_to_utf8(arcNameW, arc->ArchiveNameUtf8);

    struct _stat ftbuf;
    if (_wstat(arcNameW, &ftbuf) == 0) {
        arc->ArchiveDate = UnixTimeToDosTime(ftbuf.st_mtime);
    } else {
        arc->ArchiveDate = 0;
    }

    FaJmpFrame jf;
    FA_JMP_PUSH(jf);
    if (setjmp(jf.buf) != 0) {
        FA_JMP_POP(jf);
        *openResult = jf.code ? MapFreeArcError(jf.code, true) : E_UNKNOWN_FORMAT;
        CleanupArchiveSlot(arc);
        return 0;
    }

    arc->arcinfo = new (std::nothrow) ARCHIVE(arc->ArchiveNameUtf8);
    if (!arc->arcinfo) {
        FA_JMP_POP(jf);
        *openResult = E_NO_MEMORY;
        CleanupArchiveSlot(arc);
        return 0;
    }
    arc->arcinfo->read_structure(GenerateDecryptionForArchive, arc);

    if (cmtBuf && cmtBufSize > 0 && arc->arcinfo->arcComment.size > 0) {
        int copyLen = mymin(cmtBufSize - 1, arc->arcinfo->arcComment.size);
        memcpy(cmtBuf, &arc->arcinfo->arcComment[0], copyLen);
        cmtBuf[copyLen] = 0;
        if (cmtSize) *cmtSize = copyLen + 1;
        if (cmtState) *cmtState = (copyLen < arc->arcinfo->arcComment.size) ? 2 : 1;
    } else {
        if (cmtSize) *cmtSize = 0;
        if (cmtState) *cmtState = 0;
    }
    FA_JMP_POP(jf);

    *openResult = 0;
    return ArcHandle;
}

extern "C" HANDLE __stdcall OpenArchive(tOpenArchiveData* ArchiveData)
{
    if (!ArchiveData || !ArchiveData->ArcName) return 0;
    WCHAR arcNameW[1024] = {0};
    MultiByteToWideChar(CP_ACP, 0, ArchiveData->ArcName, -1, arcNameW, 1023);
    int h = OpenArchiveInternal(arcNameW, ArchiveData->OpenMode, &ArchiveData->OpenResult,
                                ArchiveData->CmtBuf, ArchiveData->CmtBufSize,
                                &ArchiveData->CmtSize, &ArchiveData->CmtState);
    return (HANDLE)(INT_PTR)h;
}

extern "C" HANDLE __stdcall OpenArchiveW(tOpenArchiveDataW* ArchiveData)
{
    if (!ArchiveData || !ArchiveData->ArcNameW) return 0;
    char cmtBufA[4096] = {0};
    int cmtSize = 0, cmtState = 0;
    int h = OpenArchiveInternal(ArchiveData->ArcNameW, ArchiveData->OpenMode, &ArchiveData->OpenResult,
                                ArchiveData->CmtBufW ? cmtBufA : NULL,
                                ArchiveData->CmtBufW ? (int)mymin((int)sizeof(cmtBufA), ArchiveData->CmtBufSize) : 0,
                                &cmtSize, &cmtState);
    if (h && ArchiveData->CmtBufW && cmtSize > 0) {
        MultiByteToWideChar(CP_UTF8, 0, cmtBufA, -1, ArchiveData->CmtBufW, ArchiveData->CmtBufSize);
        ArchiveData->CmtSize = (int)wcslen(ArchiveData->CmtBufW) + 1;
        ArchiveData->CmtState = cmtState;
    }
    return (HANDLE)(INT_PTR)h;
}

extern "C" int __stdcall CloseArchive(HANDLE hArcData)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx > 0 && idx <= MAX_ARCHIVES && ArchiveList[idx].ArchiveOpen) {
        CleanupArchiveSlot(&ArchiveList[idx]);
        return 0;
    }
    return E_ECLOSE;
}

/******************************************************************************
** WCX Exported Functions: ReadHeader / ReadHeaderEx / ReadHeaderExW         **
******************************************************************************/
static int AdvanceAndReadNextHeader(ArchiveRec *arc, WCHAR *fileNameW, int maxFileNameW,
                                    uint64 *outPackSize, uint64 *outUnpSize,
                                    int *outFileAttr, int *outFileTime, int *outFileCRC)
{
    FaJmpFrame jf;
    FA_JMP_PUSH(jf);
    if (setjmp(jf.buf) != 0) {
        FA_JMP_POP(jf);
        arc->header_read = false;
        return jf.code ? MapFreeArcError(jf.code, false) : E_BAD_ARCHIVE;
    }

        if (arc->current_ctrl_block < 0 || ++arc->current_file_in_block >= arc->dirblock->total_files) {
            StopSolidWorker(arc);
            if (arc->dirblock) {
                delete arc->dirblock;
                arc->dirblock = NULL;
            }
            for (;;) {
                if (++arc->current_ctrl_block >= arc->arcinfo->control_blocks_descriptors.size) {
                    arc->header_read = false;
                    FA_JMP_POP(jf);
                    return E_END_ARCHIVE;
                }
                BLOCK &descriptor = arc->arcinfo->control_blocks_descriptors[arc->current_ctrl_block];
                if (descriptor.type == DIR_BLOCK) {
                    arc->dirblock = new DIRECTORY_BLOCK(*arc->arcinfo, descriptor, GenerateDecryptionForArchive, arc);
                    arc->current_file_in_block = 0;
                    arc->current_data_block = 0;
                    if (arc->dirblock->total_files > 0)
                        break;
                    delete arc->dirblock;
                    arc->dirblock = NULL;
                }
            }
        }

        DIRECTORY_BLOCK *dir = arc->dirblock;
        int i = arc->current_file_in_block;

        while (arc->current_data_block < dir->num_of_blocks && i >= dir->block_end(arc->current_data_block)) {
            arc->current_data_block++;
        }

        char utf8name[MY_FILENAME_MAX * 4];
        dir->fullname(i, utf8name);
        char *cleanUtf8 = utf8name;
        while (*cleanUtf8 == '\\' || *cleanUtf8 == '/') cleanUtf8++;

        WCHAR utf16full[MY_FILENAME_MAX];
        utf8_to_utf16(cleanUtf8, utf16full);
        for (WCHAR *p = utf16full; *p; p++) {
            if (*p == L'/') *p = L'\\';
        }
        wcslcpy_safe(fileNameW, utf16full, maxFileNameW - 1);

        *outUnpSize = (uint64)dir->size[i];
        if (arc->current_data_block < dir->num_of_blocks && i == dir->block_start(arc->current_data_block)) {
            *outPackSize = (uint64)dir->data_block[arc->current_data_block].compsize;
        } else {
            *outPackSize = 0;
        }

        *outFileAttr = dir->isdir[i] ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
        *outFileTime = UnixTimeToDosTime(dir->time[i]);
        *outFileCRC = (int)dir->crc[i];
        arc->header_read = true;
        FA_JMP_POP(jf);
        return 0;
}

extern "C" int __stdcall ReadHeader(HANDLE hArcData, tHeaderData* HeaderData)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx < 1 || idx > MAX_ARCHIVES || !ArchiveList[idx].ArchiveOpen || !HeaderData)
        return E_EREAD;

    ArchiveRec *arc = &ArchiveList[idx];
    memset(HeaderData, 0, sizeof(tHeaderData));

    WCHAR fileNameW[1024] = {0};
    uint64 packSize = 0, unpSize = 0;
    int fileAttr = 0, fileTime = 0, fileCRC = 0;

    int res = AdvanceAndReadNextHeader(arc, fileNameW, 1024, &packSize, &unpSize, &fileAttr, &fileTime, &fileCRC);
    if (res != 0) return res;

    strlcpy_safe(HeaderData->ArcName, arc->ArchiveName, 259);
    WideCharToMultiByte(CP_ACP, 0, fileNameW, -1, HeaderData->FileName, 259, NULL, NULL);
    HeaderData->PackSize = (int)(packSize & 0xFFFFFFFF);
    HeaderData->UnpSize = (int)(unpSize & 0xFFFFFFFF);
    HeaderData->FileAttr = fileAttr;
    HeaderData->FileTime = fileTime;
    HeaderData->FileCRC = fileCRC;
    HeaderData->UnpVer = arc->UnpVer;
    return 0;
}

extern "C" int __stdcall ReadHeaderEx(HANDLE hArcData, tHeaderDataEx* HeaderDataEx)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx < 1 || idx > MAX_ARCHIVES || !ArchiveList[idx].ArchiveOpen || !HeaderDataEx)
        return E_EREAD;

    ArchiveRec *arc = &ArchiveList[idx];
    memset(HeaderDataEx, 0, sizeof(tHeaderDataEx));

    WCHAR fileNameW[1024] = {0};
    uint64 packSize = 0, unpSize = 0;
    int fileAttr = 0, fileTime = 0, fileCRC = 0;

    int res = AdvanceAndReadNextHeader(arc, fileNameW, 1024, &packSize, &unpSize, &fileAttr, &fileTime, &fileCRC);
    if (res != 0) return res;

    strlcpy_safe(HeaderDataEx->ArcName, arc->ArchiveName, 1023);
    WideCharToMultiByte(CP_ACP, 0, fileNameW, -1, HeaderDataEx->FileName, 1023, NULL, NULL);
    HeaderDataEx->PackSize = (DWORD)(packSize & 0xFFFFFFFF);
    HeaderDataEx->PackSizeHigh = (int)(packSize >> 32);
    HeaderDataEx->UnpSize = (DWORD)(unpSize & 0xFFFFFFFF);
    HeaderDataEx->UnpSizeHigh = (int)(unpSize >> 32);
    HeaderDataEx->FileAttr = fileAttr;
    HeaderDataEx->FileTime = fileTime;
    HeaderDataEx->FileCRC = fileCRC;
    HeaderDataEx->UnpVer = arc->UnpVer;
    return 0;
}

extern "C" int __stdcall ReadHeaderExW(HANDLE hArcData, tHeaderDataExW* HeaderDataExW)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx < 1 || idx > MAX_ARCHIVES || !ArchiveList[idx].ArchiveOpen || !HeaderDataExW)
        return E_EREAD;

    ArchiveRec *arc = &ArchiveList[idx];
    memset(HeaderDataExW, 0, sizeof(tHeaderDataExW));

    WCHAR fileNameW[1024] = {0};
    uint64 packSize = 0, unpSize = 0;
    int fileAttr = 0, fileTime = 0, fileCRC = 0;

    int res = AdvanceAndReadNextHeader(arc, fileNameW, 1024, &packSize, &unpSize, &fileAttr, &fileTime, &fileCRC);
    if (res != 0) return res;

    wcslcpy_safe(HeaderDataExW->ArcNameW, arc->ArchiveNameW, 1023);
    wcslcpy_safe(HeaderDataExW->FileNameW, fileNameW, 1023);
    HeaderDataExW->PackSize = (DWORD)(packSize & 0xFFFFFFFF);
    HeaderDataExW->PackSizeHigh = (int)(packSize >> 32);
    HeaderDataExW->UnpSize = (DWORD)(unpSize & 0xFFFFFFFF);
    HeaderDataExW->UnpSizeHigh = (int)(unpSize >> 32);
    HeaderDataExW->FileAttr = fileAttr;
    HeaderDataExW->FileTime = fileTime;
    HeaderDataExW->FileCRC = fileCRC;
    HeaderDataExW->UnpVer = arc->UnpVer;
    return 0;
}

/******************************************************************************
** WCX Exported Functions: ProcessFile / ProcessFileW                        **
******************************************************************************/
static int ProcessFileInternal(ArchiveRec *arc, int Operation, const WCHAR *DestPath, const WCHAR *DestName)
{
    if (!arc || !arc->ArchiveOpen || !arc->dirblock || !arc->header_read)
        return E_EREAD;

    if (Operation == PK_SKIP)
        return 0;

    if (Operation != PK_EXTRACT && Operation != PK_TEST)
        return E_NOT_SUPPORTED;

    DIRECTORY_BLOCK *dir = arc->dirblock;
    int curfile = arc->current_file_in_block;
    int datablock = arc->current_data_block;

    WCHAR fullDestW[MY_FILENAME_MAX] = {0};
    if (Operation == PK_EXTRACT) {
        if (!DestName || !DestName[0])
            return E_ECREATE;
        if (DestPath && DestPath[0]) {
            wcslcpy_safe(fullDestW, DestPath, MY_FILENAME_MAX - 2);
            size_t len = wcslen(fullDestW);
            if (len > 0 && fullDestW[len - 1] != L'\\' && fullDestW[len - 1] != L'/') {
                wcscat(fullDestW, L"\\");
            }
            wcsncat(fullDestW, DestName, MY_FILENAME_MAX - wcslen(fullDestW) - 1);
        } else {
            wcslcpy_safe(fullDestW, DestName, MY_FILENAME_MAX - 1);
        }
    }

    if (CallProcessDataProc(arc, (Operation == PK_EXTRACT) ? fullDestW : arc->ArchiveNameW, 0) == 0)
        return E_EABORTED;

    // Handle directories and 0-byte files immediately without solid decompression
    if (dir->isdir[curfile] || dir->size[curfile] == 0) {
        if (Operation == PK_EXTRACT) {
            if (dir->isdir[curfile]) {
                BuildPathTo(fullDestW);
                create_dir(fullDestW);
            } else {
                char utf8dest[MY_FILENAME_MAX * 4];
                utf16_to_utf8(fullDestW, utf8dest);
                MYFILE outfile;
                outfile.setname(utf8dest);
                if (outfile.exists())
                    outfile.remove_readonly_attrib();
                if (!outfile.tryOpen(WRITE_MODE))
                    return E_ECREATE;
                outfile.tryClose();
                outfile.SetFileDateTime(dir->time[curfile]);
            }
        }
        return 0;
    }

    // Non-empty file: check if our solid-block streaming worker can continue or must be started
    if (arc->worker) {
        if (arc->worker->state == SolidWorker::STATE_FINISHED ||
            arc->worker->ctrl_block_idx != arc->current_ctrl_block ||
            arc->worker->data_block_idx != datablock ||
            arc->worker->curfile > curfile) {
            StopSolidWorker(arc);
        }
    }

    bool newlyCreated = false;
    if (!arc->worker) {
        SolidWorker *w = new SolidWorker(arc, dir, arc->current_ctrl_block, datablock);
        BLOCK &data_block = dir->data_block[datablock];
        FaJmpFrame jf;
        FA_JMP_PUSH(jf);
        if (setjmp(jf.buf) != 0) {
            FA_JMP_POP(jf);
            int err = MapFreeArcError(jf.code ? jf.code : FREEARC_ERRCODE_GENERAL, false);
            /* A CHECK while opening the shared handle may leave a half-built
               MYFILE behind; drop it so the next block retries the open. */
            if (arc->infile && !arc->infile->isopen()) {
                delete arc->infile;
                arc->infile = NULL;
            }
            delete w;
            return err;
        }
        w->compressor_to_use = GenerateDecryptionForArchive(data_block.compressor, w->compressor_buf, arc);
        /* One handle per archive slot instead of one per solid block: the
           decoder is the sole user and re-seeks at every block start. */
        if (!arc->infile) {
            arc->infile = new (std::nothrow) MYFILE();
            if (!arc->infile) {
                FA_JMP_POP(jf);
                delete w;
                return E_NO_MEMORY;
            }
            arc->infile->setname(arc->ArchiveNameUtf8);
            if (!arc->infile->tryOpen(READ_MODE)) {
                delete arc->infile;
                arc->infile = NULL;
                FA_JMP_POP(jf);
                delete w;
                return E_EOPEN;
            }
        }
        arc->infile->seek(data_block.pos);
        w->bytes_left = data_block.compsize;
        FA_JMP_POP(jf);
        arc->worker = w;
        newlyCreated = true;
    }

    SolidWorker *w = arc->worker;
    w->file_err = 0;
    w->target_file = curfile;
    w->target_op = Operation;
    wcslcpy_safe(w->target_dest, fullDestW, MY_FILENAME_MAX - 1);

    if (newlyCreated) {
        w->thread.Create(solid_worker_thread, w);
    } else {
        w->mainToWorkerEvent.Signal();
    }

    // Ping-pong event loop between Total Commander thread and solid decompression thread.
    // PROGRESS now carries an accumulated byte count, and FILE_DONE / FINISHED
    // carry the final remainder, so the callback still sees every byte once.
    bool user_aborted = false;
    for (;;) {
        w->workerToMainEvent.Wait();
        if (w->state == SolidWorker::STATE_PROGRESS) {
            if (CallProcessDataProc(arc, NULL, w->progress_bytes) == 0)
                w->abort_requested = true;
            w->mainToWorkerEvent.Signal();
        } else if (w->state == SolidWorker::STATE_FILE_DONE) {
            if (w->progress_bytes > 0 && CallProcessDataProc(arc, NULL, w->progress_bytes) == 0) {
                w->abort_requested = true;
                user_aborted = true;
            }
            break;
        } else if (w->state == SolidWorker::STATE_FINISHED) {
            if (w->progress_bytes > 0)
                CallProcessDataProc(arc, NULL, w->progress_bytes);
            break;
        }
    }

    int err = w->file_err;
    if (user_aborted) {
        /* The output file was already closed by the time cancellation was
           noticed; undo it here, matching the worker-side cleanup done when
           an early PROGRESS handshake is aborted. */
        if (Operation == PK_EXTRACT && fullDestW[0])
            DeleteFileW(fullDestW);
        if (err == 0) err = E_EABORTED;
    }
    if (w->state == SolidWorker::STATE_FINISHED || err != 0) {
        StopSolidWorker(arc);
    }
    return err;
}

extern "C" int __stdcall ProcessFile(HANDLE hArcData, int Operation, char* DestPath, char* DestName)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx < 1 || idx > MAX_ARCHIVES || !ArchiveList[idx].ArchiveOpen)
        return E_EREAD;

    WCHAR destPathW[1024] = {0};
    WCHAR destNameW[1024] = {0};
    if (DestPath) MultiByteToWideChar(CP_ACP, 0, DestPath, -1, destPathW, 1023);
    if (DestName) MultiByteToWideChar(CP_ACP, 0, DestName, -1, destNameW, 1023);

    return ProcessFileInternal(&ArchiveList[idx], Operation,
                               DestPath ? destPathW : NULL,
                               DestName ? destNameW : NULL);
}

extern "C" int __stdcall ProcessFileW(HANDLE hArcData, int Operation, WCHAR* DestPath, WCHAR* DestName)
{
    int idx = (int)(INT_PTR)hArcData;
    if (idx < 1 || idx > MAX_ARCHIVES || !ArchiveList[idx].ArchiveOpen)
        return E_EREAD;

    return ProcessFileInternal(&ArchiveList[idx], Operation, DestPath, DestName);
}

/******************************************************************************
** WCX Callback Registration Functions                                       **
******************************************************************************/
extern "C" void __stdcall SetChangeVolProc(HANDLE hArcData, tChangeVolProc pChangeVolProc)
{
    int index = (int)(INT_PTR)hArcData;
    if (index < 1 || index > MAX_ARCHIVES) index = 0;
    ArchiveList[index].ChangeVolProc = pChangeVolProc;
}

extern "C" void __stdcall SetProcessDataProc(HANDLE hArcData, tProcessDataProc pProcessDataProc)
{
    int index = (int)(INT_PTR)hArcData;
    if (index < 1 || index > MAX_ARCHIVES) index = 0;
    ArchiveList[index].ProcessDataProc = pProcessDataProc;
}

extern "C" void __stdcall SetChangeVolProcW(HANDLE hArcData, tChangeVolProcW pChangeVolProcW)
{
    int index = (int)(INT_PTR)hArcData;
    if (index < 1 || index > MAX_ARCHIVES) index = 0;
    ArchiveList[index].ChangeVolProcW = pChangeVolProcW;
}

extern "C" void __stdcall SetProcessDataProcW(HANDLE hArcData, tProcessDataProcW pProcessDataProcW)
{
    int index = (int)(INT_PTR)hArcData;
    if (index < 1 || index > MAX_ARCHIVES) index = 0;
    ArchiveList[index].ProcessDataProcW = pProcessDataProcW;
}

/******************************************************************************
** WCX Archive Content Detection (CanYouHandleThisFile / W)                  **
******************************************************************************/
static BOOL CheckFreeArcByContent(const WCHAR *filenameW)
{
    if (!filenameW || !filenameW[0]) return FALSE;
    BOOL result = FALSE;
    char utf8name[MY_FILENAME_MAX * 4];
    MYFILE f;
    FaJmpFrame jf;
    FA_JMP_PUSH(jf);
    if (setjmp(jf.buf) != 0) {
        /* Not a FreeArc archive (or an unreadable footer).  MYFILE f was
           declared before the frame, so its destructor still runs and closes
           the handle when this function returns. */
        FA_JMP_POP(jf);
        return FALSE;
    }
    utf16_to_utf8(filenameW, utf8name);
    f.setname(utf8name);
    if (f.tryOpen(READ_MODE)) {
        FILESIZE fsize = f.size();
        if (fsize >= 8) {
            FILESIZE pos = FindFooterDescriptor(f);
            FOOTER_BLOCK_LOCAL_DESCRIPTOR arcFooter(f, pos);
            (void)arcFooter;
            result = TRUE;
        }
    }
    FA_JMP_POP(jf);
    return result;
}

extern "C" BOOL __stdcall CanYouHandleThisFile(char* filename)
{
    if (!filename || !filename[0]) return FALSE;
    WCHAR filenameW[1024] = {0};
    MultiByteToWideChar(CP_ACP, 0, filename, -1, filenameW, 1023);
    return CheckFreeArcByContent(filenameW);
}

extern "C" BOOL __stdcall CanYouHandleThisFileW(WCHAR* filename)
{
    return CheckFreeArcByContent(filename);
}

/******************************************************************************
** WCX Packing & Deleting via Arc.exe (when available)                       **
******************************************************************************/
static bool FindArcExe(WCHAR *outExe, size_t maxLen)
{
    char customPathA[MAX_PATH] = {0};
    GetPrivateProfileStringA("freearc", "ArcExe", "", customPathA, MAX_PATH, inifilename);
    if (customPathA[0]) {
        MultiByteToWideChar(CP_ACP, 0, customPathA, -1, outExe, (int)maxLen);
        if (file_exists(outExe)) return true;
    }

    if (g_hInst && GetModuleFileNameW(g_hInst, outExe, (DWORD)maxLen)) {
        WCHAR *slash = wcsrchr(outExe, L'\\');
        if (slash) {
            wcscpy(slash + 1, L"Arc.exe");
            if (file_exists(outExe)) return true;
            wcscpy(slash + 1, L"bin\\Arc.exe");
            if (file_exists(outExe)) return true;
        }
    }

    const WCHAR *candidates[] = {
        L"F:\\Software\\FreeArc\\bin\\Arc.exe",
        L"C:\\Program Files (x86)\\FreeArc\\bin\\Arc.exe",
        L"C:\\Program Files\\FreeArc\\bin\\Arc.exe",
        L"D:\\Program Files (x86)\\FreeArc\\bin\\Arc.exe",
        L"D:\\Program Files\\FreeArc\\bin\\Arc.exe"
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (file_exists((WCHAR*)candidates[i])) {
            wcslcpy_safe(outExe, candidates[i], (int)maxLen - 1);
            return true;
        }
    }

    if (SearchPathW(NULL, L"Arc.exe", NULL, (DWORD)maxLen, outExe, NULL) > 0) {
        return true;
    }
    return false;
}

/******************************************************************************
** Packing progress.                                                         **
**                                                                            **
** Total Commander advances its bar by the Size argument of ProcessDataProc:   **
** the sum of all Size values is compared against the byte total TC computed   **
** for the selected files.  The old RunArcCommandWithProgress only ever called  **
** it with Size=0, which repaints the dialog but never moves the bar - that    **
** is why packing showed no progress.                                          **
**                                                                            **
** Arc.exe writes "Compressing 6 files, 18,874,368 bytes." followed by         **
** "Processed  42%\b\b\b\b" about twice a second, even when stdout is a pipe.  **
** Both output handles are redirected into a pipe, the newest percentage is    **
** converted back into bytes and those bytes are handed to the callback.       **
******************************************************************************/

enum { ARC_OK = 0, ARC_FAILED = 1, ARC_LAUNCH = 2, ARC_ABORT = 3 };

struct ProgressTracker {
    ArchiveRec *arc;
    uint64 total;       /* bytes that count as 100% */
    uint64 reported;    /* bytes already handed to TC */
    uint64 pending;     /* bytes collected but not yet handed to TC */
    uint64 step;        /* 1% of total - the reporting quantum */
    DWORD tick;         /* last time the progress dialog was advanced */
    int percent;        /* newest percentage Arc.exe announced, in tenths */
    bool aborted;
};

/* Hands the collected byte count to Total Commander.  Returns true when TC
   asked to stop.  Size is an int, so large deltas are split into chunks. */
static bool FlushPackProgress(ProgressTracker *pt)
{
    if (!pt || !pt->arc) return false;
    uint64 delta = pt->pending;
    if (delta == 0) return false;
    pt->pending = 0;
    pt->tick = GetTickCount();

    bool aborted = false;
    while (delta > 0) {
        int chunk = (int)(delta > (uint64)0x10000000 ? (uint64)0x10000000 : delta);
        if (CallProcessDataProc(pt->arc, NULL, chunk) == 0) aborted = true;
        delta -= chunk;
    }
    if (aborted) pt->aborted = true;
    return aborted;
}

/* Throttle: TC repaints the whole dialog on every callback, so bytes are
   released once per percent of the total (or every 300 ms for tiny jobs). */
static void TrackPackProgress(ProgressTracker *pt, uint64 done)
{
    if (!pt || !pt->arc) return;
    if (done > pt->total) done = pt->total;
    if (done <= pt->reported) return;

    uint64 step = pt->step ? pt->step : 1;
    pt->pending += done - pt->reported;
    pt->reported = done;
    if (pt->pending < step && GetTickCount() - pt->tick < 300) return;
    FlushPackProgress(pt);
}

/* Arc.exe's indicator is " 42%" below 1000 MB and " 12.3%" above that; every
   value is followed by backspaces.  The final report's "Ratio 59.82%" is
   followed by spaces, so it is ignored.  Returns tenths of a percent, or -1
   when the buffer holds no percentage token. */
static int ParseArcPercentTenths(const char *buf, int len)
{
    int found = -1;
    for (int i = 1; i + 1 < len; i++) {
        if (buf[i] != '%' || buf[i + 1] != '\b') continue;

        int start = i;
        while (start > 0 && ((buf[start-1] >= '0' && buf[start-1] <= '9') ||
                             buf[start-1] == '.'))
            start--;
        if (start == 0) continue;                 /* token cut off at buffer edge */

        char prev = buf[start-1];
        if (prev != ' ' && prev != '\b' && prev != '\r' && prev != '\n') continue;

        int whole = 0, wdigits = 0, frac = 0, k = start;
        for (; k < i && buf[k] >= '0' && buf[k] <= '9' && wdigits < 3; k++, wdigits++)
            whole = whole * 10 + (buf[k] - '0');
        if (k < i && buf[k] == '.' && k + 1 < i && buf[k+1] >= '0' && buf[k+1] <= '9')
            frac = buf[k+1] - '0';
        if (wdigits == 0) continue;

        int tenths = whole * 10 + frac;
        if (tenths <= 1000) found = tenths;
    }
    return found;
}

/* "Compressing 6 files, 18,874,368 bytes." is the total TC compares against.
   The closing "Compressed 6 files, 18,874,368 => ... bytes" is skipped by
   requiring "bytes" immediately after the number. */
static uint64 ParseArcTotal(const char *buf, int len)
{
    for (int i = len - 7; i >= 0; i--) {
        if (memcmp(buf + i, "files,", 6) != 0) continue;
        int j = i + 6;
        while (j < len && buf[j] == ' ') j++;
        uint64 value = 0;
        int digits = 0;
        while (j < len && ((buf[j] >= '0' && buf[j] <= '9') || buf[j] == ',')) {
            if (buf[j] != ',') {
                if (value < ((uint64)1 << 50)) value = value * 10 + (buf[j] - '0');
                digits++;
            }
            j++;
        }
        while (j < len && buf[j] == ' ') j++;
        if (digits > 0 && j + 5 <= len && memcmp(buf + j, "bytes", 5) == 0)
            return value;
    }
    return 0;
}

static void ScanPackOutput(ProgressTracker *pt, const char *buf, int len)
{
    if (!pt) return;
    if (pt->total == 0) {
        uint64 total = ParseArcTotal(buf, len);
        if (total > 0) {
            pt->total = total;
            pt->step = total / 100;
            if (pt->step == 0) pt->step = 1;
        }
    }
    int percent = ParseArcPercentTenths(buf, len);
    if (percent > pt->percent) pt->percent = percent;
}

/* Runs Arc.exe with stdout/stderr redirected into a 64 KB pipe, stdin from
   NUL.  The pipe is drained on every wake-up so a chatty Arc.exe can never
   block on a full pipe.  CREATE_NO_WINDOW keeps the console hidden. */
static int RunArcWithPipe(WCHAR *cmdLine, const WCHAR *workDir, ProgressTracker *pt)
{
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 64 * 1024)) return ARC_LAUNCH;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (hNul != INVALID_HANDLE_VALUE) ? hNul : NULL;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    BOOL started = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                                  (workDir && workDir[0]) ? workDir : NULL, &si, &pi);
    CloseHandle(hWrite);
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
    if (!started) {
        CloseHandle(hRead);
        return ARC_LAUNCH;
    }

    char tail[2048];
    int tailLen = 0;
    int result = ARC_OK;
    int tick = 0;

    for (;;) {
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 20);

        for (;;) {
            DWORD avail = 0;
            if (!PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) || avail == 0) break;
            char buf[1024];
            DWORD got = 0;
            DWORD want = avail < (DWORD)sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(hRead, buf, want, &got, NULL) || got == 0) break;
            if (got > sizeof(buf)) got = (DWORD)sizeof(buf);

            if ((int)got >= (int)sizeof(tail)) {
                memcpy(tail, buf + got - sizeof(tail), sizeof(tail));
                tailLen = (int)sizeof(tail);
            } else {
                int excess = tailLen + (int)got - (int)sizeof(tail);
                if (excess > 0) {
                    memmove(tail, tail + excess, tailLen - excess);
                    tailLen -= excess;
                }
                memcpy(tail + tailLen, buf, got);
                tailLen += (int)got;
            }
        }

        if (pt) ScanPackOutput(pt, tail, tailLen);
        if (waitResult == WAIT_OBJECT_0) break;

        tick++;
        if (pt && pt->total > 0 && pt->percent > 0)
            TrackPackProgress(pt, pt->total * (uint64)pt->percent / 1000);

        if (pt && pt->aborted) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            result = ARC_ABORT;
            break;
        }
        /* ~100 ms cancel poll; Size=0 only repaints the dialog. */
        if ((tick % 5) == 0 && pt &&
            CallProcessDataProc(pt->arc, NULL, 0) == 0) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            result = ARC_ABORT;
            break;
        }
    }

    if (result == ARC_OK) {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        if (exitCode != 0) result = ARC_FAILED;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);
    return result;
}

/* TC's own sum of the selected files is the number its bar is measured
   against; Arc.exe prints the same value, used as a fallback for wildcards
   and directory entries where the sum cannot be computed here. */
static uint64 SumAddListBytes(const WCHAR *addList, const WCHAR *srcPath)
{
    uint64 total = 0;
    for (const WCHAR *p = addList; p && *p; p += wcslen(p) + 1) {
        if (wcschr(p, L'*') || wcschr(p, L'?')) return 0;

        WCHAR full[MAX_PATH * 2] = {0};
        if (p[0] == L'\\' || (p[0] && p[1] == L':')) {
            wcslcpy_safe(full, p, MAX_PATH * 2 - 1);
        } else if (srcPath && srcPath[0]) {
            _snwprintf(full, MAX_PATH * 2 - 1, L"%s\\%s", srcPath, p);
            full[MAX_PATH * 2 - 1] = 0;
        } else {
            wcslcpy_safe(full, p, MAX_PATH * 2 - 1);
        }

        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExW(full, GetFileExInfoStandard, &fad)) continue;
        if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return 0;
        total += ((uint64)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    }
    return total;
}

static int RunArcForPacking(WCHAR *cmdLine, const WCHAR *workDir, uint64 totalBytes)
{
    ProgressTracker pt;
    memset(&pt, 0, sizeof(pt));
    pt.arc = &ArchiveList[0];        /* TC registers the packer callback here */
    pt.total = totalBytes;
    pt.step = totalBytes / 100;
    if (pt.step == 0) pt.step = 1;
    pt.tick = GetTickCount();

    int res = RunArcWithPipe(cmdLine, workDir, &pt);

    /* The closing 100% can be printed just before the process exits, and
       throttled bytes can still be pending - complete the bar here. */
    if (res == ARC_OK && pt.total > 0)
        TrackPackProgress(&pt, pt.total);
    if (res == ARC_OK) {
        FlushPackProgress(&pt);
        if (pt.aborted) res = ARC_ABORT;
    }

    switch (res) {
        case ARC_OK:     return 0;
        case ARC_ABORT:  return E_EABORTED;
        case ARC_LAUNCH: return E_ECREATE;
        default:         return E_EWRITE;
    }
}

extern "C" int __stdcall PackFilesW(WCHAR *PackedFile, WCHAR *SubPath, WCHAR *SrcPath, WCHAR *AddList, int Flags)
{
    if (!AddList || !AddList[0]) return E_NO_FILES;
    if (!PackedFile || !PackedFile[0]) return E_ECREATE;

    WCHAR arcExe[MAX_PATH] = {0};
    if (!FindArcExe(arcExe, MAX_PATH))
        return E_NOT_SUPPORTED;

    WCHAR tempDir[MAX_PATH] = {0}, listFile[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tempDir);
    GetTempFileNameW(tempDir, L"fal", 0, listFile);

    FILE *fp = _wfopen(listFile, L"wb");
    if (!fp) return E_ECREATE;

    for (WCHAR *p = AddList; *p; p += wcslen(p) + 1) {
        char utf8line[MY_FILENAME_MAX * 4];
        utf16_to_utf8(p, utf8line);
        size_t len = strlen(utf8line);
        if (len > 0 && (utf8line[len - 1] == '\\' || utf8line[len - 1] == '/'))
            utf8line[len - 1] = 0;
        fprintf(fp, "%s\r\n", utf8line);
    }
    fclose(fp);

    int level = GetPrivateProfileIntA("bzip2dll", "CompressionRate", 4, inifilename);
    if (level < 1) level = 1;
    if (level > 9) level = 9;

    const WCHAR *cmd = (Flags & PK_PACK_MOVE_FILES) ? L"m" : L"a";
    const WCHAR *epFlag = (Flags & PK_PACK_SAVE_PATHS) ? L"" : L" -ep";

    WCHAR subPathArg[1024] = {0};
    if (SubPath && SubPath[0]) {
        _snwprintf(subPathArg, 1023, L" \"-ap%s\"", SubPath);
    }

    WCHAR cmdLine[8192] = {0};
    _snwprintf(cmdLine, 8191, L"\"%s\" %s -y --noarcext -sclUTF8 -m%d%s%s -- \"%s\" @\"%s\"",
               arcExe, cmd, level, epFlag, subPathArg, PackedFile, listFile);

    /* Byte total TC's progress bar is measured against.  Wildcards and
       directory entries make it unknowable here (0), in which case the value
       Arc.exe prints in "Compressing N files, X bytes." is used instead. */
    uint64 totalBytes = SumAddListBytes(AddList, SrcPath);
    int res = RunArcForPacking(cmdLine, SrcPath, totalBytes);
    DeleteFileW(listFile);
    return res;
}

extern "C" int __stdcall PackFiles(char *PackedFile, char *SubPath, char *SrcPath, char *AddList, int Flags)
{
    if (!AddList || !AddList[0]) return E_NO_FILES;
    WCHAR packedW[1024] = {0}, subPathW[1024] = {0}, srcPathW[1024] = {0};
    if (PackedFile) MultiByteToWideChar(CP_ACP, 0, PackedFile, -1, packedW, 1023);
    if (SubPath) MultiByteToWideChar(CP_ACP, 0, SubPath, -1, subPathW, 1023);
    if (SrcPath) MultiByteToWideChar(CP_ACP, 0, SrcPath, -1, srcPathW, 1023);

    size_t totalChars = 0;
    for (char *p = AddList; *p; p += strlen(p) + 1) {
        totalChars += strlen(p) + 1;
    }
    WCHAR *addListW = (WCHAR*)calloc(totalChars + 2, sizeof(WCHAR));
    if (!addListW) return E_NO_MEMORY;

    WCHAR *dst = addListW;
    for (char *p = AddList; *p; p += strlen(p) + 1) {
        int written = MultiByteToWideChar(CP_ACP, 0, p, -1, dst, (int)(totalChars + 1));
        dst += written;
    }
    *dst = 0;

    int res = PackFilesW(packedW, SubPath ? subPathW : NULL, SrcPath ? srcPathW : NULL, addListW, Flags);
    free(addListW);
    return res;
}

extern "C" int __stdcall DeleteFilesW(WCHAR *PackedFile, WCHAR *DeleteList)
{
    if (!DeleteList || !DeleteList[0]) return E_BAD_DATA;
    if (!PackedFile || !PackedFile[0]) return E_BAD_DATA;

    WCHAR arcExe[MAX_PATH] = {0};
    if (!FindArcExe(arcExe, MAX_PATH))
        return E_NOT_SUPPORTED;

    WCHAR tempDir[MAX_PATH] = {0}, listFile[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tempDir);
    GetTempFileNameW(tempDir, L"fad", 0, listFile);

    FILE *fp = _wfopen(listFile, L"wb");
    if (!fp) return E_ECREATE;

    for (WCHAR *p = DeleteList; *p; p += wcslen(p) + 1) {
        char utf8line[MY_FILENAME_MAX * 4];
        utf16_to_utf8(p, utf8line);
        size_t len = strlen(utf8line);
        if (len >= 4 && strcmp(utf8line + len - 4, "\\*.*") == 0) {
            utf8line[len - 4] = 0;
        }
        fprintf(fp, "%s\r\n", utf8line);
    }
    fclose(fp);

    WCHAR cmdLine[8192] = {0};
    _snwprintf(cmdLine, 8191, L"\"%s\" d -y --noarcext -sclUTF8 -- \"%s\" @\"%s\"",
               arcExe, PackedFile, listFile);

    int res = RunArcForPacking(cmdLine, NULL, 0);
    DeleteFileW(listFile);
    return res;
}

extern "C" int __stdcall DeleteFiles(char *PackedFile, char *DeleteList)
{
    if (!DeleteList || !DeleteList[0]) return E_BAD_DATA;
    WCHAR packedW[1024] = {0};
    if (PackedFile) MultiByteToWideChar(CP_ACP, 0, PackedFile, -1, packedW, 1023);

    size_t totalChars = 0;
    for (char *p = DeleteList; *p; p += strlen(p) + 1) {
        totalChars += strlen(p) + 1;
    }
    WCHAR *delListW = (WCHAR*)calloc(totalChars + 2, sizeof(WCHAR));
    if (!delListW) return E_NO_MEMORY;

    WCHAR *dst = delListW;
    for (char *p = DeleteList; *p; p += strlen(p) + 1) {
        int written = MultiByteToWideChar(CP_ACP, 0, p, -1, dst, (int)(totalChars + 1));
        dst += written;
    }
    *dst = 0;

    int res = DeleteFilesW(packedW, delListW);
    free(delListW);
    return res;
}

/******************************************************************************
** WCX Capabilities & Configuration Dialog                                   **
******************************************************************************/
extern "C" int __stdcall GetPackerCaps()
{
    return PK_CAPS_NEW | PK_CAPS_MODIFY | PK_CAPS_MULTIPLE | PK_CAPS_DELETE | PK_CAPS_OPTIONS | PK_CAPS_BY_CONTENT | PK_CAPS_SEARCHTEXT;
}

static HANDLE hBrush = NULL;

static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int i;
    char num[4];
    char ch;
    num[1] = '\0';
    switch (uMsg) {
        case WM_INITDIALOG:
            SetWindowTextA(hwndDlg, "FreeArc WCX Settings");
            SetDlgItemTextA(hwndDlg, 100, "FreeArc WCX Plugin for Total Commander\nUnarc engine (c) 2005-2014 Bulat Ziganshin\nWCX interface based on Christian Ghisler's SDK");
            for (ch = '1'; ch <= '9'; ch++) {
                num[0] = ch;
                SendDlgItemMessageA(hwndDlg, 103, CB_ADDSTRING, 0, (LPARAM)&num);
            }
            i = GetPrivateProfileIntA("bzip2dll", "CompressionRate", 4, inifilename);
            if (i < 1) i = 1;
            if (i > 9) i = 9;
            SendDlgItemMessageA(hwndDlg, 103, CB_SETCURSEL, i - 1, 0);
            hBrush = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
            return TRUE;
        case WM_CTLCOLORDLG:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
            SetBkColor((HDC)wParam, GetSysColor(COLOR_BTNFACE));
            SetTextColor((HDC)wParam, GetSysColor(COLOR_BTNTEXT));
            return (INT_PTR)hBrush;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 104: /* OK */
                    num[0] = (char)('1' + SendDlgItemMessageA(hwndDlg, 103, CB_GETCURSEL, 0, 0));
                    WritePrivateProfileStringA("bzip2dll", "CompressionRate", num, inifilename);
                    if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }
                    EndDialog(hwndDlg, 1);
                    return TRUE;
                case 2: /* Cancel */
                    if (hBrush) { DeleteObject(hBrush); hBrush = NULL; }
                    EndDialog(hwndDlg, 0);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

extern "C" void __stdcall ConfigurePacker(HWND ParentHandle, HINSTANCE hinstance)
{
    DialogBoxA(hinstance ? hinstance : g_hInst, "CONFDLG", ParentHandle, (DLGPROC)DialogProc);
}

/* Mempack stubs (StartMemPack / PackToMem / DoneMemPack) were removed:
   GetPackerCaps() never advertised PK_CAPS_MEMPACK and none of them was in
   the .def export table, so Total Commander could never call them. */

extern "C" int __stdcall GetBackgroundFlags(void)
{
    return BACKGROUND_UNPACK | BACKGROUND_PACK;
}

extern "C" void __stdcall PackSetDefaultParams(PackDefaultParamStruct* dps)
{
    if (dps) {
        strlcpy_safe(inifilename, dps->DefaultIniName, MAX_PATH - 1);
    }
}
