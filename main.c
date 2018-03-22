#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdbool.h>
#include <tchar.h>
#include <stdint.h>
#include <strsafe.h>
#include <time.h>
#include "TasksQueue.h"
#include "list.h"
#include "scanuser.h"
#include <fltUser.h>

#pragma comment (lib, "fltlib.lib")

#define CRC_INFECTED_FILE   612700139
#define DEFAULT_SPACING     50
#define MAX_THREADS         64
#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2

typedef signed long SIGNED_DWORD;
typedef unsigned long long QWORD;

INT gSpacingSize = DEFAULT_SPACING;
INT gGoodFiles;
INT gBadFiles;
INT gPe64File;
INT gStartingArgument;
UINT gMaxThreads;
UINT gThreadsArray[MAX_THREADS];
CRITICAL_SECTION gCritSection;
GLOBALHANDLE gEvents[2];
LIST_ENTRY gHeadList;

typedef struct _SCANNER_THREAD_CONTEXT {

    HANDLE Port;
    HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;

DWORD WINAPI
MultithreadScanner(
    __in        LPVOID                    lpParam
);

VOID
ErrorHandler(
    __in        LPTSTR                    lpszFunction
);

BOOL
FileExists(
    __in_z      LPCTSTR                   FilePath
);

VOID CheckIfFileExists(
    __in        LPCTSTR                   FilePath
);

VOID
FileCreate(
    __out       PHANDLE                   hFile,
    __in        LPCSTR                    FilePath
);

VOID
FileRead(
    __in        HANDLE                    hFile,
    __out       PDWORD                    FileSize,
    __out       LPVOID*                   FileBuffer,
    __out       PDWORD                    BytesRead,
    __out       PINT                      Error
);

VOID
LogDosHeader(
    __in        FILE*                     Out,
    __in        PIMAGE_DOS_HEADER         Pdh
);

VOID
GetComputerArchitecture(
    __in        WORD                      Machine,
    __in        FILE*                     Out
);

VOID
LogNtHeader(
    __in        FILE*                     Out,
    __in        PIMAGE_NT_HEADERS         Pnh,
    __in        IMAGE_FILE_HEADER         Ifh
);

VOID
LogTextInFile(
    __in        FILE*                     Out,
    __in        PCHAR                     String
);

VOID
LogOptionalHeader(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PINT                      Error
);

VOID
LogDirectories(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PINT                      Error
);

VOID
LogDirectories(
    __in        FILE*                     out,
    __in        IMAGE_OPTIONAL_HEADER     ioh,
    __out       PINT                      error
);

VOID
LogSectionHeader(
    __in        FILE*                     Out,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        PIMAGE_SECTION_HEADER     Psh,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
);

VOID
LogImports(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PIMAGE_IMPORT_DESCRIPTOR  Pid,
    __in        PIMAGE_DOS_HEADER         Pdh,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
);

VOID
LogExports(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PIMAGE_EXPORT_DIRECTORY   Ped,
    __in        PIMAGE_DOS_HEADER         Pdh,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
);

SIGNED_DWORD
RVA2FA(
    __in        CONST PIMAGE_DOS_HEADER   DosHeader,
    __in        CONST WORD                NumberOfSections,
    __in        CONST DWORD               RVA,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize
);

VOID
CreatePath(
    __inout_z   PTCHAR                    FilePath,
    __in_z      LPCTSTR                   Argv,
    __in_z      LPCTSTR                   Name
);

VOID
SearchForAdson(
    __in        FILE*                     Out,
    __in        CONST PIMAGE_DOS_HEADER   DosHeader,
    __in        CONST IMAGE_FILE_HEADER   Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       BOOL*                     Virused
);

VOID
LogDword(
    __in        FILE*                     Out,
    __in        DWORD                     Number32Bits
);

BOOL
CheckIfNumber(
    __in        PTCHAR                    WorkerThreads
);

VOID
GetWorkerThreads(
    __in        PTCHAR                    FirstArg
);

VOID
CreategEventsWithManualReset(
    VOID
);

VOID
InterlockedIncrementInt(
    __out       PINT                      number
);

VOID
InterlockedInsertElementInTailList(
    __inout     PTCHAR                    FilePath,
    __in        PTCHAR                    newARG,
    __in        WIN32_FIND_DATA           FindFileData,
    __inout     PPROGRAM_ITEM             pProgramItem
);

VOID
LogThreadsUsageOnConsole(
    VOID
);

INT
_tmain(
    __in        INT                       argc,
    __in        PTCHAR                    argv[]
)
{
    clock_t begin = clock();
    if (argc < 2)
    {
        printf("No argument given! Please give arguments!\n");
        return;
    }

    TCHAR               newARG[200];
    WIN32_FIND_DATA     FindFileData;
    HANDLE              hFile;
    TCHAR               FilePath[100];
    PPROGRAM_ITEM       pProgramItem;
    PDWORD              dwThreadIdArray;
    SCANNER_THREAD_CONTEXT context;
    PHANDLE             hTreadArray;
    PSCANNER_MESSAGE msg;

    HRESULT hr;
    //PSCANNER_MESSAGE msg = NULL;
    // DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
    HANDLE port, completion;

    GetWorkerThreads(argv[1]);
    gMaxThreads = min(gMaxThreads, 64);

    _tcscpy(newARG, argv[gStartingArgument]);
    for (INT i = gStartingArgument + 1; i < argc; i++)
    {
        _tcscat(newARG, " ");
        _tcscat(newARG, argv[i]);
    }

    //
    //  Open a commuication channel to the filter
    //

    printf("Scanner: Connecting to the filter ...\n");

    hr = FilterConnectCommunicationPort(ScannerPortName,
        0,
        NULL,
        0,
        NULL,
        &port);

    if (IS_ERROR(hr)) {

        printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
        return 2;
    }

    completion = CreateIoCompletionPort(port,
        NULL,
        0,
        gMaxThreads);


    if (completion == NULL) {

        printf("ERROR: Creating completion port: %d\n", GetLastError());
        CloseHandle(port);
        return;
    }



    printf("Scanner: Port = 0x%p Completion = 0x%p\n", port, completion);

    context.Port = port;
    context.Completion = completion;

    InitializeListHead(&gHeadList);
    InitializeCriticalSection(&gCritSection);
    CreategEventsWithManualReset();

    dwThreadIdArray = (PDWORD)malloc(sizeof(DWORD) * gMaxThreads);
    hTreadArray = (PHANDLE)malloc(sizeof(HANDLE) * gMaxThreads);
    if (dwThreadIdArray == NULL || hTreadArray == NULL)
    {
        printf("Allocation failed!\n");
        return;
    }

    for (int i = 0; (UINT)i < gMaxThreads; i++)
    {
        hTreadArray[i] = CreateThread(
            NULL,												// default security attributes
            0,													// use default stack size
            MultithreadScanner,									// thread function name
                                                                //  (int*)i,											// argument to thread function ( current thread id )
            &context,
            0,													// use default creation flags
            &dwThreadIdArray[i]);								// returns the thread identifier

                                                                // Check the return value for success.
                                                                // If CreateThread fails, terminate execution.
                                                                // This will automatically clean up threads and memory
        if (hTreadArray[i] == NULL)
        {
            ErrorHandler(TEXT("CreateThread"));
            hr = GetLastError();
            ExitProcess(2);
        }

        msg = malloc(sizeof(SCANNER_MESSAGE));

        if (msg == NULL) {

            hr = ERROR_NOT_ENOUGH_MEMORY;
            goto main_cleanup;
        }
        memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

        //
        //  Request messages from the filter driver.
        //

        hr = FilterGetMessage(port,
            &msg->MessageHeader,
            FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
            &msg->Ovlp);

        if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
        {
            free(msg);
            goto main_cleanup;
        }
    }

    hFile = FindFirstFile(newARG, &FindFileData);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Invalid file handle. Error is %u.\n", GetLastError());
        return;
    }

    pProgramItem = (PPROGRAM_ITEM)_aligned_malloc(sizeof(PROGRAM_ITEM), MEMORY_ALLOCATION_ALIGNMENT);
    if (pProgramItem == NULL)
    {
        printf("Memory allocation failed.\n");
        return;
    }
    InterlockedInsertElementInTailList(FilePath, newARG, FindFileData, pProgramItem);
    while (FindNextFile(hFile, &FindFileData))
    {
        pProgramItem = (PPROGRAM_ITEM)_aligned_malloc(sizeof(PROGRAM_ITEM), MEMORY_ALLOCATION_ALIGNMENT);
        if (pProgramItem == NULL)
        {
            printf("Memory allocation failed.\n");
            return;
        }
        InterlockedInsertElementInTailList(FilePath, newARG, FindFileData, pProgramItem);
    }

    // Set the event for no more files
    SetEvent(gEvents[1]);
    WaitForMultipleObjects(gMaxThreads, hTreadArray, TRUE, INFINITE);

    // Close all threads handles and free memory allocations.
    DWORD threadExitCode;
    for (UINT i = 0; i < gMaxThreads; i++)
    {
        // GetExitCodeThread returns nonzero if succeeds
        BOOL errorCode = GetExitCodeThread(hTreadArray[i], &threadExitCode);
        if (errorCode)
        {
            CloseHandle(hTreadArray[i]);
        }
        else
        {
            printf("ERROR! Thread %d i couldn't be closed!", i);
        }
    }

    printf("Found %d good files.\n", gGoodFiles);
    printf("Found %d bad files, from which %d are PE64 files.\n", gBadFiles, gPe64File);

    free(dwThreadIdArray);
    free(hTreadArray);

    // LogThreadsUsageOnConsole();

    clock_t end = clock();
    DOUBLE time_spent = (DOUBLE)(end - begin) / CLOCKS_PER_SEC;
    printf("TIME SPENT: %f", time_spent);

main_cleanup:

    printf("Scanner processed the file. Result = 0x%08x\n", hr);
    CloseHandle(port);
    CloseHandle(completion);
    return hr;
}

BOOL
FileExists(
    __in_z      LPCTSTR                   FilePath
)
{
    // If the user didn't given any path return NULL
    if (FilePath == NULL)
        return false;

    WIN32_FILE_ATTRIBUTE_DATA fileAttribute;

    // LPVOID - VOID* ( VOID pointer )
    // lpFileInformation ( in our case fileAttribute ) must be a WIN32_FILE_ATTRIBUTE_DATA!
    if (GetFileAttributesEx(FilePath, GetFileExInfoStandard, &fileAttribute) == 0)
        return FALSE;
    return TRUE;
}

VOID CheckIfFileExists(
    __in        LPCTSTR                   FilePath
)
{
    if (!FileExists(FilePath)) {
        //printf("File %s doesn't exist.\n", FilePath);
        //exit(1);
    }
    //printf("Step 1 : File %s exists\n", fileName);
}

VOID
FileCreate(
    __out       PHANDLE                   hFile,
    __in        LPCSTR                    FilePath
)
{
    *hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*hFile == INVALID_HANDLE_VALUE)
    {
        //printf("CreateFile error. Extended Error Information %d.\n", GetLastError());
        return;
    }
}

// ReadFile cannot crash ( the handle was already verified before this function is appealed )
VOID
FileRead(
    __in        HANDLE                    hFile,
    __out       PDWORD                    FileSize,
    __out       LPVOID                    *FileBuffer,
    __out       PDWORD                    BytesRead,
    __out       PINT                      Error
)
{
    *FileSize = GetFileSize(hFile, NULL);
    *FileBuffer = VirtualAlloc(NULL, *FileSize, MEM_COMMIT, PAGE_READWRITE);
    if (ReadFile(hFile, *FileBuffer, *FileSize, &*BytesRead, NULL) == 0)
    {
        //printf("Couldn't read the file %s. Extended Error Information %d.\n", fileName, GetLastError());
        // if we managed to allocate memory, we need to freed it because the read was unsuccessfull
        if (*FileBuffer)
            VirtualFree(*FileBuffer, *FileSize, MEM_DECOMMIT);
        *Error = 1;
    }
}

VOID
GetComputerArchitecture(
    __in        WORD                      Machine,
    __in        FILE*                     Out
)
{
    switch (Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        fprintf(Out, "x86\n");
        break;
    case IMAGE_FILE_MACHINE_IA64:
        fprintf(Out, "Intel Itanium\n");
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        fprintf(Out, "x64\n");
        break;
    }
}

VOID
LogDosHeader(
    __in        FILE*                     Out,
    __in        PIMAGE_DOS_HEADER         Pdh
)
{
    //printf("DOS HEADER IN!\n");
    fprintf(Out, "***************************** Dos Header *****************************\n");

    LogTextInFile(Out, "Magic number:");
    fprintf(Out, "%#x (%s)\n", Pdh->e_magic, "MZ");

    LogTextInFile(Out, "Bytes on last page of file:");
    fprintf(Out, "%d\n", Pdh->e_cblp);

    LogTextInFile(Out, "Pages in file:");
    fprintf(Out, "%#x\n", Pdh->e_cp);

    LogTextInFile(Out, "Relocations:");
    fprintf(Out, "%#x\n", Pdh->e_crlc);

    LogTextInFile(Out, "Size of header in paragraphs:");
    fprintf(Out, "%#x\n", Pdh->e_cparhdr);

    LogTextInFile(Out, "Minimum extra paragraphs needed:");
    fprintf(Out, "%#x\n", Pdh->e_minalloc);

    LogTextInFile(Out, "Maximum extra paragraphs needed:");
    fprintf(Out, "%#x\n", Pdh->e_maxalloc);

    LogTextInFile(Out, "Initial (relative) SS value:");
    fprintf(Out, "%#x\n", Pdh->e_ss);

    LogTextInFile(Out, "Initial SP value:");
    fprintf(Out, "%#x\n", Pdh->e_sp);

    LogTextInFile(Out, "Checksum:");
    fprintf(Out, "%#x\n", Pdh->e_csum);

    LogTextInFile(Out, "Initial IP value:");
    fprintf(Out, "%#x\n", Pdh->e_ip);

    LogTextInFile(Out, "Initial (relative) CS value:");
    fprintf(Out, "%#x\n", Pdh->e_cs);

    LogTextInFile(Out, "File address of relocation table:");
    fprintf(Out, "%#x\n", Pdh->e_lfarlc);

    LogTextInFile(Out, "Overlay number:");
    fprintf(Out, "%#x\n", Pdh->e_ovno);

    LogTextInFile(Out, "OEM identifier:");
    fprintf(Out, "%#x\n", Pdh->e_oemid);

    LogTextInFile(Out, "OEM information:");
    fprintf(Out, "%#x\n", Pdh->e_oeminfo);

    LogTextInFile(Out, "File address of new exe header:");
    fprintf(Out, "%#lx\n\n", Pdh->e_lfanew);

    //printf("DOS HEADER OUT!\n");
}

VOID
LogNtHeader(
    __in        FILE*                     Out,
    __in        PIMAGE_NT_HEADERS         Pnh,
    __in        IMAGE_FILE_HEADER         Ifh
)
{
    //printf("NT IN!\n");
    fprintf(Out, "***************************** NT Header *****************************\n");

    LogTextInFile(Out, "Signature:");
    fprintf(Out, "%#lx (%s)\n", Pnh->Signature, "(Portable Executable)");

    LogTextInFile(Out, "Machine:");
    GetComputerArchitecture(Ifh.Machine, Out);

    LogTextInFile(Out, "Number of sections:");
    fprintf(Out, "%#x\n", Ifh.NumberOfSections);

    LogTextInFile(Out, "Timestamp:");
    fprintf(Out, "%lu\n", Ifh.TimeDateStamp);

    LogTextInFile(Out, "Pointer to symbol table:");
    fprintf(Out, "%#lx\n", Ifh.PointerToSymbolTable);

    LogTextInFile(Out, "Number of symbols");
    fprintf(Out, "%#lx\n", Ifh.NumberOfSymbols);

    LogTextInFile(Out, "Size of optional header:");
    fprintf(Out, "%#x | %lu \n", Ifh.SizeOfOptionalHeader, Ifh.SizeOfOptionalHeader);

    LogTextInFile(Out, "Characteristics:");
    fprintf(Out, "%#lx\n\n", Ifh.Characteristics);

    //printf("NT OUT!\n");
}

VOID
LogOptionalHeader(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PINT                      Error
)
{
    //printf("Optional header IN!\n");
    fprintf(Out, "***************************** Optional Header *****************************\n");

    LogTextInFile(Out, "Magic:");
    fprintf(Out, "%#x  (%s)\n", Ioh.Magic, Ioh.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "PE64" : "PE32");

    if (Ioh.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        gPe64File++;
        *Error = 1;
        return;
    }

    LogTextInFile(Out, "Linker Version:");
    fprintf(Out, "%d.%d\n", Ioh.MajorLinkerVersion, Ioh.MinorLinkerVersion);

    LogTextInFile(Out, "Size of code:");
    fprintf(Out, "%#lu\n", Ioh.SizeOfCode);

    LogTextInFile(Out, "Size of initialized data:");
    fprintf(Out, "%lu\n", Ioh.SizeOfInitializedData);

    LogTextInFile(Out, "Size of uninitialized:");
    fprintf(Out, "%lu\n", Ioh.SizeOfUninitializedData);

    LogTextInFile(Out, "Adress of entry point :");
    fprintf(Out, "%#x\n", Ioh.AddressOfEntryPoint);

    LogTextInFile(Out, "Base of code:");
    fprintf(Out, "%#x\n", Ioh.BaseOfCode);

    LogTextInFile(Out, "Base of data :");
    fprintf(Out, "%#x\n", Ioh.BaseOfData);

    LogTextInFile(Out, "Image base:");
    fprintf(Out, "%#x\n", Ioh.ImageBase);

    LogTextInFile(Out, "Section aligment:");
    fprintf(Out, "%lu\n", Ioh.SectionAlignment);

    LogTextInFile(Out, "File aligment:");
    fprintf(Out, "%lu\n", Ioh.FileAlignment);

    LogTextInFile(Out, "Operation system version:");
    fprintf(Out, "%d.%d\n", Ioh.MajorOperatingSystemVersion, Ioh.MinorOperatingSystemVersion);

    LogTextInFile(Out, "Image version:");
    fprintf(Out, "%d.%d\n", Ioh.MajorImageVersion, Ioh.MinorImageVersion);

    LogTextInFile(Out, "Subsystem version:");
    fprintf(Out, "%d.%d\n", Ioh.MajorSubsystemVersion, Ioh.MinorImageVersion);

    LogTextInFile(Out, "Win32 version value:");
    fprintf(Out, "%d\n", Ioh.Win32VersionValue);

    LogTextInFile(Out, "Size of image:");
    fprintf(Out, "%lu B \n", Ioh.SizeOfImage);

    LogTextInFile(Out, "Size of headers:");
    fprintf(Out, "%d\n", Ioh.SizeOfHeaders);

    LogTextInFile(Out, "CheckSum:");
    fprintf(Out, "%d\n", Ioh.CheckSum);

    LogTextInFile(Out, "Subsystem:");
    switch (Ioh.Subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
    {
        fprintf(Out, "Unknown subsystem.\n");
        break;
    }
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
    {
        fprintf(Out, "WINDOWS GUI.\n");
        break;
    }
    }

    LogTextInFile(Out, "DLL characteristics:");
    fprintf(Out, "%#x\n", Ioh.DllCharacteristics);

    LogTextInFile(Out, "Size of stack reserve:");
    fprintf(Out, "%lu\n", Ioh.SizeOfStackReserve);

    LogTextInFile(Out, "Size of stack commit:");
    fprintf(Out, "%lu\n", Ioh.SizeOfStackCommit);

    LogTextInFile(Out, "Size of heap reverse:");
    fprintf(Out, "%lu\n", Ioh.SizeOfHeapReserve);

    LogTextInFile(Out, "Size of heap commit:");
    fprintf(Out, "%d\n", Ioh.SizeOfHeapCommit);

    LogTextInFile(Out, "Loader flags:");
    fprintf(Out, "%#x\n", Ioh.LoaderFlags);

    LogTextInFile(Out, "Number of RVA:");
    fprintf(Out, "%d\n\n", Ioh.NumberOfRvaAndSizes);

    //printf("Optional header OUT!\n");
}

VOID
LogOneDirectory(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __in        UINT                      CurrentDirIndex
)
{
    PCHAR buffer;
    PCHAR buf;
    CHAR dir[30] = "Directory";

    buffer = malloc(16);
    _itoa(CurrentDirIndex, buffer, 10);
    strcat(dir, buffer);
    strcat(dir, " : ");
    LogTextInFile(Out, dir);

    size_t sz;
    sz = snprintf(NULL, 0, "%#lx", Ioh.DataDirectory[CurrentDirIndex].VirtualAddress);
    buf = (PCHAR)malloc(sz + 1);
    snprintf(buf, sz + 1, "%#lx", Ioh.DataDirectory[CurrentDirIndex].VirtualAddress);
    gSpacingSize = 10;
    LogTextInFile(Out, buf);

    gSpacingSize = DEFAULT_SPACING;
    fprintf(Out, "%lu bytes\n", Ioh.DataDirectory[CurrentDirIndex].Size);
    free(buffer);
    free(buf);
}

VOID
LogTextInFile(
    __in        FILE*                     Out,
    __in        PCHAR                     String
)
{
    PCHAR newChar;
    newChar = malloc(100);
    int i;
    for (i = 0; i < gSpacingSize; i++)
    {
        if ((UINT)i < strlen(String))
            newChar[i] = String[i];
        else
            newChar[i] = ' ';
    }
    newChar[i] = '\0';
    fprintf(Out, newChar);
    free(newChar);
}

VOID
LogDirectories(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PINT                      Error
)
{
    //printf("Directories IN!\n");
    fprintf(Out, "***************************** Data Dirctories Information *****************************\n");
    if (Ioh.NumberOfRvaAndSizes > 16)
    {
        *Error = 1;
        return;
    }
    for (UINT i = 0; i < Ioh.NumberOfRvaAndSizes; i++)
        LogOneDirectory(Out, Ioh, i);

    fprintf(Out, "\n");

    //printf("Directories OUT!\n");
}

VOID
LogSectionHeader(
    __in        FILE*                     Out,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        PIMAGE_SECTION_HEADER     Psh,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
)
{
    //printf("Section Header IN\n");
    fprintf(Out, "********************************* Section Header *********************************\n");
    for (int i = 0; i < Ifh.NumberOfSections; i++)
    {
        if (((DWORD)Psh) + sizeof(IMAGE_SECTION_HEADER) >= GlobalSize)
        {
            *Error = 1;
            return;
        }
        LogTextInFile(Out, "Section name:");
        fprintf(Out, "%.8s\n", Psh->Name);


        LogTextInFile(Out, "Virtual Address:");
        fprintf(Out, "%#lx\n", Psh->VirtualAddress);

        LogTextInFile(Out, "Virtual Size:");
        fprintf(Out, "%lu bytes\n", Psh->Misc.VirtualSize);

        LogTextInFile(Out, "Size Raw Data:");
        fprintf(Out, "%lu bytes\n", Psh->SizeOfRawData);

        LogTextInFile(Out, "Pointer to raw data:");
        fprintf(Out, "%#lx\n", Psh->PointerToRawData);

        fprintf(Out, "___________________________________________________________________________________\n\n");
        Psh++;
    }
    //printf("Section header OUT!\n");
}

VOID
LogImports(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PIMAGE_IMPORT_DESCRIPTOR  Pid,
    __in        PIMAGE_DOS_HEADER         Pdh,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
)
{
    //printf("IMPORTS IN!\n");
    if (IMAGE_DIRECTORY_ENTRY_IMPORT >= Ioh.NumberOfRvaAndSizes ||
        Ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    {
        printf("No import table\n");
        fprintf(Out, "No import table.\n");
        return;

    }
    else
    {
        Pid = (PIMAGE_IMPORT_DESCRIPTOR)RVA2FA(Pdh, Ifh.NumberOfSections, Ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, FileBuffer, GlobalSize);
        if ((INT)Pid == -1)
        {
            *Error = 1;
            return;
        }
        if (Pid)
        {
            fprintf(Out, "***************************************IMPORTS***************************************\n\n");
            while (Pid->Name)
            {

                if (RVA2FA(Pdh, Ifh.NumberOfSections, Pid->Name, FileBuffer, GlobalSize) == -1)
                {
                    *Error = 1;
                    return;
                }
                char* DLLname = (char*)RVA2FA(Pdh, Ifh.NumberOfSections, Pid->Name, FileBuffer, GlobalSize);


                LogTextInFile(Out, "DLL Name:");
                fprintf(Out, "%s\n", DLLname);

                LogTextInFile(Out, "Characteristics:");
                fprintf(Out, "%#lx\n", Pid->Characteristics);

                LogTextInFile(Out, "First Thunk:");
                fprintf(Out, "%#lx\n", Pid->FirstThunk);

                LogTextInFile(Out, "Forwarder Chain:");
                fprintf(Out, "%#lx\n", Pid->ForwarderChain);

                LogTextInFile(Out, "Original First Thunk:");
                fprintf(Out, "%#lx\n", Pid->OriginalFirstThunk);

                LogTextInFile(Out, "TimeDateStamp:");;
                fprintf(Out, "%lu\n\n", Pid->TimeDateStamp);

                // Get the adress table:
                PIMAGE_THUNK_DATA ptd = (PIMAGE_THUNK_DATA)RVA2FA(Pdh, Ifh.NumberOfSections, Pid->OriginalFirstThunk, FileBuffer, GlobalSize);
                if ((int)ptd == -1)
                {
                    *Error = 1;
                    return;
                }
                fprintf(Out, "####### Imported functions #######\n");
                while ((int)ptd < (int)GlobalSize && ptd->u1.AddressOfData)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(ptd->u1.Ordinal))
                    {
                        LogTextInFile(Out, "Ordinal:");
                        fprintf(Out, "%#lx\n", IMAGE_ORDINAL(ptd->u1.Ordinal));
                    }
                    else
                    {
                        gSpacingSize = 20;

                        PIMAGE_IMPORT_BY_NAME pibn = (PIMAGE_IMPORT_BY_NAME)RVA2FA(Pdh, Ifh.NumberOfSections, ptd->u1.AddressOfData, FileBuffer, GlobalSize);
                        if ((int)pibn == -1)
                        {
                            *Error = 1;
                            return;
                        }
                        LogTextInFile(Out, "Function Name:");
                        fprintf(Out, "%s\n", pibn->Name);

                        LogTextInFile(Out, "Function Hint:");
                        fprintf(Out, "#%x\n", pibn->Hint);

                        fprintf(Out, "_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _\n");

                        gSpacingSize = DEFAULT_SPACING;
                    }
                    ptd++;
                }
                Pid++;
                fprintf(Out, "_____________________________________________________________________\n");
            }
        }
    }
    //printf("IMPORTS OUT\n");
}

VOID
LogExports(
    __in        FILE*                     Out,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       PIMAGE_EXPORT_DIRECTORY   Ped,
    __in        PIMAGE_DOS_HEADER         Pdh,
    __in        IMAGE_FILE_HEADER         Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize,
    __out       PINT                      Error
)
{
    //printf("Exports IN!\n");

    DWORD   j;
    DWORD   k;

    PDWORD  addressOfFunctions;
    PWORD   addressOfNameOrdinals;
    PDWORD  addressOfNames;

    if (IMAGE_DIRECTORY_ENTRY_EXPORT >= Ioh.NumberOfRvaAndSizes ||
        Ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        //printf("No exp table\n");
        fprintf(Out, "No export table.\n");
        return;
    }

    Ped = (PIMAGE_EXPORT_DIRECTORY)RVA2FA(Pdh, Ifh.NumberOfSections, Ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, FileBuffer, GlobalSize);
    if ((INT)Ped == -1)
    {
        *Error = 1;
        return;
    }
    if (Ped)
    {
        fprintf(Out, "***************************************EXPORTS***************************************\n\n");
        if (RVA2FA(Pdh, Ifh.NumberOfSections, Ped->Name, FileBuffer, GlobalSize) == -1)
        {
            *Error = 1;
            return;
        }
        char* Dllname = (char*)RVA2FA(Pdh, Ifh.NumberOfSections, Ped->Name, FileBuffer, GlobalSize);
        LogTextInFile(Out, "DLL Name:\n");
        fprintf(Out, "%s\n", Dllname);

        LogTextInFile(Out, "Characteristics:");
        fprintf(Out, "%#lx\n", Ped->Characteristics);

        LogTextInFile(Out, "Ordinal Base:");
        fprintf(Out, "%#lx\n", Ped->Base);

        LogTextInFile(Out, "Major Version:");
        fprintf(Out, "%d\n", Ped->MajorVersion);

        LogTextInFile(Out, "Minor Version:");
        fprintf(Out, "%d\n", Ped->MinorVersion);

        LogTextInFile(Out, "Exported functions:");
        fprintf(Out, "%lu\n", Ped->NumberOfFunctions);

        LogTextInFile(Out, "Functions exported by name:");
        fprintf(Out, "%lu\n", Ped->NumberOfNames);

        LogTextInFile(Out, "TimeStamp:");
        fprintf(Out, "%lu\n\n", Ped->TimeDateStamp);

        addressOfFunctions = (PDWORD)RVA2FA(Pdh, Ifh.NumberOfSections, Ped->AddressOfFunctions, FileBuffer, GlobalSize);
        addressOfNameOrdinals = (PWORD)RVA2FA(Pdh, Ifh.NumberOfSections, Ped->AddressOfNameOrdinals, FileBuffer, GlobalSize);
        addressOfNames = (PDWORD)RVA2FA(Pdh, Ifh.NumberOfSections, Ped->AddressOfNames, FileBuffer, GlobalSize);

        if ((int)addressOfFunctions == -1 || (int)addressOfNameOrdinals == -1 || (int)addressOfNames == -1)
        {
            *Error = 1;
            return;
        }

        fprintf(Out, "########### EXPORTED FUNCTIONS BY NAME ########### \n");
        for (j = 0; j < Ped->NumberOfNames; j++)
        {

            if (RVA2FA(Pdh, Ifh.NumberOfSections, addressOfNames[j], FileBuffer, GlobalSize) == -1)
            {
                *Error = 1;
                return;
            }

            LogTextInFile(Out, "Function Name:");
            fprintf(Out, "%s\n", (PCHAR)RVA2FA(Pdh, Ifh.NumberOfSections, addressOfNames[j], FileBuffer, GlobalSize));

            LogTextInFile(Out, "Ordinal:");
            fprintf(Out, "%#lx\n", addressOfNameOrdinals[j] + Ped->Base);

            LogTextInFile(Out, "RVA:");
            fprintf(Out, "%#lx\n\n", addressOfFunctions[addressOfNameOrdinals[j]]);
        }

        fprintf(Out, "########### EXPORTED FUNCTIONS BY ORDINAL ########### \n");
        for (j = 0; j < Ped->NumberOfFunctions; j++)
        {
            if (addressOfFunctions[j] != 0)
            {
                for (k = 0; k < Ped->NumberOfNames; k++)
                {
                    // search for a function without name
                    if (addressOfFunctions[addressOfNameOrdinals[k]] == addressOfFunctions[j])
                        break;
                }

                if (k >= Ped->NumberOfNames)
                {
                    LogTextInFile(Out, "Function Name:");
                    fprintf(Out, "No Name\n");

                    LogTextInFile(Out, "Ordinal:");
                    fprintf(Out, "%#lx\n", j + Ped->Base);

                    LogTextInFile(Out, "RVA:");
                    fprintf(Out, "%#lx\n\n", addressOfFunctions[j]);
                }
            }
        }
    }
    //printf("Exports OUT!\n");
}

SIGNED_DWORD
RVA2FA(
    __in        CONST PIMAGE_DOS_HEADER   DosHeader,
    __in        CONST WORD                NumberOfSections,
    __in        CONST DWORD               RVA,
    __in        LPCBYTE                   FileBuffer,
    __in        DWORD                     GlobalSize
)
{
    PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)(FileBuffer + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    INT ok = 0;
    if (RVA == 0)
    {
        return -1;
    }

    for (WORD i = 0; i < NumberOfSections && (DWORD)(FileBuffer + secHeader->PointerToRawData) < GlobalSize && (DWORD)(FileBuffer + secHeader->PointerToRawData + secHeader->SizeOfRawData) < GlobalSize; i++)
    {
        if ((secHeader->VirtualAddress <= RVA) && (RVA < (secHeader->VirtualAddress + secHeader->Misc.VirtualSize)))
        {
            ok = 1;
            break;
        }
        secHeader++;
    }

    if (!ok)
    {
        return -1;
    }

    if ((FileBuffer + secHeader->PointerToRawData + (RVA - secHeader->VirtualAddress)) < FileBuffer + secHeader->PointerToRawData)
    {
        return -1;
    }

    if ((FileBuffer + secHeader->PointerToRawData + (RVA - secHeader->VirtualAddress)) > FileBuffer + secHeader->PointerToRawData + secHeader->SizeOfRawData)
    {
        return -1;
    }

    if ((DWORD)(FileBuffer + secHeader->PointerToRawData + (RVA - secHeader->VirtualAddress)) > GlobalSize)
    {
        return -1;
    }

    return (DWORD)(FileBuffer + secHeader->PointerToRawData + (RVA - secHeader->VirtualAddress));
}


VOID
CreatePath(
    __inout_z   PTCHAR                    FilePath,
    __in_z      LPCTSTR                   Argv,
    __in_z      LPCTSTR                   Name
)
{
    PTCHAR p;
    _tcscpy_s(FilePath, 100, Argv);
    p = _tcschr(FilePath, '*');
    if (p)
    {
        *p = 0;
        _tcscat(FilePath, Name);
    }
}

VOID
LogDword(
    __in        FILE*                     Out,
    __in        DWORD                     Number32Bits
)
{
    PCHAR buf;
    size_t sz;
    INT k = 0;
    sz = snprintf(NULL, 0, "%x", Number32Bits);
    buf = (PCHAR)malloc(sz + 1);
    snprintf(buf, sz + 1, "%x", Number32Bits);
    for (INT i = (signed)strlen(buf) - 1; i >= 0; i -= 2)
    {
        k = 1;
        if (i - 1 >= 0)
        {
            fprintf(Out, "%c", buf[i - 1]);
            k = 0;
        }
        fprintf(Out, "%c", buf[i]);
        if (i != 0)
        {
            fprintf(Out, " ");
        }
    }

    for (int i = 0; i < (signed)(sizeof(QWORD) - strlen(buf)); i++)
    {
        fprintf(Out, "0");
        k++;
        if (k % 2 == 0)
        {
            fprintf(Out, " ");
        }
    }
    free(buf);
}

VOID
SearchForAdson(
    __in        FILE*                     Out,
    __in        CONST PIMAGE_DOS_HEADER   DosHeader,
    __in        CONST IMAGE_FILE_HEADER   Ifh,
    __in        LPCBYTE                   FileBuffer,
    __in        IMAGE_OPTIONAL_HEADER     Ioh,
    __out       BOOL*                     Virused
)
{
    UINT                   crc = 0;
    PIMAGE_SECTION_HEADER  secHeader = (PIMAGE_SECTION_HEADER)(FileBuffer + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    IMAGE_SECTION_HEADER   Adson = secHeader[Ifh.NumberOfSections - 1];
    PDWORD                 key = NULL;

    if (strcmp((LPCTSTR)Adson.Name, ".Adson") != 0
        || Adson.Misc.VirtualSize != 0x1804
        || Adson.VirtualAddress != Ioh.AddressOfEntryPoint)
    {
        //printf(".Adson not found!\n");
        return;
    }

    key = (DWORD*)((DWORD)DosHeader + Adson.PointerToRawData + 0x15); // from ida, instr_patched_2
                                                                      // printf("The encryption key is : %#x\n", *key);
    fprintf(Out, "Virus decoded:\n");
    for (INT i = 0; i < sizeof(QWORD) * 0xB5; i += sizeof(QWORD))
    {
        DWORD *a = (DWORD*)((DWORD)DosHeader + Adson.PointerToRawData + 0x37 + i);
        DWORD *b = (DWORD*)((DWORD)DosHeader + Adson.PointerToRawData + 0x37 + i + 4);
        if (*a > *key)
        {
            crc = _mm_crc32_u32(crc, *b);
            crc = _mm_crc32_u32(crc, *a);
            LogDword(Out, *b);
            LogDword(Out, *a);
            fprintf(Out, "\n");
        }
        else
        {
            QWORD res = (QWORD)*b * (QWORD)*key;
            res += (QWORD)*a;
            DWORD low = (DWORD)res;
            DWORD high = (DWORD)(res >> 32);
            crc = _mm_crc32_u32(crc, low);
            crc = _mm_crc32_u32(crc, high);
            LogDword(Out, low);
            LogDword(Out, high);
            fprintf(Out, "\n");
        }
    }
    if (crc != CRC_INFECTED_FILE)
    {
        return;
    }

    *Virused = TRUE;
}

BOOL
CheckIfNumber(
    __in        PTCHAR                    WorkerThreads
)
{
    for (UINT i = 0; i < strlen(WorkerThreads); i++)
    {
        if (!isdigit(WorkerThreads[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

VOID
GetWorkerThreads(
    __in        PTCHAR                    FirstArg
)
{
    if (CheckIfNumber(FirstArg))
    {
        gStartingArgument = 2;
        gMaxThreads = atoi(FirstArg);
    }
    else
    {
        gStartingArgument = 1;
        printf("Number of worker threads has not been given! The number of worker threads is 8!\n");
        gMaxThreads = 8;
    }
}

VOID
InterlockedGetHeadListOrResetEvent(
    __out       PPROGRAM_ITEM*            ProgramItem
)
{
    EnterCriticalSection(&gCritSection);
    if (!IsListEmpty(&gHeadList))
    {
        *ProgramItem = CONTAINING_RECORD(RemoveHeadList(&gHeadList), PROGRAM_ITEM, ItemEntry);
    }
    else
    {
        ResetEvent(gEvents[0]);
    }
    LeaveCriticalSection(&gCritSection);
}

VOID
InterlockedIncrementInt(
    __out       PINT                      Number
)
{
    EnterCriticalSection(&gCritSection);
    (*Number)++;
    LeaveCriticalSection(&gCritSection);
}


VOID
CreategEventsWithManualReset(
    VOID
)
{
    gEvents[0] = CreateEvent(
        NULL,                        // default security attributes
        TRUE,                        // auto-reset event
        FALSE,                       // initial state is nonsignaled
        TEXT("ListNotEmptyEvent")    // object name
    );
    ResetEvent(gEvents[0]);
    gEvents[1] = CreateEvent(
        NULL,                         // default security attributes
        TRUE,                         // auto-reset event
        FALSE,                        // initial state is nonsignaled
        TEXT("ListEmptyEvent")        // object name
    );
    ResetEvent(gEvents[1]);
}

VOID
InterlockedInsertElementInTailList(
    __inout     PTCHAR                    FilePath,
    __in        PTCHAR                    NewArg,
    __in        WIN32_FIND_DATA           FindFileData,
    __inout     PPROGRAM_ITEM             pProgramItem
)
{
    CreatePath(FilePath, NewArg, FindFileData.cFileName);
    FillProgramItem(pProgramItem, FilePath, FindFileData);
    InterlockedInsertTailList(&gHeadList, &(pProgramItem->ItemEntry), &gCritSection);
    SetEvent(gEvents[0]);
}

VOID
LogThreadsUsageOnConsole(
    VOID
)
{
    for (int i = 0; (UINT)i < gMaxThreads; i++)
        printf("Thread %d processed %d files.\n", i, gThreadsArray[i]);
}

DWORD WINAPI
MultithreadScanner(
    //__in        LPVOID                    lpParam,
    __in        PSCANNER_THREAD_CONTEXT   Context
)
{
    HANDLE         hStdout = INVALID_HANDLE_VALUE;
    PPROGRAM_ITEM  program_item = NULL;
    INT            error = 0;
    INT            i = 0;
    DWORD currentEvent = 0;

    LPOVERLAPPED pOvlp;
    BOOL result;
    DWORD outSize;
    HRESULT hr;
    ULONG_PTR key;
    PSCANNER_NOTIFICATION notification;
    SCANNER_REPLY_MESSAGE replyMessage;
    PSCANNER_MESSAGE message;

    // Make sure there is a console to receive output results.
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    // Cast the parameter to the correct data type.
    //i = (INT)lpParam;

    while (TRUE)
    {
        currentEvent = WaitForMultipleObjects(2, gEvents, FALSE, INFINITE);
        if (currentEvent == WAIT_OBJECT_0)
        {
            InterlockedGetHeadListOrResetEvent(&program_item);
            if (program_item != NULL)
            {
                HANDLE                      hFile = NULL;
                LPCTSTR                     filePath1 = program_item->FilePath;
                CHAR                        fileName[100];
                CHAR                        outFile[100] = "C:\\Users\\IEUser\\Desktop\\Output\\";
                DWORD                       fileSize = 0;
                DWORD                       BytesRead = 0;
                PVOID                       fileBuffer = NULL;

                PIMAGE_IMPORT_DESCRIPTOR    pid = NULL;
                PIMAGE_EXPORT_DIRECTORY     ped = NULL;
                PIMAGE_DOS_HEADER           pdh = NULL;
                PIMAGE_NT_HEADERS           pnh = NULL;
                IMAGE_FILE_HEADER           ifh;
                IMAGE_OPTIONAL_HEADER       ioh;
                PIMAGE_SECTION_HEADER       psh = NULL;

                //CHAR                      outFile[100] = "C:\\Users\\IEUser\\Desktop\\Output\\";
                //CHAR                      outFile[100] = "C:\\Users\\dvieriu\\Desktop\\Output\\";
                //CHAR                      outFile[100] = "C:\\Users\\Denis\\Desktop\\Output\\";

                result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);
                message = CONTAINING_RECORD(pOvlp, SCANNER_MESSAGE, Ovlp);

                if (!result)
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    break;
                }

                printf("Received message, size %Id\n", pOvlp->InternalHigh);

                notification = &message->Notification;
                _Analysis_assume_(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

                // assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

                strcpy(fileName, program_item->FileName);
                strcat(outFile, fileName);
                strcat(outFile, ".log");

                CheckIfFileExists(filePath1);
                FileCreate(&hFile, filePath1);
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    continue;
                }
                FileRead(hFile, &fileSize, &fileBuffer, &BytesRead, &error);

                DWORD globalSize = (DWORD)fileBuffer + fileSize;
                FILE *out;
                out = fopen(outFile, "w");
                if (!out)
                {
                    perror("");
                    exit(1);
                }

                fprintf(out, "************************** File Information **************************\n");

                LogTextInFile(out, "File name:");
                fprintf(out, "%s \n", fileName);

                LogTextInFile(out, "File size:");
                fprintf(out, "%lu bytes | %.2lf kb \n\n", fileSize, fileSize * 1.0 / 1024);



                //Dos Header

                if (fileSize > 0)
                {
                    pdh = (PIMAGE_DOS_HEADER)fileBuffer;
                    pnh = (PIMAGE_NT_HEADERS)((DWORD)(pdh)+(pdh->e_lfanew));
                }
                // Checks if the DOS HEADER and NT HEADEAR are correct ( MAGIC = MZ , SIGNATURE = PE )
                if ((DWORD)pnh < globalSize && fileSize > 0)
                {
                    if (pdh->e_magic == IMAGE_DOS_SIGNATURE && pnh->Signature == IMAGE_NT_SIGNATURE)
                    {
                        error = 0;

                        LogDosHeader(out, pdh);

                        ifh = pnh->FileHeader;

                        LogNtHeader(out, pnh, ifh);

                        ioh = pnh->OptionalHeader;

                        if (error) { goto endCode; }
                        LogOptionalHeader(out, ioh, &error);

                        if (error) { goto endCode; }
                        LogDirectories(out, ioh, &error);

                        if (error) { goto endCode; }
                        psh = (PIMAGE_SECTION_HEADER)((DWORD)fileBuffer + pdh->e_lfanew + sizeof(IMAGE_NT_HEADERS));

                        if ((DWORD)psh > globalSize)
                        {
                            error = 1;
                            goto endCode;
                        }

                        if (error) { goto endCode; }
                        LogSectionHeader(out, ifh, psh, globalSize, &error);

                        if (error) { goto endCode; }
                        LogImports(out, ioh, pid, pdh, ifh, fileBuffer, globalSize, &error);

                        if (error) { goto endCode; }
                        LogExports(out, ioh, ped, pdh, ifh, fileBuffer, globalSize, &error);


                    endCode:
                        if (error == 1)
                        {
                            replyMessage.ReplyHeader.Status = 0;
                            replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
                            replyMessage.Reply.SafeToOpen = FALSE;

                            hr = FilterReplyMessage(Context->Port,
                                (PFILTER_REPLY_HEADER)&replyMessage,
                                sizeof(replyMessage));

                            if (SUCCEEDED(hr)) {
                                printf("Replied message\n");
                            }
                            else
                            {
                                printf("Scanner: Error replying message. Error = 0x%X\n", hr);
                                break;
                            }

                            InterlockedIncrementInt(&gBadFiles);
                        }
                        else
                        {
                            replyMessage.ReplyHeader.Status = 0;
                            replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
                            replyMessage.Reply.SafeToOpen = TRUE;
                            InterlockedIncrementInt(&gGoodFiles);
                            BOOL virused = FALSE;
                            SearchForAdson(out, pdh, ifh, fileBuffer, ioh, &virused);
                            if (virused == TRUE)
                            {
                                replyMessage.Reply.SafeToOpen = FALSE;
                                printf("The file %s contains .Adson!\n", fileName);
                                hr = FilterReplyMessage(Context->Port,
                                    (PFILTER_REPLY_HEADER)&replyMessage,
                                    sizeof(replyMessage));

                                if (SUCCEEDED(hr)) {
                                    printf("Replied message\n");
                                }
                                else
                                {
                                    hr = FilterReplyMessage(Context->Port,
                                        (PFILTER_REPLY_HEADER)&replyMessage,
                                        sizeof(replyMessage));

                                    if (SUCCEEDED(hr)) {
                                        printf("Replied message\n");
                                    }
                                    else
                                    {
                                        printf("Scanner: Error replying message. Error = 0x%X\n", hr);
                                        break;
                                    }
                                    printf("Scanner: Error replying message. Error = 0x%X\n", hr);
                                    break;
                                }
                            }
                            else
                            {
                                printf("The file %s is clean!\n", fileName);
                            }
                        }
                    }
                    else
                    {
                        InterlockedIncrementInt(&gBadFiles);
                    }
                }
                else
                {
                    InterlockedIncrementInt(&gBadFiles);
                }

                fclose(out);
                gThreadsArray[i]++;
                DestroyProgramItem(program_item);
            }
        }
        else if (currentEvent == WAIT_OBJECT_0 + 1)
        {
            break;
        }


    }

    if (!SUCCEEDED(hr)) {

        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

            //
            //  Scanner port disconncted.
            //

            printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

        }
        else {

            printf("Scanner: Unknown error occured. Error = 0x%X\n", hr);
        }
    }

    free(message);

    return hr;

}

VOID
ErrorHandler(
    __in        LPTSTR                    lpszFunction
)
{
    // Retrieve the system error message for the last-error code.

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message.

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    // Free error-handling buffer allocations.

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}
