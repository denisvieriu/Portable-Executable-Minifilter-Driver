#pragma once
#ifndef _TASKS_QUEUE_H_
#define _TASKS_QUEUE_H_
#include <windows.h>

//
// Main list structure which will contain all the filenames and their filepaths
// 
typedef struct _PROGRAM_ITEM {
	PTCHAR       FilePath;
	PCHAR        FileName;
	LIST_ENTRY   ItemEntry;
}PROGRAM_ITEM, *PPROGRAM_ITEM;

FORCEINLINE
    VOID 
    PrintProgramList(
        __in        PLIST_ENTRY               gHeadList
    );

VOID
FillProgramItem(
    __out       PPROGRAM_ITEM             pProgramItem,
    __in        PTCHAR                    FilePath,
    __in        WIN32_FIND_DATA           FindFileData
    );

VOID 
DestroyProgramItem(
    __in        PPROGRAM_ITEM             program_item
    );

#endif