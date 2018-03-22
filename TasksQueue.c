#define _CRT_SECURE_NO_WARNINGS
#include "TasksQueue.h"
#include <stdio.h>


FORCEINLINE
    VOID
    PrintProgramList(
        __in        PLIST_ENTRY               gHeadList
    )
{
	for (LIST_ENTRY *it = gHeadList->Flink; it != &(*gHeadList); it = it->Flink)
	{
		PPROGRAM_ITEM prog = CONTAINING_RECORD(it, PROGRAM_ITEM, ItemEntry);
		printf("Filename is: %s, Filepath is: %s\n", prog->FileName, prog->FilePath);
	}
}

VOID
FillProgramItem(
    __out        PPROGRAM_ITEM            pProgramItem,
    __in         PTCHAR                   FilePath,
    __in         WIN32_FIND_DATA          FindFileData
    )
{
	pProgramItem->FileName = (char*)malloc(strlen(FindFileData.cFileName) + 1);
	strcpy(pProgramItem->FileName, FindFileData.cFileName);
	pProgramItem->FilePath = (TCHAR*)malloc(strlen(FilePath) + 1);
	strcpy(pProgramItem->FilePath, FilePath);

}

VOID
DestroyProgramItem(
    __in        PPROGRAM_ITEM             program_item
    )
{
	free(program_item->FileName);
	free(program_item->FilePath);
}


