#pragma once

FORCEINLINE
	VOID
	InitializeListHead(
	__out PLIST_ENTRY ListHead
	)
{
	ListHead->Flink = ListHead->Blink = ListHead;
}

__checkReturn
	BOOLEAN
	FORCEINLINE
	IsListEmpty(
	__in const LIST_ENTRY * ListHead
	)
{
	return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
	BOOLEAN
	RemoveEntryList(
	__in PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Flink;

	Flink = Entry->Flink;
	Blink = Entry->Blink;
	Blink->Flink = Flink;
	Flink->Blink = Blink;
	return (BOOLEAN)(Flink == Blink);
}

FORCEINLINE
	PLIST_ENTRY
	RemoveHeadList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Flink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Flink;
	Flink = Entry->Flink;
	ListHead->Flink = Flink;
	Flink->Blink = ListHead;
	return Entry;
}

FORCEINLINE
	PLIST_ENTRY
	RemoveTailList(
	__inout PLIST_ENTRY ListHead
	)
{
	PLIST_ENTRY Blink;
	PLIST_ENTRY Entry;

	Entry = ListHead->Blink;
	Blink = Entry->Blink;
	ListHead->Blink = Blink;
	Blink->Flink = ListHead;
	return Entry;
}


FORCEINLINE
	VOID
	InsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Blink;

	Blink = ListHead->Blink;
	Entry->Flink = ListHead;
	Entry->Blink = Blink;
	Blink->Flink = Entry;
	ListHead->Blink = Entry;
}


FORCEINLINE
	VOID
	InsertHeadList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
	)
{
	PLIST_ENTRY Flink;

	Flink = ListHead->Flink;
	Entry->Flink = Flink;
	Entry->Blink = ListHead;
	Flink->Blink = Entry;
	ListHead->Flink = Entry;
}

BOOLEAN
	InterlockedIsListEmpty(
	__in const LIST_ENTRY* ListHead,
	__in CRITICAL_SECTION* ListLock
	)
{
	BOOLEAN result;

	result = FALSE;

	EnterCriticalSection( ListLock );
	result = IsListEmpty( ListHead );
	LeaveCriticalSection( ListLock );

	return result;
}

PLIST_ENTRY
	InterlockedRemoveHeadList(
	__inout PLIST_ENTRY ListHead,
	__in CRITICAL_SECTION* ListLock
	)
{
	PLIST_ENTRY result;

	result = NULL;

	EnterCriticalSection( ListLock );
	result = RemoveHeadList( ListHead );
	LeaveCriticalSection( ListLock );

	return result;
}

BOOLEAN
	InterlockedRemoveEntryList(
	__in PLIST_ENTRY Entry,
	__in CRITICAL_SECTION* ListLock
	)
{
	BOOLEAN result;

	result = FALSE;

	EnterCriticalSection( ListLock );
	result = RemoveEntryList( Entry );
	LeaveCriticalSection( ListLock );

	return result;
}

VOID
	InterlockedInsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry,
	__in CRITICAL_SECTION* ListLock
	)
{
	EnterCriticalSection( ListLock );
	InsertTailList( ListHead, Entry );
	LeaveCriticalSection( ListLock );
}