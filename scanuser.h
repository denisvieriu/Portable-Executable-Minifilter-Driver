/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

scanuser.h

Abstract:

Header file which contains the structures, type definitions,
constants, global variables and function prototypes for the
user mode part of the scanner.

Environment:

Kernel & user mode

--*/
#ifndef __SCANUSER_H__
#define __SCANUSER_H__

#include  <FltUser.h>

#pragma pack(1)


const PWSTR ScannerPortName = L"\\MyPort";


#define SCANNER_READ_BUFFER_SIZE   1024

typedef struct _SCANNER_NOTIFICATION {

	ULONG BytesToScan;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Contents[SCANNER_READ_BUFFER_SIZE];

} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

typedef struct _SCANNER_REPLY {

	BOOLEAN SafeToOpen;

} SCANNER_REPLY, *PSCANNER_REPLY;

typedef struct _SCANNER_MESSAGE {

    //
    //  Required structure header.
    //

    FILTER_MESSAGE_HEADER MessageHeader;


    //
    //  Private scanner-specific fields begin here.
    //

    SCANNER_NOTIFICATION Notification;

    //
    //  Overlapped structure: this is not really part of the message
    //  However we embed it instead of using a separately allocated overlap structure
    //

    OVERLAPPED Ovlp;

} SCANNER_MESSAGE, *PSCANNER_MESSAGE;

typedef struct _SCANNER_REPLY_MESSAGE {

    //
    //  Required structure header.
    //

    FILTER_REPLY_HEADER ReplyHeader;

    //
    //  Private scanner-specific fields begin here.
    //

    SCANNER_REPLY Reply;

} SCANNER_REPLY_MESSAGE, *PSCANNER_REPLY_MESSAGE;

#endif //  __SCANUSER_H__

