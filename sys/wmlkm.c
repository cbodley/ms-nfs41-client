/* Copyright (c) 2010, 2011
 * The Regents of the University of Michigan
 * All Rights Reserved
 * 
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * Permission is granted to use, copy and redistribute this software
 * for noncommercial education and research purposes, so long as no
 * fee is charged, and so long as the name of the University of Michigan
 * is not used in any advertising or publicity pertaining to the use
 * or distribution of this software without specific, written prior
 * authorization.  Permission to modify or otherwise create derivative
 * works of this software is not granted.
 *
 * This software is provided as is, without representation or warranty
 * of any kind either express or implied, including without limitation
 * the implied warranties of merchantability, fitness for a particular
 * purpose, or noninfringement.  The Regents of the University of
 * Michigan shall not be liable for any damages, including special,
 * indirect, incidental, or consequential damages, with respect to any
 * claim arising out of or in connection with the use of the software,
 * even if it has been or is hereafter advised of the possibility of
 * such damages.
 *
 * Comments: RDBSS depends on wmlkm files. See comments in nulmrx/wmlkm
 */
#pragma hdrstop

#include <ntddk.h>
#include <ntdef.h> 
#define LPVOID PVOID64 // BUG - need to find include for this
#include "wmlkm.h"

NTSTATUS
WmlTinySystemControl(
    __inout PVOID WmiLibInfo,
    __in PVOID DeviceObject,
    __in PVOID Irp
    )
{
    return(STATUS_WMI_GUID_NOT_FOUND);
}

ULONG
WmlTrace(
    __in ULONG Type,
    __in LPVOID TraceGuid,
    __in ULONG64 LoggerHandle,
    ... // Pairs: Address, Length
    )
{
    return STATUS_SUCCESS;
}