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
 */

#include <Windows.h>
#include "options.h"


DWORD InitializeConnectionInfo(
    IN OUT PCONNECTION_INFO Connection,
    IN PMOUNT_OPTION_BUFFER Options,
    OUT LPWSTR *ConnectionName)
{
    DWORD result = WN_SUCCESS;
    SIZE_T size;

    /* verify that this is a mount options buffer */
    if (Options &&
        Options->Zero == 0 &&
        Options->Secret == MOUNT_OPTION_BUFFER_SECRET)
    {
        Connection->Options = Options;
        size = MAX_CONNECTION_BUFFER_SIZE(Options->Length);
    }
    else
    {
        Connection->Options = NULL;
        size = MAX_CONNECTION_BUFFER_SIZE(0);
    }

    Connection->Buffer = LocalAlloc(LMEM_ZEROINIT, size);
    if (Connection->Buffer)
        *ConnectionName = (LPWSTR)Connection->Buffer->Buffer;
    else
        result = WN_OUT_OF_MEMORY;

    return result;
}

static FORCEINLINE SIZE_T ConnectionBufferSize(
    IN PCONNECTION_BUFFER Buffer)
{
    return sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG) +
        Buffer->NameLength + Buffer->EaPadding + Buffer->EaLength;
}

void MarshalConnectionInfo(
    IN OUT PCONNECTION_INFO Connection)
{
    PCONNECTION_BUFFER Buffer = Connection->Buffer;
    LPWSTR ConnectionName = (LPWSTR)Buffer->Buffer;

    Buffer->NameLength = (USHORT)(wcslen(ConnectionName) + 1) * sizeof(WCHAR);

    /* copy the EaBuffer after the end of ConnectionName */
    if (Connection->Options && Connection->Options->Length)
    {
        PBYTE ptr = Buffer->Buffer + Buffer->NameLength;
        /* add padding so EaBuffer starts on a ULONG boundary */
        Buffer->EaPadding = (USHORT)
            (sizeof(ULONG) - (SIZE_T)ptr % sizeof(ULONG)) % sizeof(ULONG);
        Buffer->EaLength = Connection->Options->Length;
        ptr += Buffer->EaPadding;

        RtlCopyMemory(ptr, Connection->Options->Buffer, Buffer->EaLength);
    }

    Connection->BufferSize = (ULONG)ConnectionBufferSize(Buffer);
}

void FreeConnectionInfo(
    IN PCONNECTION_INFO Connection)
{
    if (Connection->Buffer)
    {
        LocalFree(Connection->Buffer);
        Connection->Buffer = NULL;
    }
    Connection->Options = NULL;
    Connection->BufferSize = 0;
}
