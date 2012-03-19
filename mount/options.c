/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>

#include "options.h"


DWORD InitializeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options,
    IN ULONG BufferSize)
{
    Options->Current = NULL;
    Options->Remaining = BufferSize;
    Options->Buffer = LocalAlloc(LMEM_ZEROINIT, BufferSize);
    if (Options->Buffer == NULL)
        return ERROR_OUTOFMEMORY;

    Options->Buffer->Secret = MOUNT_OPTION_BUFFER_SECRET;
    return NO_ERROR;
}

void FreeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options)
{
    Options->Current = NULL;
    Options->Remaining = 0;
    if (Options->Buffer)
    {
        LocalFree(Options->Buffer);
        Options->Buffer = NULL;
    }
}

static BOOL FindOptionByName(
    IN LPCTSTR Name,
    IN PMOUNT_OPTION_LIST Options,
    OUT PFILE_FULL_EA_INFORMATION* ppOption)
{
    PFILE_FULL_EA_INFORMATION Current =
        (PFILE_FULL_EA_INFORMATION)Options->Buffer->Buffer;
    ULONG NameLength = (ULONG)_tcslen(Name) * sizeof(TCHAR);

    for (;;)
    {
        if (Current->EaNameLength == NameLength &&
            _tcscmp((LPTSTR)Current->EaName, Name) == 0)
        {
            *ppOption = Current;
            return TRUE;
        }
        if (Current->NextEntryOffset == 0)
            break;
        Current = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Current + Current->NextEntryOffset);
    }
    return FALSE;
}

static FORCEINLINE ULONG EaBufferSize(
    IN UCHAR NameSize,
    IN USHORT ValueSize)
{
    ULONG Size = sizeof(ULONG) + 2 * sizeof(UCHAR) + sizeof(USHORT)
        + NameSize + ValueSize + sizeof(TCHAR);
    /* extended attributes require ULONG alignment;
     * see documentation for IoCheckEaBufferValidity() */
    return ( (Size + 3) / sizeof(ULONG) ) * sizeof(ULONG);
}

static FORCEINLINE ULONG EaBufferNextOffset(
    IN PFILE_FULL_EA_INFORMATION EaBuffer)
{
    return EaBufferSize(
        EaBuffer->EaNameLength,
        EaBuffer->EaValueLength);
}

BOOL InsertOption(
    IN LPCTSTR Name,
    IN LPCTSTR Value,
    IN OUT PMOUNT_OPTION_LIST Options)
{
    PFILE_FULL_EA_INFORMATION Current;
    UCHAR NameLen = (UCHAR)_tcslen(Name) * sizeof(TCHAR);
    USHORT ValueLen = (USHORT)_tcslen(Value) * sizeof(TCHAR);
    ULONG SpaceRequired = EaBufferSize(NameLen, ValueLen);

    /* don't allow duplicate options */
    if (FindOptionByName(Name, Options, &Current)) {
        _ftprintf(stderr, TEXT("Found a duplicate option ")
            TEXT("'%s%s%s' while parsing '%s%s%s'.\n"),
            (PTCH)Current->EaName,
            Current->EaValueLength ? TEXT("=") : TEXT(""),
            (PTCH)(Current->EaName + Current->EaNameLength + sizeof(TCHAR)),
            Name, ValueLen ? TEXT("=") : Value, Value);
        return FALSE;
    }

    /* fail if we're out of space */
    if (SpaceRequired > Options->Remaining) {
        _ftprintf(stderr, TEXT("Out of space for options!\n"));
        return FALSE;
    }

    if (Options->Current == NULL)
        Current = Options->Current = (PFILE_FULL_EA_INFORMATION)
            Options->Buffer->Buffer;
    else
        Current = Options->Current = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Options->Current + Options->Current->NextEntryOffset);

    Current->EaNameLength = NameLen;
    if (NameLen) /* copy attribute name */
        StringCbCopy((LPTSTR)Current->EaName,
            NameLen + sizeof(TCHAR), Name);

    Current->EaValueLength = ValueLen;
    if (ValueLen) /* copy attribute value */
        StringCbCopy((LPTSTR)(Current->EaName + NameLen + sizeof(TCHAR)),
            ValueLen + sizeof(TCHAR), Value);

    Current->Flags = 0;
    Current->NextEntryOffset = EaBufferNextOffset(Options->Current);

    Options->Buffer->Length = (ULONG)(
        (Current->EaName + NameLen + ValueLen + 2 * sizeof(TCHAR))
            - Options->Buffer->Buffer );
    Options->Remaining -= SpaceRequired;
    return TRUE;
}

static void RecursivePrintEaInformation(
    IN PFILE_FULL_EA_INFORMATION EA)
{
    _tprintf(
        TEXT("----------------------\n")
        TEXT("Alignment:           %5lu\n")
        TEXT("NextEntryOffset:     %5lu\n")
        TEXT("Flags:               %5u\n")
        TEXT("EaNameLength:        %5u\n")
        TEXT("EaValueLength:       %5u\n")
        TEXT("EaName:   %16ls\n")
        TEXT("EaValue:  %16ls\n\n"),
        (ULONG_PTR)EA % sizeof(ULONG),
        EA->NextEntryOffset,
        EA->Flags,
        EA->EaNameLength,
        EA->EaValueLength,
        (LPTSTR)EA->EaName,
        (LPTSTR)(EA->EaName + EA->EaNameLength + sizeof(TCHAR)));

    if (EA->NextEntryOffset)
        RecursivePrintEaInformation((PFILE_FULL_EA_INFORMATION)
            ((PBYTE)EA + EA->NextEntryOffset));
}

static const TCHAR COMMA_T = TEXT(',');
static const TCHAR EQUAL_T = TEXT('=');

BOOL ParseMountOptions(
    IN LPTSTR Arg,
    IN OUT PMOUNT_OPTION_LIST Options)
{
    PTCH pos, comma, equals;

    pos = Arg;
    for (;;)
    {
        comma = _tcschr(pos, COMMA_T);
        if (comma)
        {
            if (comma == pos)
                goto out_empty_option;
            *comma = 0;
        }
        else if (_tcslen(pos) == 0)
            goto out_empty_option;

        /* accept 'option=value' or 'option' */
        equals = _tcschr(pos, EQUAL_T);
        if (equals)
        {
            if (equals == pos)
                goto out_empty_option;
            *equals = 0;
            if (!InsertOption(pos, equals + 1, Options))
                return FALSE;
        }
        else if (!InsertOption(pos, TEXT(""), Options))
            return FALSE;

        if (comma == NULL)
            break;

        pos = comma + 1;
    }

/*  RecursivePrintEaInformation(
        (PFILE_FULL_EA_INFORMATION)Options->Buffer->Buffer); */
    return TRUE;

out_empty_option:
    _ftprintf(stderr, TEXT("Found an empty option while ")
        TEXT("reading mount options at '%s'.\n"), pos);
    return FALSE;
}
