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

#include <ntifs.h>
#include <strsafe.h>
#include <stdio.h>


#define MAX_LIST_LEN 4096
#define MAX_EA_VALUE 256

#define MAX_GETEA (sizeof(FILE_GET_EA_INFORMATION) + MAX_EA_VALUE)
#define MAX_FULLEA (sizeof(FILE_FULL_EA_INFORMATION) + 2 * MAX_EA_VALUE)

static NTSTATUS ea_list(
    HANDLE FileHandle)
{
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    CHAR Buffer[MAX_LIST_LEN];
    PFILE_FULL_EA_INFORMATION EaBuffer;
    NTSTATUS status;
    BOOLEAN RestartScan = TRUE;

on_overflow:
    EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;

    status = ZwQueryEaFile(FileHandle, &IoStatusBlock,
        EaBuffer, MAX_LIST_LEN, FALSE, NULL, 0, NULL, RestartScan);
    switch (status) {
    case STATUS_SUCCESS:
    case STATUS_BUFFER_OVERFLOW:
        break;
    case STATUS_NO_EAS_ON_FILE:
        printf("No EAs on file.\n", status);
        goto out;
    default:
        fprintf(stderr, "ZwQueryEaFile() failed with %X\n", status);
        goto out;
    }

    while (EaBuffer) {
        printf("%s = %.*s\n", EaBuffer->EaName, EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);

        if (EaBuffer->NextEntryOffset == 0)
            break;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)
            ((PCHAR)EaBuffer + EaBuffer->NextEntryOffset);
    }

    if (status == STATUS_BUFFER_OVERFLOW) {
        printf("overflow, querying more\n", status);
        RestartScan = FALSE;
        goto on_overflow;
    }
out:
    return status;
}

static NTSTATUS ea_get(
    HANDLE FileHandle,
    IN LPCWSTR EaNames[],
    IN DWORD Count)
{
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    CHAR GetBuffer[MAX_LIST_LEN] = { 0 };
    CHAR FullBuffer[MAX_LIST_LEN] = { 0 };
    PFILE_GET_EA_INFORMATION EaList = (PFILE_GET_EA_INFORMATION)GetBuffer, EaQuery;
    PFILE_FULL_EA_INFORMATION EaBuffer = (PFILE_FULL_EA_INFORMATION)FullBuffer;
    ULONG ActualByteCount, EaListLength;
    DWORD i;
    NTSTATUS status;

    EaQuery = EaList;
    EaListLength = 0;

    for (i = 0; i < Count; i++) {
        LPCWSTR EaName = EaNames[i];
        ULONG EaNameLength = (ULONG)((wcslen(EaName)+1) * sizeof(WCHAR));

        /* convert EaName */
        status = RtlUnicodeToUTF8N(EaQuery->EaName, MAX_EA_VALUE,
            &ActualByteCount, EaName, EaNameLength);
        if (status) {
            fwprintf(stderr, L"RtlUnicodeToUTF8N('%s') failed with %X\n", EaName, status);
            goto out;
        }
        EaQuery->EaNameLength = (UCHAR)ActualByteCount - 1;
        EaQuery->NextEntryOffset = FIELD_OFFSET(FILE_GET_EA_INFORMATION, EaName) + EaQuery->EaNameLength + 1;

        if (i == Count - 1) {
            EaListLength += EaQuery->NextEntryOffset;
            EaQuery->NextEntryOffset = 0;
        } else {
            EaQuery->NextEntryOffset = 4 + ((EaQuery->NextEntryOffset - 1) & ~3);
            EaListLength += EaQuery->NextEntryOffset;
        }
        EaQuery = (PFILE_GET_EA_INFORMATION)((PCHAR)EaQuery + EaQuery->NextEntryOffset);
    }
 
    status = ZwQueryEaFile(FileHandle, &IoStatusBlock,
        EaBuffer, MAX_FULLEA, FALSE, EaList, EaListLength, NULL, TRUE);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_NO_EAS_ON_FILE:
        printf("No EAs on file.\n", status);
        goto out;
    default:
        fprintf(stderr, "ZwQueryEaFile('%s') failed with %X\n", EaList->EaName, status);
        goto out;
    }
    
    while (EaBuffer) {
        printf("%s = %.*s\n", EaBuffer->EaName, EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);

        if (EaBuffer->NextEntryOffset == 0)
            break;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)
            ((PCHAR)EaBuffer + EaBuffer->NextEntryOffset);
    }
out:
    return status;
}

static NTSTATUS full_ea_init(
    IN LPCWSTR EaName,
    IN LPCWSTR EaValue,
    OUT PFILE_FULL_EA_INFORMATION EaBuffer,
    OUT PULONG EaLength)
{
    ULONG ActualByteCount, EaNameLength;
    NTSTATUS status;

    EaBuffer->NextEntryOffset = 0;
    EaBuffer->Flags = 0;

    EaNameLength = (ULONG)((wcslen(EaName)+1) * sizeof(WCHAR));

    /* convert EaName */
    status = RtlUnicodeToUTF8N(EaBuffer->EaName, MAX_FULLEA -
        FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName),
        &ActualByteCount, EaName, EaNameLength);
    if (status) {
        fwprintf(stderr, L"RtlUnicodeToUTF8N('%s') failed with %X\n", EaName, status);
        goto out;
    }
    EaBuffer->EaNameLength = (UCHAR)ActualByteCount - 1;

    if (EaValue == NULL) {
        EaBuffer->EaValueLength = 0;
    } else {
        ULONG EaValueLength = (ULONG)((wcslen(EaValue)+1) * sizeof(WCHAR));

        /* convert EaValue */
        status = RtlUnicodeToUTF8N(EaBuffer->EaName + EaBuffer->EaNameLength + 1,
            MAX_FULLEA - FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) - EaBuffer->EaNameLength - 1,
            &ActualByteCount, EaValue, EaValueLength);
        if (status) {
            fwprintf(stderr, L"RtlUnicodeToUTF8N('%s') failed with %X\n", EaName, status);
            goto out;
        }
        EaBuffer->EaValueLength = (UCHAR)ActualByteCount - 1;
    }

    *EaLength = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
        EaBuffer->EaNameLength + 1 + EaBuffer->EaValueLength;
out:
    return status;
}

static NTSTATUS ea_set(
    HANDLE FileHandle,
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength)
{
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    NTSTATUS status;

    status = ZwSetEaFile(FileHandle, &IoStatusBlock, EaBuffer, EaLength);
    switch (status) {
    case STATUS_SUCCESS:
        printf("%s = %.*s\n", EaBuffer->EaName, EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);
        break;
    default:
        fprintf(stderr, "ZwSetEaFile() failed with %X\n", status);
        break;
    }
    return status;
}

int wmain(DWORD argc, LPWSTR argv[])
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ACCESS_MASK DesiredAccess = GENERIC_READ;
    ULONG FileAttributes = 0;
    ULONG ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    ULONG CreateDisposition = FILE_OPEN_IF;
    //ULONG CreateOptions = FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT;
    ULONG CreateOptions = 0;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    CHAR Buffer[MAX_FULLEA] = { 0 };
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    ULONG EaLength = 0;

    if (argc < 3) {
        fwprintf(stderr, L"Usage: nfs_ea <filename> <create|set|get|list> ...\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    if (wcscmp(argv[2], L"create") == 0) {
        if (argc < 5) {
            fwprintf(stderr, L"Usage: nfs_ea <filename> create <name> <value>\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        CreateDisposition = FILE_OVERWRITE_IF;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;
        status = full_ea_init(argv[3], argv[4], EaBuffer, &EaLength);
        if (status)
            goto out;
        wprintf(L"Creating file %s.\n", argv[1]);
    } else if (wcscmp(argv[2], L"set") == 0) {
        if (argc < 4) {
            fwprintf(stderr, L"Usage: nfs_ea <filename> set <name> [value]\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        DesiredAccess |= GENERIC_WRITE;
    } else if (wcscmp(argv[2], L"get") == 0) {
        if (argc < 4) {
            fwprintf(stderr, L"Usage: nfs_ea <filename> get <name> [name...]\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
    } else if (wcscmp(argv[2], L"list") != 0) {
        fwprintf(stderr, L"Usage: nfs_ea <filename> <create|set|get|list> ...\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    RtlInitUnicodeString(&FileName, argv[1]);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, 0, NULL, NULL);

    status = NtCreateFile(&FileHandle, DesiredAccess, &ObjectAttributes,
        &IoStatusBlock, NULL, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
    if (status) {
        fwprintf(stderr, L"NtCreateFile(%s) failed with %X\n", FileName.Buffer, status);
        goto out;
    }

    if (wcscmp(argv[2], L"set") == 0) {
        EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;
        status = full_ea_init(argv[3], argc > 4 ? argv[4] : NULL,
            EaBuffer, &EaLength);
        if (status)
            goto out_close;

        wprintf(L"Setting extended attribute '%s' on file %s:\n",
            argv[3], FileName.Buffer);
        status = ea_set(FileHandle, EaBuffer, EaLength);
    } else if (wcscmp(argv[2], L"get") == 0) {
        wprintf(L"Querying extended attribute on file %s:\n",
            argv[3], FileName.Buffer);
        status = ea_get(FileHandle, argv + 3, argc - 3);
    } else if (wcscmp(argv[2], L"list") == 0) {
        wprintf(L"Listing extended attributes for %s:\n", FileName.Buffer);
        status = ea_list(FileHandle);
    } else if (wcscmp(argv[2], L"create") == 0) {
        wprintf(L"File '%s' was created with \n", FileName.Buffer);
        status = ea_get(FileHandle, argv + 3, 1);
    }

out_close:
    NtClose(FileHandle);
out:
    return status;
}
