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
#include <Winnetwk.h> /* for WNet*Connection */
#include <stdlib.h>
#include <stdio.h>

#include "nfs41_driver.h" /* NFS41_PROVIDER_NAME_A */
#include "options.h"


DWORD EnumMounts(
    IN LPNETRESOURCE pContainer);

static DWORD DoMount(
    IN LPTSTR pLocalName,
    IN LPTSTR pRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions);
static DWORD DoUnmount(
    IN LPTSTR pLocalName,
    IN BOOL bForce);

static void RecursivePrintEaInformation(
    IN PFILE_FULL_EA_INFORMATION EA);
static BOOL ParseDriveLetter(
    IN LPTSTR pArg,
    OUT PTCH pDriveLetter);
void PrintErrorMessage(
    IN DWORD dwError);

static VOID PrintUsage(LPTSTR pProcess)
{
    _tprintf(TEXT("Usage: %s [options] <drive letter|*> <hostname>:<path>\n")
        TEXT("Options:\n")
        TEXT("\t-h\thelp\n")
        TEXT("\t-d\tunmount\n")
        TEXT("\t-f\tforce unmount if the drive is in use\n")
        TEXT("\t-p\tmake the mount persist over reboots\n")
        TEXT("\t-o <comma-separated mount options>\n")
        TEXT("Mount options:\n")
        TEXT("\tro\tmount as read-only\n")
        TEXT("\trsize=#\tread buffer size in bytes\n")
        TEXT("\twsize=#\twrite buffer size in bytes\n")
        TEXT("\tsec=krb5:krb5i:krb5p\tspecify gss security flavor\n")
        TEXT("\twritethru\tturns off rdbss caching for writes\n")
        TEXT("\tnocache\tturns off rdbss caching\n")
        TEXT("\ttimeout=#\tspecify upcall timeout value in seconds (default 120s)\n"),
        pProcess, pProcess, pProcess);
}

DWORD __cdecl _tmain(DWORD argc, LPTSTR argv[])
{
    DWORD   i, result = NO_ERROR;
    TCHAR   szLocalName[] = TEXT("C:\0");
    LPTSTR  pLocalName = NULL;
    LPTSTR  pRemoteName = NULL;
    BOOL    bUnmount = FALSE;
    BOOL    bForceUnmount = FALSE;
    BOOL    bPersistent = FALSE;
    MOUNT_OPTION_LIST Options;

    if (argc == 1) {
        /* list open nfs shares */
        result = EnumMounts(NULL);
        if (result)
            PrintErrorMessage(GetLastError());
        goto out;
    }

    result = InitializeMountOptions(&Options, MAX_OPTION_BUFFER_SIZE);
    if (result) {
        PrintErrorMessage(GetLastError());
        goto out;
    }

    /* parse command line */
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == TEXT('-'))
        {
            if (_tcscmp(argv[i], TEXT("-h")) == 0) /* help */
            {
                PrintUsage(argv[0]);
                goto out;
            }
            else if (_tcscmp(argv[i], TEXT("-d")) == 0) /* unmount */
            {
                bUnmount = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-f")) == 0) /* force unmount */
            {
                bForceUnmount = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-p")) == 0) /* persistent */
            {
                bPersistent = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-o")) == 0) /* mount option */
            {
                ++i;
                if (i >= argc)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    _ftprintf(stderr, TEXT("Mount options missing ")
                        TEXT("after '-o'.\n\n"));
                    PrintUsage(argv[0]);
                    goto out_free;
                }

                if (!ParseMountOptions(argv[i], &Options))
                {
                    result = ERROR_BAD_ARGUMENTS;
                    goto out_free;
                }
            }
            else
                _ftprintf(stderr, TEXT("Unrecognized option ")
                    TEXT("'%s', disregarding.\n"), argv[i]);
        }
        else if (pLocalName == NULL) /* drive letter */
        {
            pLocalName = argv[i];
        }
        else if (pRemoteName == NULL) /* remote path */
        {
            pRemoteName = argv[i];
        }
        else
            _ftprintf(stderr, TEXT("Unrecognized argument ")
                TEXT("'%s', disregarding.\n"), argv[i]);
    }

    /* validate local drive letter */
    if (pLocalName == NULL)
    {
        result = ERROR_BAD_ARGUMENTS;
        _ftprintf(stderr, TEXT("Missing argument for drive letter.\n\n"));
        PrintUsage(argv[0]);
        goto out_free;
    }
    if (FALSE == ParseDriveLetter(pLocalName, szLocalName))
    {
        result = ERROR_BAD_ARGUMENTS;
        _ftprintf(stderr, TEXT("Invalid drive letter '%s'. ")
            TEXT("Expected 'C' or 'C:'.\n\n"), pLocalName);
        PrintUsage(argv[0]);
        goto out_free;
    }

    if (bUnmount == TRUE) /* unmount */
    {
        result = DoUnmount(szLocalName, bForceUnmount);
        if (result)
            PrintErrorMessage(result);
    }
    else /* mount */
    {
        if (pRemoteName == NULL)
        {
            result = ERROR_BAD_NET_NAME;
            _ftprintf(stderr, TEXT("Missing argument for remote path.\n\n"));
            PrintUsage(argv[0]);
            goto out_free;
        }

        result = DoMount(szLocalName, pRemoteName, bPersistent, &Options);
        if (result)
            PrintErrorMessage(result);
    }

out_free:
    FreeMountOptions(&Options);
out:
    return result;
}

static void ConvertUnixSlashes(
    IN OUT LPTSTR pRemoteName)
{
    LPTSTR pos = pRemoteName;
    for (pos = pRemoteName; *pos; pos++)
        if (*pos == TEXT('/'))
            *pos = TEXT('\\');
}

static DWORD ParseRemoteName(
    IN LPTSTR pRemoteName,
    IN OUT PMOUNT_OPTION_LIST pOptions,
    OUT LPTSTR pConnectionName,
    IN size_t cchConnectionLen)
{
    DWORD result = NO_ERROR;
    LPTSTR pEnd;
    
    ConvertUnixSlashes(pRemoteName);

    /* fail if the server name doesn't end with :\ */
    pEnd = _tcsrchr(pRemoteName, TEXT(':'));
    if (pEnd == NULL || pEnd[1] != TEXT('\\')) {
        _ftprintf(stderr, TEXT("Failed to parse the remote path. ")
            TEXT("Expected 'hostname:\\path'.\n"));
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }
    *pEnd = TEXT('\0');
    ++pEnd;

    if (!InsertOption(TEXT("srvname"), pRemoteName, pOptions) ||
        !InsertOption(TEXT("mntpt"), *pEnd ? pEnd : TEXT("\\"), pOptions)) {
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }

    result = StringCchCopy(pConnectionName, cchConnectionLen, TEXT("\\\\"));
    if (FAILED(result))
        goto out;
    result = StringCbCat(pConnectionName, cchConnectionLen, pRemoteName);
    if (FAILED(result))
        goto out;
    if (*pEnd)
        result = StringCchCat(pConnectionName, cchConnectionLen, pEnd);

out:
    return result;
}

static DWORD DoMount(
    IN LPTSTR pLocalName,
    IN LPTSTR pRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions)
{
    DWORD result = NO_ERROR;
    TCHAR szExisting[MAX_PATH];
    TCHAR szRemoteName[MAX_PATH];
    DWORD dwLength;

    *szRemoteName = TEXT('\0');
    result = ParseRemoteName(pRemoteName, pOptions, szRemoteName, MAX_PATH);
    if (result)
        goto out;

    /* fail if the connection already exists */
    result = WNetGetConnection(pLocalName, (LPTSTR)szExisting, &dwLength);
    if (result == NO_ERROR)
    {
        result = ERROR_ALREADY_ASSIGNED;
        _ftprintf(stderr, TEXT("Mount failed, drive %s is ")
            TEXT("already assigned to '%s'.\n"),
            pLocalName, szExisting);
    }
    else
    {
        NETRESOURCE NetResource;
        TCHAR szConnection[MAX_PATH];
        DWORD ConnectSize = MAX_PATH, ConnectResult, Flags = 0;

        ZeroMemory(&NetResource, sizeof(NETRESOURCE));
        NetResource.dwType = RESOURCETYPE_DISK;
        /* drive letter is chosen automatically if lpLocalName == NULL */
        NetResource.lpLocalName = *pLocalName == TEXT('*') ? NULL : pLocalName;
        NetResource.lpRemoteName = szRemoteName;
        /* ignore other network providers */
        NetResource.lpProvider = TEXT(NFS41_PROVIDER_NAME_A);
        /* pass mount options via lpComment */
        if (pOptions->Buffer->Length)
        {
            if (pOptions->Current)
                pOptions->Current->NextEntryOffset = 0;
            NetResource.lpComment = (LPTSTR)pOptions->Buffer;
        }

        if (bPersistent)
            Flags |= CONNECT_UPDATE_PROFILE;

        result = WNetUseConnection(NULL,
            &NetResource, NULL, NULL, Flags,
            szConnection, &ConnectSize, &ConnectResult);

        if (result == NO_ERROR)
            _tprintf(TEXT("Successfully mounted %s to drive %s\n"),
                pRemoteName, szConnection);
        else
            _ftprintf(stderr, TEXT("WNetUseConnection(%s, %s) ")
                TEXT("failed with error code %u.\n"),
                pLocalName, szRemoteName, result);
    }

out:
    return result;
}

static DWORD DoUnmount(
    IN LPTSTR pLocalName,
    IN BOOL bForce)
{
    DWORD result;

    /* disconnect the specified local drive */
    result = WNetCancelConnection2(pLocalName, CONNECT_UPDATE_PROFILE, bForce);
    /* TODO: verify that this connection uses the nfs41 provider -cbodley */
    switch (result)
    {
    case NO_ERROR:
        _tprintf(TEXT("Drive %s unmounted successfully.\n"), pLocalName);
        break;
    case ERROR_NOT_CONNECTED:
        _ftprintf(stderr, TEXT("Drive %s is not currently ")
            TEXT("connected.\n"), pLocalName);
        break;
    default:
        _ftprintf(stderr, TEXT("WNetCancelConnection2(%s) failed ")
            TEXT("with error code %u.\n"), pLocalName, result);
        break;
    }
    return result;
}

static BOOL ParseDriveLetter(
    IN LPTSTR pArg,
    OUT PTCH pDriveLetter)
{
    /* accept 'C' or 'C:' */
    switch (_tcslen(pArg))
    {
    case 2:
        if (pArg[1] != TEXT(':'))
            return FALSE;
        /* break intentionally missing */
    case 1:
        if (_istlower(*pArg))
            *pArg = (TCHAR)_totupper(*pArg);
        else if (!_istupper(*pArg) && *pArg != TEXT('*'))
            return FALSE;

        *pDriveLetter = *pArg;
        return TRUE;
    }
    return FALSE;
}

void PrintErrorMessage(
    IN DWORD dwError)
{
    LPTSTR lpMsgBuf = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    _fputts(lpMsgBuf, stderr);
    LocalFree(lpMsgBuf);
}
