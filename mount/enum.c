/* Copyright (c) 2010
 * The Regents of the University of Michigan
 * All Rights Reserved
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
#include <tchar.h>
#include <stdio.h>

#include "nfs41_driver.h" /* NFS41_PROVIDER_NAME_A */


void PrintErrorMessage(
    IN DWORD dwError);

static __inline
void PrintMountLine(
    LPCTSTR local,
    LPCTSTR remote)
{
    _tprintf(TEXT("%-11s %s\n"), local, remote);
}

/* ENUM_RESOURCE_BUFFER_SIZE
 * from msdn re: WNetEnumResource
 *   "An application cannot set the lpBuffer parameter to NULL and
 * retrieve the required buffer size from the lpBufferSize parameter.
 * Instead, the application should allocate a buffer of a reasonable
 * size—16 kilobytes is typical—and use the value of lpBufferSize for
 * error detection." */
#define ENUM_RESOURCE_BUFFER_SIZE (16*1024)

DWORD EnumMounts(
    IN LPNETRESOURCE pContainer)
{
    DWORD result = NO_ERROR;
    LPNETRESOURCE pResources;
    DWORD i, dwCount, dwTotal = 0;
    DWORD dwBufferSize = ENUM_RESOURCE_BUFFER_SIZE;
    HANDLE hEnum;

    pResources = (LPNETRESOURCE)GlobalAlloc(0, ENUM_RESOURCE_BUFFER_SIZE);
    if (pResources == NULL) {
        result = WN_OUT_OF_MEMORY;
        goto out;
    }

    result = WNetOpenEnum(RESOURCE_CONNECTED,
        RESOURCETYPE_DISK, 0, pContainer, &hEnum);
    if (result)
        goto out_free;

    _tprintf(TEXT("Listing %s mounts:\n\n"), TEXT(NFS41_PROVIDER_NAME_A));
    PrintMountLine(TEXT("Volume"), TEXT("Remote path"));
    do
    {
        dwCount = (DWORD)-1;
        result = WNetEnumResource(hEnum,
            &dwCount, pResources, &dwBufferSize);

        if (result == NO_ERROR)
        {
            for (i = 0; i < dwCount; i++)
            {
                if (_tcscmp(pResources[i].lpProvider,
                    TEXT(NFS41_PROVIDER_NAME_A)) == 0)
                {
                    PrintMountLine(pResources[i].lpLocalName,
                        pResources[i].lpRemoteName);
                    dwTotal++;
                }
            }
        }
        else if (result != WN_NO_MORE_ENTRIES)
            break;
    }
    while (result != WN_NO_MORE_ENTRIES);

    result = WNetCloseEnum(hEnum);

    _tprintf(TEXT("\nFound %d share%s.\n"), dwTotal,
        dwTotal == 1 ? TEXT("") : TEXT("s"));

out_free:
    GlobalFree((HGLOBAL)pResources);
out:
    return result;
}