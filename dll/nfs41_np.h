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

#ifndef __NFS41_NP_H__
#define __NFS41_NP_H__

#define NFS41NP_MUTEX_NAME  "NFS41NPMUTEX"

#define NFS41NP_MAX_DEVICES 26

typedef struct __NFS41NP_NETRESOURCE {
    BOOL    InUse;
    USHORT  LocalNameLength;
    USHORT  RemoteNameLength;
    USHORT  ConnectionNameLength;
    DWORD   dwScope;
    DWORD   dwType;
    DWORD   dwDisplayType;
    DWORD   dwUsage;
    WCHAR   LocalName[MAX_PATH];
    WCHAR   RemoteName[MAX_PATH];
    WCHAR   ConnectionName[MAX_PATH];
    WCHAR   Options[MAX_PATH];
} NFS41NP_NETRESOURCE, *PNFS41NP_NETRESOURCE;

typedef struct __NFS41NP_SHARED_MEMORY {
    INT                 NextAvailableIndex;
    INT                 NumberOfResourcesInUse;
    NFS41NP_NETRESOURCE NetResources[NFS41NP_MAX_DEVICES];
} NFS41NP_SHARED_MEMORY, *PNFS41NP_SHARED_MEMORY;

#endif /* !__NFS41_NP_H__ */
