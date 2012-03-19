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

#ifndef __NFS41_MOUNT_OPTIONS_H__
#define __NFS41_MOUNT_OPTIONS_H__


#define MOUNT_OPTION_BUFFER_SECRET ('n4')

/* MOUNT_OPTION_BUFFER
 *   Buffer passed to the network provider via NETRESOURCE.lpComment.
 * To avoid interpreting a normal comment string as mount options, a
 * NULL and secret number are expected at the front. */
typedef struct _MOUNT_OPTION_BUFFER {
    USHORT  Zero; /* = 0 */
    USHORT  Secret; /* = 'n4' */
    ULONG   Length;
    CHAR    Buffer[1];
} MOUNT_OPTION_BUFFER, *PMOUNT_OPTION_BUFFER;


#ifndef FILE_FULL_EA_INFORMATION
/* from wdm.h
 * couldn't find a definition outside of the ddk -cbodley */
typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG   NextEntryOffset;
    UCHAR   Flags;
    UCHAR   EaNameLength;
    USHORT  EaValueLength;
    CHAR    EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
#endif

/* MOUNT_OPTION_LIST
 *   Used internally to encapsulate the formation of the
 * extended attribute buffer for mount options. */
typedef struct _MOUNT_OPTION_LIST {
    PMOUNT_OPTION_BUFFER Buffer;
    ULONG Remaining;
    PFILE_FULL_EA_INFORMATION Current;
} MOUNT_OPTION_LIST, *PMOUNT_OPTION_LIST;

/* allocate space for 8 full attributes, but limit options by
 * space rather than count. */
#define MAX_OPTION_EA_SIZE ( 8 * \
    (sizeof(FILE_FULL_EA_INFORMATION) + MAX_PATH) )

#define MAX_OPTION_BUFFER_SIZE ( sizeof(MOUNT_OPTION_BUFFER) + \
    MAX_OPTION_EA_SIZE - 1 )


/* options.c */
DWORD InitializeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options,
    IN ULONG BufferSize);

void FreeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options);

BOOL ParseMountOptions(
    IN LPTSTR Arg,
    IN OUT PMOUNT_OPTION_LIST Options);

BOOL InsertOption(
    IN LPCTSTR Name,
    IN LPCTSTR Value,
    IN OUT PMOUNT_OPTION_LIST Options);

#endif /* !__NFS41_MOUNT_OPTIONS_H__ */
