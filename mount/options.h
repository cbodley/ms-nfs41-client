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
