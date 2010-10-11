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

#ifndef __NFS41_NP_OPTIONS_H__
#define __NFS41_NP_OPTIONS_H__


#define MOUNT_OPTION_BUFFER_SECRET ('n4')

/* MOUNT_OPTION_BUFFER
 *   The mount options buffer received by NPAddConnection3
 * via NETRESOURCE.lpComment. To avoid interpreting a normal
 * comment string as mount options, a NULL and secret number
 * are expected at the front. */
typedef struct _MOUNT_OPTION_BUFFER {
	USHORT	Zero;	/* = 0 */
	USHORT	Secret;	/* = 'n4' */
	ULONG	Length;
	BYTE	Buffer[1];
} MOUNT_OPTION_BUFFER, *PMOUNT_OPTION_BUFFER;

/* CONNECTION_BUFFER
 *   The connection information as sent to the driver via
 * IOCTL_NFS41_ADDCONN. The buffer contains the connection name
 * followed by any extended attributes for mount options. */
typedef struct _CONNECTION_BUFFER {
	USHORT	NameLength;	/* length of connection filename */
	USHORT	EaPadding;	/* 0-3 bytes of padding to put EaBuffer
						 * on a ULONG boundary */
	ULONG	EaLength;	/* length of EaBuffer */
	BYTE	Buffer[1];
} CONNECTION_BUFFER, *PCONNECTION_BUFFER;

/* CONNECTION_INFO
 *   Used in NPAddConnection3 to encapsulate the formation of
 * the connection buffer. */
typedef struct _CONNECTION_INFO {
	PMOUNT_OPTION_BUFFER	Options;
	ULONG					BufferSize;
	PCONNECTION_BUFFER		Buffer;
} CONNECTION_INFO, *PCONNECTION_INFO;

#define MAX_CONNECTION_BUFFER_SIZE(EaSize) ( \
	sizeof(CONNECTION_BUFFER) + MAX_PATH + (EaSize) )


/* options.c */
DWORD InitializeConnectionInfo(
	IN OUT PCONNECTION_INFO Connection,
	IN PMOUNT_OPTION_BUFFER Options,
	OUT LPWSTR *ConnectionName);

void FreeConnectionInfo(
	IN OUT PCONNECTION_INFO Connection);

/* MarshallConnectionInfo
 *   Prepares the CONNECTION_BUFFER for transmission to the driver
 * by copying the extended attributes into place and updating the
 * lengths accordingly. */
void MarshalConnectionInfo(
	IN OUT PCONNECTION_INFO Connection);


#endif /* !__NFS41_NP_OPTIONS_H__ */
