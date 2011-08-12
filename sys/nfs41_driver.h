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

#ifndef _NFS41_DRIVER_
#define _NFS41_DRIVER_

#define NFS41_DEVICE_NAME L"\\Device\\nfs41_driver"
#define NFS41_SHADOW_DEVICE_NAME L"\\??\\nfs41_driver"
#define NFS41_USER_DEVICE_NAME L"\\\\.\\nfs41_driver"
#define NFS41_USER_DEVICE_NAME_A "\\\\.\\nfs41_driver"
#define NFS41_PROVIDER_NAME_A "NFS41 Network"
#define NFS41_PROVIDER_NAME_U L"NFS41 Network"

#define NFS41_PIPE_NAME L"\\Device\\nfs41_pipe"
#define NFS41_SHADOW_PIPE_NAME L"\\??\\nfs41_pipe"
#define NFS41_USER_PIPE_NAME L"\\\\.\\nfs41_pipe"

#define NFS41_SHARED_MEMORY_NAME L"\\BaseNamedObjects\\nfs41_shared_memory"
#define NFS41_USER_SHARED_MEMORY_NAME "Global\\nfs41_shared_memory"

// See "Defining I/O Control Codes" in WDK docs
#define _RDR_CTL_CODE(code, method) \
    CTL_CODE(FILE_DEVICE_NETWORK_REDIRECTOR, 0x800 | (code), method, FILE_ANY_ACCESS)

#define IOCTL_NFS41_START       _RDR_CTL_CODE(0, METHOD_BUFFERED)
#define IOCTL_NFS41_STOP        _RDR_CTL_CODE(1, METHOD_NEITHER)
#define IOCTL_NFS41_GETSTATE    _RDR_CTL_CODE(3, METHOD_NEITHER)
#define IOCTL_NFS41_ADDCONN     _RDR_CTL_CODE(4, METHOD_BUFFERED)
#define IOCTL_NFS41_DELCONN     _RDR_CTL_CODE(5, METHOD_BUFFERED)
#define IOCTL_NFS41_READ        _RDR_CTL_CODE(6, METHOD_BUFFERED)
#define IOCTL_NFS41_WRITE       _RDR_CTL_CODE(7, METHOD_BUFFERED)
#define IOCTL_NFS41_INVALCACHE  _RDR_CTL_CODE(8, METHOD_BUFFERED)

typedef enum _nfs41_opcodes {
    NFS41_MOUNT,
    NFS41_UNMOUNT,
    NFS41_OPEN,
    NFS41_CLOSE,
    NFS41_READ,
    NFS41_WRITE,
    NFS41_LOCK,
    NFS41_UNLOCK,
    NFS41_DIR_QUERY,
    NFS41_FILE_QUERY,
    NFS41_FILE_SET,
    NFS41_EA_SET,
    NFS41_SYMLINK,
    NFS41_VOLUME_QUERY,
    NFS41_ACL_QUERY,
    NFS41_ACL_SET,
    NFS41_SHUTDOWN,
    INVALID_OPCODE
} nfs41_opcodes;

enum rpcsec_flavors {
    RPCSEC_AUTH_SYS,
    RPCSEC_AUTHGSS_KRB5,
    RPCSEC_AUTHGSS_KRB5I,
    RPCSEC_AUTHGSS_KRB5P
};

typedef enum _nfs41_init_driver_state {
   NFS41_INIT_DRIVER_STARTABLE,
   NFS41_INIT_DRIVER_START_IN_PROGRESS,
   NFS41_INIT_DRIVER_STARTED
} nfs41_init_driver_state;

typedef enum _nfs41_start_driver_state {
   NFS41_START_DRIVER_STARTABLE,
   NFS41_START_DRIVER_START_IN_PROGRESS,
   NFS41_START_DRIVER_STARTED,
   NFS41_START_DRIVER_STOPPED
} nfs41_start_driver_state;
#endif
