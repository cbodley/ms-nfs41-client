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

#include <windows.h>
#include <stdio.h>

#include "daemon_debug.h"
#include "from_kernel.h"
#include "nfs41_driver.h"
#include "nfs41_ops.h"


static int g_debug_level = DEFAULT_DEBUG_LEVEL;

void set_debug_level(int level) { g_debug_level = level; }

void dprintf(int level, LPCSTR format, ...)
{
    if (level <= g_debug_level) {
        va_list args;
        va_start(args, format);
        printf("%04x: ", GetCurrentThreadId());
        vprintf(format, args);
        va_end(args);
    }
}

void eprintf(LPCSTR format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%04x: ", GetCurrentThreadId());
    vfprintf(stderr, format, args);
    va_end(args);
}

void print_hexbuf(int level, unsigned char *title, unsigned char *buf, int len) 
{
    int j, k;
    if (level > g_debug_level) return;
    printf("%s", title);
    for(j = 0, k = 0; j < len; j++, k++) {
        printf("%02x '%c' ", buf[j], isascii(buf[j])? buf[j]:' ');
        if (((k+1) % 10 == 0 && k > 0)) {
            printf("\n");
        }
    }
    printf("\n");
}

void print_create_attributes(int level, DWORD create_opts) {
    if (level > g_debug_level) return;
    printf("create attributes: ");
    if (create_opts & FILE_DIRECTORY_FILE)
        printf("DIRECTORY_FILE ");
    if (create_opts & FILE_NON_DIRECTORY_FILE)
        printf("NON_DIRECTORY_FILE ");
    if (create_opts & FILE_WRITE_THROUGH)
        printf("WRITE_THROUGH ");
    if (create_opts & FILE_SEQUENTIAL_ONLY)
        printf("SEQUENTIAL_ONLY ");
    if (create_opts & FILE_RANDOM_ACCESS)
        printf("RANDOM_ACCESS ");
    if (create_opts & FILE_NO_INTERMEDIATE_BUFFERING)
        printf("NO_INTERMEDIATE_BUFFERING ");
    if (create_opts & FILE_SYNCHRONOUS_IO_ALERT)
        printf("SYNCHRONOUS_IO_ALERT ");
    if (create_opts & FILE_SYNCHRONOUS_IO_NONALERT)
        printf("SYNCHRONOUS_IO_NONALERT ");
    if (create_opts & FILE_CREATE_TREE_CONNECTION)
        printf("CREATE_TREE_CONNECTION ");
    if (create_opts & FILE_COMPLETE_IF_OPLOCKED)
        printf("COMPLETE_IF_OPLOCKED ");
    if (create_opts & FILE_NO_EA_KNOWLEDGE)
        printf("NO_EA_KNOWLEDGE ");
    if (create_opts & FILE_OPEN_REPARSE_POINT)
        printf("OPEN_REPARSE_POINT ");
    if (create_opts & FILE_DELETE_ON_CLOSE)
        printf("DELETE_ON_CLOSE ");
    if (create_opts & FILE_OPEN_BY_FILE_ID)
        printf("OPEN_BY_FILE_ID ");
    if (create_opts & FILE_OPEN_FOR_BACKUP_INTENT)
        printf("OPEN_FOR_BACKUP_INTENT ");
    if (create_opts & FILE_RESERVE_OPFILTER)
        printf("RESERVE_OPFILTER");
    printf("\n");
}

void print_disposition(int level, DWORD disposition) {
    if (level > g_debug_level) return;
    printf("userland disposition = ");
    if (disposition == FILE_SUPERSEDE)
        printf("FILE_SUPERSEDE\n");
    else if (disposition == FILE_CREATE)
        printf("FILE_CREATE\n");
    else if (disposition == FILE_OPEN)
        printf("FILE_OPEN\n");
    else if (disposition == FILE_OPEN_IF)
        printf("FILE_OPEN_IF\n");
    else if (disposition == FILE_OVERWRITE)
        printf("FILE_OVERWRITE\n");
    else if (disposition == FILE_OVERWRITE_IF)
        printf("FILE_OVERWRITE_IF\n");
}

void print_access_mask(int level, DWORD access_mask) {
    if (level > g_debug_level) return;
    printf("access mask: ");
    if (access_mask & FILE_READ_DATA)
        printf("READ ");
    if (access_mask & STANDARD_RIGHTS_READ)
        printf("READ_ACL ");
    if (access_mask & FILE_READ_ATTRIBUTES)
        printf("READ_ATTR ");
    if (access_mask & FILE_READ_EA)
        printf("READ_EA ");
    if (access_mask & FILE_WRITE_DATA)
        printf("WRITE ");
    if (access_mask & STANDARD_RIGHTS_WRITE)
        printf("WRITE_ACL ");
    if (access_mask & FILE_WRITE_ATTRIBUTES)
        printf("WRITE_ATTR ");
    if (access_mask & FILE_WRITE_EA)
        printf("WRITE_EA ");
    if (access_mask & FILE_APPEND_DATA)
        printf("APPEND ");
    if (access_mask & FILE_EXECUTE)
        printf("EXECUTE ");
    if (access_mask & FILE_LIST_DIRECTORY)
        printf("LIST ");
    if (access_mask & FILE_TRAVERSE)
        printf("TRAVERSE ");
    if (access_mask & SYNCHRONIZE)
        printf("SYNC ");
    if (access_mask & FILE_DELETE_CHILD)
        printf("DELETE_CHILD");
    printf("\n");
}

void print_share_mode(int level, DWORD mode)
{
    if (level > g_debug_level) return;
    printf("share mode: ");
    if (mode & FILE_SHARE_READ)
        printf("READ ");
    if (mode & FILE_SHARE_WRITE)
        printf("WRITE ");
    if (mode & FILE_SHARE_DELETE)
        printf("DELETE");
    printf("\n");
}

void print_file_id_both_dir_info(int level, FILE_ID_BOTH_DIR_INFO *pboth_dir_info)
{
    if (level > g_debug_level) return;
    printf("FILE_ID_BOTH_DIR_INFO %p %d\n", pboth_dir_info, sizeof(unsigned char *));
    printf("\tNextEntryOffset=%ld %d %d\n", pboth_dir_info->NextEntryOffset, sizeof(pboth_dir_info->NextEntryOffset), sizeof(DWORD));
    printf("\tFileIndex=%ld  %d\n", pboth_dir_info->FileIndex, sizeof(pboth_dir_info->FileIndex));
    printf("\tCreationTime=0x%x %d\n", pboth_dir_info->CreationTime.QuadPart, sizeof(pboth_dir_info->CreationTime));
    printf("\tLastAccessTime=0x%x %d\n", pboth_dir_info->LastAccessTime.QuadPart, sizeof(pboth_dir_info->LastAccessTime));
    printf("\tLastWriteTime=0x%x %d\n", pboth_dir_info->LastWriteTime.QuadPart, sizeof(pboth_dir_info->LastWriteTime));
    printf("\tChangeTime=0x%x %d\n", pboth_dir_info->ChangeTime.QuadPart, sizeof(pboth_dir_info->ChangeTime));
    printf("\tEndOfFile=0x%x %d\n", pboth_dir_info->EndOfFile.QuadPart, sizeof(pboth_dir_info->EndOfFile));
    printf("\tAllocationSize=0x%x %d\n", pboth_dir_info->AllocationSize.QuadPart, sizeof(pboth_dir_info->AllocationSize));
    printf("\tFileAttributes=%ld %d\n", pboth_dir_info->FileAttributes, sizeof(pboth_dir_info->FileAttributes));
    printf("\tFileNameLength=%ld %d\n", pboth_dir_info->FileNameLength, sizeof(pboth_dir_info->FileNameLength));
    printf("\tEaSize=%ld %d\n", pboth_dir_info->EaSize, sizeof(pboth_dir_info->EaSize));
    printf("\tShortNameLength=%d %d\n", pboth_dir_info->ShortNameLength, sizeof(pboth_dir_info->ShortNameLength));
    printf("\tShortName='%S' %d\n", pboth_dir_info->ShortName, sizeof(pboth_dir_info->ShortName));
    printf("\tFileId=0x%x %d\n", pboth_dir_info->FileId.QuadPart, sizeof(pboth_dir_info->FileId));
    printf("\tFileName='%S' %p\n", pboth_dir_info->FileName, pboth_dir_info->FileName);
}

void print_opcode(int level, DWORD opcode) 
{
    dprintf(level, (LPCSTR)opcode2string(opcode));
}

const char* opcode2string(DWORD opcode)
{
    switch(opcode) {
    case NFS41_SHUTDOWN:    return "NFS41_SHUTDOWN";
    case NFS41_MOUNT:       return "NFS41_MOUNT";
    case NFS41_UNMOUNT:     return "NFS41_UNMOUNT";
    case NFS41_OPEN:        return "NFS41_OPEN";
    case NFS41_CLOSE:       return "NFS41_CLOSE";
    case NFS41_READ:        return "NFS41_READ";
    case NFS41_WRITE:       return "NFS41_WRITE";
    case NFS41_LOCK:        return "NFS41_LOCK";
    case NFS41_UNLOCK:      return "NFS41_UNLOCK";
    case NFS41_DIR_QUERY:   return "NFS41_DIR_QUERY";
    case NFS41_FILE_QUERY:  return "NFS41_FILE_QUERY";
    case NFS41_FILE_SET:    return "NFS41_FILE_SET";
    case NFS41_EA_SET:      return "NFS41_EA_SET";
    case NFS41_VOLUME_QUERY: return "NFS41_VOLUME_QUERY";
    default:                return "UNKNOWN";
    }
}

const char* nfs_opnum_to_string(int opnum)
{
    switch (opnum)
    {
    case OP_ACCESS: return "ACCESS";
    case OP_CLOSE: return "CLOSE";
    case OP_COMMIT: return "COMMIT";
    case OP_CREATE: return "CREATE";
    case OP_DELEGPURGE: return "DELEGPURGE";
    case OP_DELEGRETURN: return "DELEGRETURN";
    case OP_GETATTR: return "GETATTR";
    case OP_GETFH: return "GETFH";
    case OP_LINK: return "LINK";
    case OP_LOCK: return "LOCK";
    case OP_LOCKT: return "LOCKT";
    case OP_LOCKU: return "LOCKU";
    case OP_LOOKUP: return "LOOKUP";
    case OP_LOOKUPP: return "LOOKUPP";
    case OP_NVERIFY: return "NVERIFY";
    case OP_OPEN: return "OPEN";
    case OP_OPENATTR: return "OPENATTR";
    case OP_OPEN_CONFIRM: return "OPEN_CONFIRM";
    case OP_OPEN_DOWNGRADE: return "OPEN_DOWNGRADE";
    case OP_PUTFH: return "PUTFH";
    case OP_PUTPUBFH: return "PUTPUBFH";
    case OP_PUTROOTFH: return "PUTROOTFH";
    case OP_READ: return "READ";
    case OP_READDIR: return "READDIR";
    case OP_READLINK: return "READLINK";
    case OP_REMOVE: return "REMOVE";
    case OP_RENAME: return "RENAME";
    case OP_RENEW: return "RENEW";
    case OP_RESTOREFH: return "RESTOREFH";
    case OP_SAVEFH: return "SAVEFH";
    case OP_SECINFO: return "SECINFO";
    case OP_SETATTR: return "SETATTR";
    case OP_SETCLIENTID: return "SETCLIENTID";
    case OP_SETCLIENTID_CONFIRM: return "SETCLIENTID_CONFIRM";
    case OP_VERIFY: return "VERIFY";
    case OP_WRITE: return "WRITE";
    case OP_RELEASE_LOCKOWNER: return "RELEASE_LOCKOWNER";
    case OP_BACKCHANNEL_CTL: return "BACKCHANNEL_CTL";
    case OP_BIND_CONN_TO_SESSION: return "BIND_CONN_TO_SESSION";
    case OP_EXCHANGE_ID: return "EXCHANGE_ID";
    case OP_CREATE_SESSION: return "CREATE_SESSION";
    case OP_DESTROY_SESSION: return "DESTROY_SESSION";
    case OP_FREE_STATEID: return "FREE_STATEID";
    case OP_GET_DIR_DELEGATION: return "GET_DIR_DELEGATION";
    case OP_GETDEVICEINFO: return "GETDEVICEINFO";
    case OP_GETDEVICELIST: return "GETDEVICELIST";
    case OP_LAYOUTCOMMIT: return "LAYOUTCOMMIT";
    case OP_LAYOUTGET: return "LAYOUTGET";
    case OP_LAYOUTRETURN: return "LAYOUTRETURN";
    case OP_SECINFO_NO_NAME: return "SECINFO_NO_NAME";
    case OP_SEQUENCE: return "SEQUENCE";
    case OP_SET_SSV: return "SET_SSV";
    case OP_TEST_STATEID: return "TEST_STATEID";
    case OP_WANT_DELEGATION: return "WANT_DELEGATION";
    case OP_DESTROY_CLIENTID: return "DESTROY_CLIENTID";
    case OP_RECLAIM_COMPLETE: return "RECLAIM_COMPLETE";
    case OP_ILLEGAL: return "ILLEGAL";
    default: return "invalid nfs opnum";
    }
}

const char* nfs_error_string(int status)
{
    switch (status)
    {
    case NFS4_OK: return "NFS4_OK";
    case NFS4ERR_PERM: return "NFS4ERR_PERM";
    case NFS4ERR_NOENT: return "NFS4ERR_NOENT";
    case NFS4ERR_IO: return "NFS4ERR_IO";
    case NFS4ERR_NXIO: return "NFS4ERR_NXIO";
    case NFS4ERR_ACCESS: return "NFS4ERR_ACCESS";
    case NFS4ERR_EXIST: return "NFS4ERR_EXIST";
    case NFS4ERR_XDEV: return "NFS4ERR_XDEV";
    case NFS4ERR_NOTDIR: return "NFS4ERR_NOTDIR";
    case NFS4ERR_ISDIR: return "NFS4ERR_ISDIR";
    case NFS4ERR_INVAL: return "NFS4ERR_INVAL";
    case NFS4ERR_FBIG: return "NFS4ERR_FBIG";
    case NFS4ERR_NOSPC: return "NFS4ERR_NOSPC";
    case NFS4ERR_ROFS: return "NFS4ERR_ROFS";
    case NFS4ERR_MLINK: return "NFS4ERR_MLINK";
    case NFS4ERR_NAMETOOLONG: return "NFS4ERR_NAMETOOLONG";
    case NFS4ERR_NOTEMPTY: return "NFS4ERR_NOTEMPTY";
    case NFS4ERR_DQUOT: return "NFS4ERR_DQUOT";
    case NFS4ERR_STALE: return "NFS4ERR_STALE";
    case NFS4ERR_BADHANDLE: return "NFS4ERR_BADHANDLE";
    case NFS4ERR_BAD_COOKIE: return "NFS4ERR_BAD_COOKIE";
    case NFS4ERR_NOTSUPP: return "NFS4ERR_NOTSUPP";
    case NFS4ERR_TOOSMALL: return "NFS4ERR_TOOSMALL";
    case NFS4ERR_SERVERFAULT: return "NFS4ERR_SERVERFAULT";
    case NFS4ERR_BADTYPE: return "NFS4ERR_BADTYPE";
    case NFS4ERR_DELAY: return "NFS4ERR_DELAY";
    case NFS4ERR_SAME: return "NFS4ERR_SAME";
    case NFS4ERR_DENIED: return "NFS4ERR_DENIED";
    case NFS4ERR_EXPIRED: return "NFS4ERR_EXPIRED";
    case NFS4ERR_LOCKED: return "NFS4ERR_LOCKED";
    case NFS4ERR_GRACE: return "NFS4ERR_GRACE";
    case NFS4ERR_FHEXPIRED: return "NFS4ERR_FHEXPIRED";
    case NFS4ERR_SHARE_DENIED: return "NFS4ERR_SHARE_DENIED";
    case NFS4ERR_WRONGSEC: return "NFS4ERR_WRONGSEC";
    case NFS4ERR_CLID_INUSE: return "NFS4ERR_CLID_INUSE";
    case NFS4ERR_RESOURCE: return "NFS4ERR_RESOURCE";
    case NFS4ERR_MOVED: return "NFS4ERR_MOVED";
    case NFS4ERR_NOFILEHANDLE: return "NFS4ERR_NOFILEHANDLE";
    case NFS4ERR_MINOR_VERS_MISMATCH: return "NFS4ERR_MINOR_VERS_MISMATCH";
    case NFS4ERR_STALE_CLIENTID: return "NFS4ERR_STALE_CLIENTID";
    case NFS4ERR_STALE_STATEID: return "NFS4ERR_STALE_STATEID";
    case NFS4ERR_OLD_STATEID: return "NFS4ERR_OLD_STATEID";
    case NFS4ERR_BAD_STATEID: return "NFS4ERR_BAD_STATEID";
    case NFS4ERR_BAD_SEQID: return "NFS4ERR_BAD_SEQID";
    case NFS4ERR_NOT_SAME: return "NFS4ERR_NOT_SAME";
    case NFS4ERR_LOCK_RANGE: return "NFS4ERR_LOCK_RANGE";
    case NFS4ERR_SYMLINK: return "NFS4ERR_SYMLINK";
    case NFS4ERR_RESTOREFH: return "NFS4ERR_RESTOREFH";
    case NFS4ERR_LEASE_MOVED: return "NFS4ERR_LEASE_MOVED";
    case NFS4ERR_ATTRNOTSUPP: return "NFS4ERR_ATTRNOTSUPP";
    case NFS4ERR_NO_GRACE: return "NFS4ERR_NO_GRACE";
    case NFS4ERR_RECLAIM_BAD: return "NFS4ERR_RECLAIM_BAD";
    case NFS4ERR_RECLAIM_CONFLICT: return "NFS4ERR_RECLAIM_CONFLICT";
    case NFS4ERR_BADXDR: return "NFS4ERR_BADXDR";
    case NFS4ERR_LOCKS_HELD: return "NFS4ERR_LOCKS_HELD";
    case NFS4ERR_OPENMODE: return "NFS4ERR_OPENMODE";
    case NFS4ERR_BADOWNER: return "NFS4ERR_BADOWNER";
    case NFS4ERR_BADCHAR: return "NFS4ERR_BADCHAR";
    case NFS4ERR_BADNAME: return "NFS4ERR_BADNAME";
    case NFS4ERR_BAD_RANGE: return "NFS4ERR_BAD_RANGE";
    case NFS4ERR_LOCK_NOTSUPP: return "NFS4ERR_LOCK_NOTSUPP";
    case NFS4ERR_OP_ILLEGAL: return "NFS4ERR_OP_ILLEGAL";
    case NFS4ERR_DEADLOCK: return "NFS4ERR_DEADLOCK";
    case NFS4ERR_FILE_OPEN: return "NFS4ERR_FILE_OPEN";
    case NFS4ERR_ADMIN_REVOKED: return "NFS4ERR_ADMIN_REVOKED";
    case NFS4ERR_CB_PATH_DOWN: return "NFS4ERR_CB_PATH_DOWN";
    case NFS4ERR_BADIOMODE: return "NFS4ERR_BADIOMODE";
    case NFS4ERR_BADLAYOUT: return "NFS4ERR_BADLAYOUT";
    case NFS4ERR_BAD_SESSION_DIGEST: return "NFS4ERR_BAD_SESSION_DIGEST";
    case NFS4ERR_BADSESSION: return "NFS4ERR_BADSESSION";
    case NFS4ERR_BADSLOT: return "NFS4ERR_BADSLOT";
    case NFS4ERR_COMPLETE_ALREADY: return "NFS4ERR_COMPLETE_ALREADY";
    case NFS4ERR_CONN_NOT_BOUND_TO_SESSION: return "NFS4ERR_CONN_NOT_BOUND_TO_SESSION";
    case NFS4ERR_DELEG_ALREADY_WANTED: return "NFS4ERR_DELEG_ALREADY_WANTED";
    case NFS4ERR_BACK_CHAN_BUSY: return "NFS4ERR_BACK_CHAN_BUSY";
    case NFS4ERR_LAYOUTTRYLATER: return "NFS4ERR_LAYOUTTRYLATER";
    case NFS4ERR_LAYOUTUNAVAILABLE: return "NFS4ERR_LAYOUTUNAVAILABLE";
    case NFS4ERR_NOMATCHING_LAYOUT: return "NFS4ERR_NOMATCHING_LAYOUT";
    case NFS4ERR_RECALLCONFLICT: return "NFS4ERR_RECALLCONFLICT";
    case NFS4ERR_UNKNOWN_LAYOUTTYPE: return "NFS4ERR_UNKNOWN_LAYOUTTYPE";
    case NFS4ERR_SEQ_MISORDERED: return "NFS4ERR_SEQ_MISORDERED";
    case NFS4ERR_SEQUENCE_POS: return "NFS4ERR_SEQUENCE_POS";
    case NFS4ERR_REQ_TOO_BIG: return "NFS4ERR_REQ_TOO_BIG";
    case NFS4ERR_REP_TOO_BIG: return "NFS4ERR_REP_TOO_BIG";
    case NFS4ERR_REP_TOO_BIG_TO_CACHE: return "NFS4ERR_REP_TOO_BIG_TO_CACHE";
    case NFS4ERR_RETRY_UNCACHED_REP: return "NFS4ERR_RETRY_UNCACHED_REP";
    case NFS4ERR_UNSAFE_COMPOUND: return "NFS4ERR_UNSAFE_COMPOUND";
    case NFS4ERR_TOO_MANY_OPS: return "NFS4ERR_TOO_MANY_OPS";
    case NFS4ERR_OP_NOT_IN_SESSION: return "NFS4ERR_OP_NOT_IN_SESSION";
    case NFS4ERR_HASH_ALG_UNSUPP: return "NFS4ERR_HASH_ALG_UNSUPP";
    case NFS4ERR_CLIENTID_BUSY: return "NFS4ERR_CLIENTID_BUSY";
    case NFS4ERR_PNFS_IO_HOLE: return "NFS4ERR_PNFS_IO_HOLE";
    case NFS4ERR_SEQ_FALSE_RETRY: return "NFS4ERR_SEQ_FALSE_RETRY";
    case NFS4ERR_BAD_HIGH_SLOT: return "NFS4ERR_BAD_HIGH_SLOT";
    case NFS4ERR_DEADSESSION: return "NFS4ERR_DEADSESSION";
    case NFS4ERR_ENCR_ALG_UNSUPP: return "NFS4ERR_ENCR_ALG_UNSUPP";
    case NFS4ERR_PNFS_NO_LAYOUT: return "NFS4ERR_PNFS_NO_LAYOUT";
    case NFS4ERR_NOT_ONLY_OP: return "NFS4ERR_NOT_ONLY_OP";
    case NFS4ERR_WRONG_CRED: return "NFS4ERR_WRONG_CRED";
    case NFS4ERR_WRONG_TYPE: return "NFS4ERR_WRONG_TYPE";
    case NFS4ERR_DIRDELEG_UNAVAIL: return "NFS4ERR_DIRDELEG_UNAVAIL";
    case NFS4ERR_REJECT_DELEG: return "NFS4ERR_REJECT_DELEG";
    case NFS4ERR_RETURNCONFLICT: return "NFS4ERR_RETURNCONFLICT";
    case NFS4ERR_DELEG_REVOKED: return "NFS4ERR_DELEG_REVOKED";
    default: return "invalid nfs error code";
    }
}

void print_condwait_status(int level, int status)
{
    if (level > g_debug_level) return;
    switch(status) {
        case WAIT_ABANDONED: printf("WAIT_ABANDONED\n"); break;
        case WAIT_OBJECT_0: printf("WAIT_OBJECT_0\n"); break;
        case WAIT_TIMEOUT: printf("WAIT_TIMEOUT\n"); break;
        case WAIT_FAILED: printf("WAIT_FAILED %d\n", GetLastError());
        default: printf("unknown status =%d\n", status);
    }
}

void print_sr_status_flags(int level, int flags)
{
    if (level > g_debug_level) return;
    printf("%04x: sr_status_flags: ", GetCurrentThreadId());
    if (flags & SEQ4_STATUS_CB_PATH_DOWN) 
        printf("SEQ4_STATUS_CB_PATH_DOWN ");
    if (flags & SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING) 
        printf("SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING ");
    if (flags & SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED) 
        printf("SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED ");
    if (flags & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED) 
        printf("SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED) 
        printf("SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_ADMIN_STATE_REVOKED) 
        printf("SEQ4_STATUS_ADMIN_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED) 
        printf("SEQ4_STATUS_RECALLABLE_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_LEASE_MOVED) 
        printf("SEQ4_STATUS_LEASE_MOVED ");
    if (flags & SEQ4_STATUS_RESTART_RECLAIM_NEEDED) 
        printf("SEQ4_STATUS_RESTART_RECLAIM_NEEDED ");
    if (flags & SEQ4_STATUS_CB_PATH_DOWN_SESSION) 
        printf("SEQ4_STATUS_CB_PATH_DOWN_SESSION ");
    if (flags & SEQ4_STATUS_BACKCHANNEL_FAULT) 
        printf("SEQ4_STATUS_BACKCHANNEL_FAULT ");
    if (flags & SEQ4_STATUS_DEVID_CHANGED) 
        printf("SEQ4_STATUS_DEVID_CHANGED ");
    if (flags & SEQ4_STATUS_DEVID_DELETED) 
        printf("SEQ4_STATUS_DEVID_DELETED ");
    printf("\n");
}
