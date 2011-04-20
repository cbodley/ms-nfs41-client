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

#define MINIRDR__NAME "Value is ignored, only fact of definition"
#include <rx.h>
#include <windef.h>
#include <winerror.h>

#include <Ntstrsafe.h>

#include "nfs41_driver.h"
#include "nfs41_np.h"
#include "nfs41_debug.h"

//#define DEBUG_CLOSE

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD nfs41_driver_unload;
DRIVER_DISPATCH ( nfs41_FsdDispatch );

struct _MINIRDR_DISPATCH nfs41_ops;
PRDBSS_DEVICE_OBJECT nfs41_dev;

#define FCB_BASIC_INFO_CACHED 0x0001
#define FCB_STANDARD_INFO_CACHED 0x0010

#define DISABLE_CACHING 0
#define ENABLE_READ_CACHING 1
#define ENABLE_WRITE_CACHING 2
#define ENABLE_READWRITE_CACHING 3

#define NFS41_MM_POOLTAG        ('nfs4')

KEVENT upcallEvent;
FAST_MUTEX upcallLock, downcallLock;
FAST_MUTEX xidLock;
FAST_MUTEX openOwnerLock;

ULONG xid = 0;
ULONG open_owner_id = 1;

#define DECLARE_CONST_ANSI_STRING(_var, _string) \
    const CHAR _var ## _buffer[] = _string; \
    const ANSI_STRING _var = { sizeof(_string) - sizeof(CHAR), \
        sizeof(_string), (PCH) _var ## _buffer }

DECLARE_CONST_ANSI_STRING(NfsV3Attributes, "NfsV3Attributes");
DECLARE_CONST_ANSI_STRING(NfsSymlinkTargetName, "NfsSymlinkTargetName");
DECLARE_CONST_ANSI_STRING(NfsActOnLink, "NfsActOnLink");

static INLINE BOOL AnsiStrEq(
    IN const ANSI_STRING *lhs,
    IN const CHAR *rhs,
    IN const UCHAR rhs_len)
{
    return lhs->Length == rhs_len &&
        RtlCompareMemory(lhs->Buffer, rhs, rhs_len) == rhs_len;
}

typedef struct _nfs3_attrs {
    DWORD type, mode, nlink, uid, gid, filler1;
    LARGE_INTEGER size, used;
    struct {
        DWORD specdata1;
        DWORD specdata2;
    } rdev;
    LONGLONG fsid, fileid;
    LONGLONG atime, mtime, ctime;
} nfs3_attrs;
LARGE_INTEGER unix_time_diff; //needed to convert windows time to unix

enum ftype3 {
    NF3REG = 1,
    NF3DIR,
    NF3BLK,
    NF3CHR,
    NF3LNK,
    NF3SOCK,
    NF3FIFO
};

typedef enum _nfs41_updowncall_state {
   NFS41_WAITING_FOR_UPCALL,
   NFS41_WAITING_FOR_DOWNCALL,
   NFS41_DONE_PROCESSING,
   NFS41_NOT_WAITING
} nfs41_updowncall_state;

typedef struct _updowncall_entry {
    DWORD version;
    DWORD xid;
    DWORD opcode;
    NTSTATUS status;
    nfs41_updowncall_state state;
    FAST_MUTEX lock;
    LIST_ENTRY next;
    KEVENT cond;
    DWORD errno;
    BOOLEAN async_op;
    SECURITY_CLIENT_CONTEXT sec_ctx;
    PSECURITY_CLIENT_CONTEXT psec_ctx;
    HANDLE open_state;
    HANDLE session;
    union {
        struct {
            PUNICODE_STRING srv_name;
            PUNICODE_STRING root;
            DWORD sec_flavor;
        } Mount;
        struct {                       
            PMDL MdlAddress;
            PVOID buf;
            LONGLONG offset;
            ULONG len;
            PRX_CONTEXT rxcontext;
        } ReadWrite;
        struct {
            LONGLONG offset;
            LONGLONG length;
            BOOLEAN exclusive;
            BOOLEAN blocking;
        } Lock;
        struct {
            ULONG count;
            LOWIO_LOCK_LIST locks;
        } Unlock;
        struct {
            FILE_BASIC_INFORMATION binfo;
            FILE_STANDARD_INFORMATION sinfo;
            PUNICODE_STRING filename;
            UNICODE_STRING symlink;
            ULONG access_mask;
            ULONG access_mode;
            ULONG attrs;
            ULONG copts;
            ULONG disp;
            ULONG cattrs;
            ULONG open_owner_id;
            DWORD mode;
            LONGLONG changeattr;
            BOOLEAN symlink_embedded;
        } Open;
        struct {
            PUNICODE_STRING filename;
            BOOLEAN remove;
            BOOLEAN renamed;
        } Close;
        struct {
            PUNICODE_STRING filter;
            PVOID buf;
            ULONG buf_len;
            FILE_INFORMATION_CLASS InfoClass;
            BOOLEAN restart_scan;
            BOOLEAN return_single;
            BOOLEAN initial_query;
        } QueryFile;
        struct {
            PUNICODE_STRING filename;
            PVOID buf;
            ULONG buf_len;
            FILE_INFORMATION_CLASS InfoClass;
            ULONG open_owner_id;
            ULONG access_mask;
            ULONG access_mode;
        } SetFile;
        struct {
            DWORD mode;
        } SetEa;
        struct {
            PUNICODE_STRING filename;
            PUNICODE_STRING target;
            BOOLEAN set;
        } Symlink;
        struct {
            FS_INFORMATION_CLASS query;
            PVOID buf;
            LONG buf_len;
        } Volume;
        struct {
            SECURITY_INFORMATION query;
            PVOID buf;
            DWORD buf_len;
        } Acl;
    } u;

} nfs41_updowncall_entry;

typedef struct _updowncall_list {
    LIST_ENTRY head;
} nfs41_updowncall_list;
nfs41_updowncall_list *upcall = NULL, *downcall = NULL;

#define nfs41_AddEntry(lock,pList,pEntry)                   \
            ExAcquireFastMutex(&lock);                      \
            InsertTailList(&pList->head, &(pEntry)->next);  \
            ExReleaseFastMutex(&lock);
#define nfs41_RemoveFirst(lock,pList,pEntry)                \
            ExAcquireFastMutex(&lock);                      \
            pEntry = (IsListEmpty(&pList->head)             \
            ? NULL                                          \
            : RemoveHeadList(&pList->head));                 \
            ExReleaseFastMutex(&lock);
#define nfs41_RemoveLast(lock,pList,pEntry)                 \
            ExAcquireFastMutex(&lock);                      \
            pEntry = RemoveTailList(&pList->head);          \
            ExReleaseFastMutex(&lock);
#define nfs41_RemoveEntry(lock,pList,pEntry)                \
            ExAcquireFastMutex(&lock);                      \
            RemoveEntryList(&pEntry->next);                 \
            ExReleaseFastMutex(&lock);                      
#define nfs41_IsListEmpty(lock,pList,flag)                  \
            ExAcquireFastMutex(&lock);                      \
            *flag = IsListEmpty(&pList->head);              \
            ExReleaseFastMutex(&lock);
#define nfs41_GetFirstEntry(lock,pList,pEntry)              \
            ExAcquireFastMutex(&lock);                      \
            pEntry = (IsListEmpty(&pList->head)             \
             ? NULL                                         \
             : (nfs41_updowncall_entry *)                   \
               (CONTAINING_RECORD(pList->head.Flink,        \
                                  nfs41_updowncall_entry,   \
                                  next)));                  \
            ExReleaseFastMutex(&lock);
#define nfs41_GetNextEntry(pList,pEntry)                    \
            ((pEntry->next.Flink == &pList->head)           \
             ? NULL                                         \
             : (nfs41_updowncall_entry *)                   \
               (CONTAINING_RECORD(pEntry->next.Flink,       \
                                  nfs41_updowncall_entry,   \
                                  next)));

/* In order to cooperate with other network providers,
 * we only claim paths of the format '\\server\nfs4\path' */
DECLARE_CONST_UNICODE_STRING(NfsPrefix, L"\\nfs4");
DECLARE_CONST_UNICODE_STRING(AUTH_SYS_NAME, L"sys");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5_NAME, L"krb5");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5I_NAME, L"krb5i");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5P_NAME, L"krb5p");

#define SERVER_NAME_BUFFER_SIZE     1024

#define MOUNT_CONFIG_RW_SIZE_MIN        1024
#define MOUNT_CONFIG_RW_SIZE_DEFAULT    32768
#define MOUNT_CONFIG_RW_SIZE_MAX        65536
#define MAX_SEC_FLAVOR_LEN 12

typedef struct _NFS41_MOUNT_CONFIG {
    DWORD ReadSize;
    DWORD WriteSize;
    BOOLEAN ReadOnly;
    WCHAR srv_buffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING SrvName;
    WCHAR mntpt_buffer[MAX_PATH];
    UNICODE_STRING MntPt;
    WCHAR sec_flavor[MAX_SEC_FLAVOR_LEN];
    UNICODE_STRING SecFlavor;
} NFS41_MOUNT_CONFIG, *PNFS41_MOUNT_CONFIG;

typedef struct _NFS41_NETROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    HANDLE                  auth_sys_session;
    HANDLE                  gss_session;
    DWORD                   nfs41d_version;
    BOOLEAN                 do_umount;
} NFS41_NETROOT_EXTENSION, *PNFS41_NETROOT_EXTENSION;
#define NFS41GetNetRootExtension(pNetRoot)      \
        (((pNetRoot) == NULL) ? NULL : (PNFS41_NETROOT_EXTENSION)((pNetRoot)->Context))

/* FileSystemName as reported by FileFsAttributeInfo query */
#define FS_NAME     L"NFS"
#define FS_NAME_LEN (sizeof(FS_NAME) - sizeof(WCHAR))
#define FS_ATTR_LEN (sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + FS_NAME_LEN)

typedef struct _NFS41_V_NET_ROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    HANDLE                  session;
    BYTE                    FsAttrs[FS_ATTR_LEN];
    LONG                    FsAttrsLen;
    DWORD                   sec_flavor;                    
} NFS41_V_NET_ROOT_EXTENSION, *PNFS41_V_NET_ROOT_EXTENSION;
#define NFS41GetVNetRootExtension(pVNetRoot)      \
        (((pVNetRoot) == NULL) ? NULL :           \
        (PNFS41_V_NET_ROOT_EXTENSION)((pVNetRoot)->Context))

typedef struct _NFS41_FCB {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    ULONG                   Flags;
    FILE_BASIC_INFORMATION  BasicInfo;
    FILE_STANDARD_INFORMATION StandardInfo;
    BOOLEAN                 Renamed;
    DWORD                   mode;
    LONGLONG                changeattr;
} NFS41_FCB, *PNFS41_FCB;
#define NFS41GetFcbExtension(pFcb)      \
        (((pFcb) == NULL) ? NULL : (PNFS41_FCB)((pFcb)->Context))

typedef struct _NFS41_SRV_OPEN {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
} NFS41_SRV_OPEN, *PNFS41_SRV_OPEN;
#define NFS41GetSrvOpenExtension(pSrvOpen)  \
        (((pSrvOpen) == NULL) ? NULL : (PNFS41_SRV_OPEN)((pSrvOpen)->Context))

typedef struct _NFS41_FOBX {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;

    HANDLE nfs41_open_state;
    SECURITY_CLIENT_CONTEXT sec_ctx;
} NFS41_FOBX, *PNFS41_FOBX;
#define NFS41GetFileObjectExtension(pFobx)  \
        (((pFobx) == NULL) ? NULL : (PNFS41_FOBX)((pFobx)->Context))

typedef struct _NFS41_SERVER_ENTRY {
    PMRX_SRV_CALL                 pRdbssSrvCall;
    WCHAR                         NameBuffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING                Name;             // the server name.
} NFS41_SERVER_ENTRY, *PNFS41_SERVER_ENTRY;

typedef struct _NFS41_DEVICE_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    PRDBSS_DEVICE_OBJECT    DeviceObject;
    ULONG                   ActiveNodes;
    HANDLE                  SharedMemorySection;
    DWORD                   nfs41d_version;
} NFS41_DEVICE_EXTENSION, *PNFS41_DEVICE_EXTENSION;

#define NFS41GetDeviceExtension(RxContext,pExt)        \
        PNFS41_DEVICE_EXTENSION pExt = (PNFS41_DEVICE_EXTENSION) \
        ((PBYTE)(RxContext->RxDeviceObject) + sizeof(RDBSS_DEVICE_OBJECT))

typedef enum _NULMRX_STORAGE_TYPE_CODES {
    NTC_NFS41_DEVICE_EXTENSION      =   (NODE_TYPE_CODE)0xFC00,    
} NFS41_STORAGE_TYPE_CODES;
#define RxDefineNode( node, type )          \
        node->NodeTypeCode = NTC_##type;    \
        node->NodeByteSize = sizeof(type);

#define RDR_NULL_STATE  0
#define RDR_UNLOADED    1
#define RDR_UNLOADING   2
#define RDR_LOADING     3
#define RDR_LOADED      4
#define RDR_STOPPED     5
#define RDR_STOPPING    6
#define RDR_STARTING    7
#define RDR_STARTED     8

nfs41_init_driver_state nfs41_init_state = NFS41_INIT_DRIVER_STARTABLE;
nfs41_start_driver_state nfs41_start_state = NFS41_START_DRIVER_STARTABLE;

static NTSTATUS map_readwrite_errors(DWORD status);

ULONG get_next_xid() {
    ULONG x;
    ExAcquireFastMutex(&xidLock);
    x = ++xid;
    ExReleaseFastMutex(&xidLock);
    return x; 
}

ULONG get_next_open_owner() {
    ULONG x;
    ExAcquireFastMutex(&openOwnerLock);
    x = open_owner_id++;
    ExReleaseFastMutex(&openOwnerLock);
    return x; 
}

void print_debug_header(PRX_CONTEXT RxContext)
{

    PIO_STACK_LOCATION IrpSp = RxContext->CurrentIrpSp;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;

    if (IrpSp) {
        DbgP("FileOject %p Filename %wZ %wZ\n", IrpSp->FileObject, 
                &IrpSp->FileObject->FileName, SrvOpen->pAlreadyPrefixedName);
        print_file_object(0, IrpSp->FileObject);
    } else
        DbgP("Couldn't print FileObject IrpSp is NULL\n");

    print_fo_all(1, RxContext);
    if (RxContext->pFobx) {
        PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
        if (pVNetRootContext && nfs41_fobx)
            DbgP("Session=0x%x OpenState=0x%x\n", pVNetRootContext->session, 
                nfs41_fobx->nfs41_open_state);
    }
    if (RxContext->CurrentIrpSp) 
        print_irps_flags(1, RxContext->CurrentIrpSp);
    if (RxContext->CurrentIrp)
        print_irp_flags(1, RxContext->CurrentIrp);
}

/* convert strings from unicode -> ansi during marshalling to
 * save space in the upcall buffers and avoid extra copies */
static INLINE ULONG length_as_ansi(
    PCUNICODE_STRING str)
{
    return sizeof(str->MaximumLength) + RtlUnicodeStringToAnsiSize(str);
}

static NTSTATUS marshall_unicode_as_ansi(
    unsigned char **pos,
    PCUNICODE_STRING str)
{
    ANSI_STRING ansi;
    NTSTATUS status;

    /* convert the string directly into the upcall buffer */
    ansi.Buffer = (PCHAR)*pos + sizeof(ansi.MaximumLength);
    ansi.MaximumLength = (USHORT)RtlUnicodeStringToAnsiSize(str);
    status = RtlUnicodeStringToAnsiString(&ansi, str, FALSE);
    if (status)
        goto out;

    RtlCopyMemory(*pos, &ansi.MaximumLength, sizeof(ansi.MaximumLength));
    *pos += sizeof(ansi.MaximumLength);
    (*pos)[ansi.Length] = '\0';
    *pos += ansi.MaximumLength;
out:
    return status;
}

NTSTATUS marshal_nfs41_header(nfs41_updowncall_entry *entry,
                              unsigned char *buf, 
                              ULONG buf_len, 
                              ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    header_len = sizeof(entry->version) + sizeof(entry->xid) + 
        sizeof(entry->opcode) + 2 * sizeof(HANDLE);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    else
        *len = header_len;
    RtlCopyMemory(tmp, &entry->version, sizeof(entry->version));
    tmp += sizeof(entry->version);
    RtlCopyMemory(tmp, &entry->xid, sizeof(entry->xid));
    tmp += sizeof(entry->xid);
    RtlCopyMemory(tmp, &entry->opcode, sizeof(entry->opcode));
    tmp += sizeof(entry->opcode);
    RtlCopyMemory(tmp, &entry->session, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    RtlCopyMemory(tmp, &entry->open_state, sizeof(HANDLE));
    tmp += sizeof(HANDLE);

    DbgP("[upcall] entry=%p xid=%d opcode=%d version=%d session=0x%x "
        "open_state=0x%x\n", entry, entry->xid, entry->opcode, entry->version,
        entry->session, entry->open_state);
out:
    return status;
}

const char* secflavorop2name(DWORD sec_flavor)
{
    switch(sec_flavor) {
    case RPCSEC_AUTH_SYS:      return "AUTH_SYS";
    case RPCSEC_AUTHGSS_KRB5:  return "AUTHGSS_KRB5";
    case RPCSEC_AUTHGSS_KRB5I: return "AUTHGSS_KRB5I";
    case RPCSEC_AUTHGSS_KRB5P: return "AUTHGSS_KRB5P";
    }

    return "UNKNOWN FLAVOR";
}
NTSTATUS marshal_nfs41_mount(nfs41_updowncall_entry *entry,
                            unsigned char *buf,
                            ULONG buf_len,
                            ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    /* 03/25/2011: Kernel crash to nfsd not running but mount upcall cued up */
    if (!MmIsAddressValid(entry->u.Mount.srv_name) || 
            !MmIsAddressValid(entry->u.Mount.root)) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    header_len = *len + length_as_ansi(entry->u.Mount.srv_name) +
        length_as_ansi(entry->u.Mount.root) + sizeof(entry->u.Mount.sec_flavor);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.Mount.srv_name);
    if (status) goto out;
    status = marshall_unicode_as_ansi(&tmp, entry->u.Mount.root);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Mount.sec_flavor, sizeof(entry->u.Mount.sec_flavor));

    *len = header_len;

    DbgP("marshal_nfs41_mount: server name=%wZ mount point=%wZ sec_flavor=%s\n", 
            entry->u.Mount.srv_name, entry->u.Mount.root, 
            secflavorop2name(entry->u.Mount.sec_flavor));
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_unmount(nfs41_updowncall_entry *entry,
                            unsigned char *buf,
                            ULONG buf_len,
                            ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;

    DbgEn();

    status = marshal_nfs41_header(entry, buf, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;

out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_open(nfs41_updowncall_entry *entry,
                            unsigned char *buf,
                            ULONG buf_len,
                            ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.Open.filename) +
        6 * sizeof(ULONG) + sizeof(DWORD);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.Open.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Open.access_mask, sizeof(entry->u.Open.access_mask));
    tmp += sizeof(entry->u.Open.access_mask);
    RtlCopyMemory(tmp, &entry->u.Open.access_mode, sizeof(entry->u.Open.access_mode));
    tmp += sizeof(entry->u.Open.access_mode);
    RtlCopyMemory(tmp, &entry->u.Open.attrs, sizeof(entry->u.Open.attrs));
    tmp += sizeof(entry->u.Open.attrs);
    RtlCopyMemory(tmp, &entry->u.Open.copts, sizeof(entry->u.Open.copts));
    tmp += sizeof(entry->u.Open.copts);
    RtlCopyMemory(tmp, &entry->u.Open.disp, sizeof(entry->u.Open.disp));
    tmp += sizeof(entry->u.Open.disp);
    RtlCopyMemory(tmp, &entry->u.Open.open_owner_id,
        sizeof(entry->u.Open.open_owner_id));
    tmp += sizeof(entry->u.Open.open_owner_id);
    RtlCopyMemory(tmp, &entry->u.Open.mode, sizeof(DWORD));

    *len = header_len;

    DbgP("marshal_nfs41_open: mask=0x%x mode=0x%x attrs=0x%x opts=0x%x "
         "dispo=0x%x open_owner_id=0x%x mode=%o\n", entry->u.Open.access_mask, 
         entry->u.Open.access_mode, entry->u.Open.attrs, 
         entry->u.Open.copts, entry->u.Open.disp,
         entry->u.Open.open_owner_id, entry->u.Open.mode); 
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_rw(nfs41_updowncall_entry *entry, 
                          unsigned char *buf, 
                          ULONG buf_len,
                          ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(entry->u.ReadWrite.len) +
        sizeof(entry->u.ReadWrite.offset) + sizeof(HANDLE);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.ReadWrite.len, sizeof(entry->u.ReadWrite.len));
    tmp += sizeof(entry->u.ReadWrite.len);
    RtlCopyMemory(tmp, &entry->u.ReadWrite.offset, sizeof(entry->u.ReadWrite.offset));
    tmp += sizeof(entry->u.ReadWrite.offset);
    __try {
        entry->u.ReadWrite.buf = 
            MmMapLockedPagesSpecifyCache(entry->u.ReadWrite.MdlAddress, 
                UserMode, MmNonCached, NULL, TRUE, NormalPagePriority);
        if (entry->u.ReadWrite.buf == NULL) {
            print_error("MmMapLockedPagesSpecifyCache failed to map pages\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        NTSTATUS code; 
        code = GetExceptionCode(); 
        print_error("Call to MmMapLocked failed due to exception 0x%x\n", code);
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.ReadWrite.buf, sizeof(HANDLE));

    *len = header_len;

    DbgP("marshal_nfs41_rw: len=%u offset=%lu MdlAddress=%p Userspace=%p\n", 
         entry->u.ReadWrite.len, entry->u.ReadWrite.offset, 
         entry->u.ReadWrite.MdlAddress, entry->u.ReadWrite.buf);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_lock(nfs41_updowncall_entry *entry,
                            unsigned char *buf,
                            ULONG buf_len,
                            PULONG len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;
    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + 2 * sizeof(LONGLONG) + 2 * sizeof(BOOLEAN);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Lock.offset, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.length, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.exclusive, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.Lock.blocking, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);

    *len = header_len;

    DbgP("marshal_nfs41_lock: offset=%llx length=%llx exclusive=%u "
         "blocking=%u\n", entry->u.Lock.offset, entry->u.Lock.length,
         entry->u.Lock.exclusive, entry->u.Lock.blocking);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_unlock(nfs41_updowncall_entry *entry,
                              unsigned char *buf,
                              ULONG buf_len,
                              PULONG len)
{
    NTSTATUS status;
    ULONG header_len = 0;
    unsigned char *tmp = buf;
    PLOWIO_LOCK_LIST lock;
    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + sizeof(ULONG) + 
        entry->u.Unlock.count * 2 * sizeof(LONGLONG);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Unlock.count, sizeof(ULONG));
    tmp += sizeof(ULONG);

    lock = &entry->u.Unlock.locks;
    while (lock) {
        RtlCopyMemory(tmp, &lock->ByteOffset, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        RtlCopyMemory(tmp, &lock->Length, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        lock = lock->Next;
    }

    *len = header_len;

    DbgP("marshal_nfs41_unlock: count=%u\n", entry->u.Unlock.count);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_close(nfs41_updowncall_entry *entry, 
                             unsigned char *buf, 
                             ULONG buf_len, 
                             ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;


    header_len = *len + sizeof(BOOLEAN);
    if (entry->u.Close.remove)
        header_len += length_as_ansi(entry->u.Close.filename) +
            sizeof(BOOLEAN);

    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Close.remove, sizeof(BOOLEAN));
    if (entry->u.Close.remove) {
        tmp += sizeof(BOOLEAN);
        status = marshall_unicode_as_ansi(&tmp, entry->u.Close.filename);
        if (status) goto out;
        RtlCopyMemory(tmp, &entry->u.Close.renamed, sizeof(BOOLEAN));
    }

    *len = header_len;

    DbgP("marshal_nfs41_close: remove=%d renamed=%d filename=%wZ\n", 
         entry->u.Close.remove, entry->u.Close.renamed, entry->u.Close.filename);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_dirquery(nfs41_updowncall_entry *entry, 
                                unsigned char *buf, 
                                ULONG buf_len, 
                                ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;

    header_len = *len + 2 * sizeof(ULONG) +
        length_as_ansi(entry->u.QueryFile.filter) + 3 * sizeof(BOOLEAN);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    status = marshall_unicode_as_ansi(&tmp, entry->u.QueryFile.filter);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.QueryFile.initial_query, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.restart_scan, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.return_single, sizeof(BOOLEAN));

    *len = header_len;

    DbgP("marshal_nfs41_dirquery: filter='%wZ'class=%d "
         "1st\\restart\\single=%d\\%d\\%d\n", entry->u.QueryFile.filter, 
         entry->u.QueryFile.InfoClass, entry->u.QueryFile.initial_query, 
         entry->u.QueryFile.restart_scan, entry->u.QueryFile.return_single);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_filequery(nfs41_updowncall_entry *entry, 
                                 unsigned char *buf, 
                                 ULONG buf_len, 
                                 ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + 2 * sizeof(ULONG);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->session, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    RtlCopyMemory(tmp, &entry->open_state, sizeof(HANDLE));

    *len = header_len;

    DbgP("marshal_nfs41_filequery: class=%d\n", entry->u.QueryFile.InfoClass);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_fileset(nfs41_updowncall_entry *entry, 
                                 unsigned char *buf, 
                                 ULONG buf_len, 
                                 ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + length_as_ansi(entry->u.SetFile.filename) +
        5 * sizeof(ULONG) + entry->u.SetFile.buf_len;
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_ansi(&tmp, entry->u.SetFile.filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.SetFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.SetFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->u.SetFile.buf, entry->u.SetFile.buf_len);
    tmp += entry->u.SetFile.buf_len;
    RtlCopyMemory(tmp, &entry->u.SetFile.open_owner_id, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.SetFile.access_mask, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.SetFile.access_mode, sizeof(ULONG));

    *len = header_len;

    DbgP("marshal_nfs41_fileset: filename='%wZ' class=%d open_owner_id=0x%x "
         "access_mask=0x%x access_mode=0x%x\n", entry->u.SetFile.filename, 
         entry->u.SetFile.InfoClass, entry->u.SetFile.open_owner_id, 
         entry->u.SetFile.access_mask, entry->u.SetFile.access_mode);
    print_hexbuf(0, (unsigned char *)"setfile buffer", entry->u.SetFile.buf, 
        entry->u.SetFile.buf_len);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_easet(nfs41_updowncall_entry *entry, 
                                 unsigned char *buf, 
                                 ULONG buf_len, 
                                 ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(DWORD);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.SetEa.mode, sizeof(DWORD));

    *len = header_len;

    DbgP("marshal_nfs41_easet: mode=0x%x\n", entry->u.SetEa.mode);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_symlink(nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(BOOLEAN) +
        length_as_ansi(entry->u.Symlink.filename);
    if (entry->u.Symlink.set)
        header_len += length_as_ansi(entry->u.Symlink.target);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    marshall_unicode_as_ansi(&tmp, entry->u.Symlink.filename);
    RtlCopyMemory(tmp, &entry->u.Symlink.set, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    if (entry->u.Symlink.set)
        marshall_unicode_as_ansi(&tmp, entry->u.Symlink.target);

    *len = header_len;

    DbgP("marshal_nfs41_symlink: name %wZ symlink target %wZ\n", 
         entry->u.Symlink.filename, 
         entry->u.Symlink.set?entry->u.Symlink.target : NULL);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_volume(nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(FS_INFORMATION_CLASS);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Volume.query, sizeof(FS_INFORMATION_CLASS));
    *len = header_len;

    DbgP("marshal_nfs41_volume: class=%d\n", entry->u.Volume.query);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_getacl(nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(SECURITY_INFORMATION);
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    *len = header_len;

    DbgP("marshal_nfs41_getacl: class=0x%x\n", entry->u.Acl.query);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_setacl(nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    DbgEn();
    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status == STATUS_INSUFFICIENT_RESOURCES) 
        goto out;
    else 
        tmp += *len;
    header_len = *len + sizeof(SECURITY_INFORMATION) +
        sizeof(ULONG) + entry->u.Acl.buf_len;
    if (header_len > buf_len) { 
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    tmp += sizeof(SECURITY_INFORMATION);
    RtlCopyMemory(tmp, &entry->u.Acl.buf_len, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, entry->u.Acl.buf, entry->u.Acl.buf_len);
    *len = header_len;

    DbgP("marshal_nfs41_setacl: class=0x%x sec_desc_len=%d\n", 
         entry->u.Acl.query, entry->u.Acl.buf_len);
out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_shutdown(nfs41_updowncall_entry *entry, 
                             unsigned char *buf, 
                             ULONG buf_len, 
                             ULONG *len) 
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char *tmp = buf;

    DbgEn();

    status = marshal_nfs41_header(entry, tmp, buf_len, len);

    DbgEx();
    return status;
}

NTSTATUS
nfs41_invalidate_cache (
    IN PRX_CONTEXT RxContext
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;

}

NTSTATUS
handle_upcall(
    IN PRX_CONTEXT RxContext,
    IN nfs41_updowncall_entry *entry,
    OUT ULONG *len
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    ULONG cbOut = LowIoContext->ParamsFor.IoCtl.OutputBufferLength;
    unsigned char *pbOut = LowIoContext->ParamsFor.IoCtl.pOutputBuffer;

    status = SeImpersonateClientEx(entry->psec_ctx, NULL);
    if (status != STATUS_SUCCESS)
        print_error("SeImpersonateClientEx failed %x\n", status);

    switch(entry->opcode) {
    case NFS41_SHUTDOWN:
        status = marshal_nfs41_shutdown(entry, pbOut, cbOut, len);
        DbgP("[upcall] About to signal waiting IO thread\n");
        KeSetEvent(&entry->cond, 0, FALSE);
        break;
    case NFS41_MOUNT:
        status = marshal_nfs41_mount(entry, pbOut, cbOut, len);
        break;
    case NFS41_UNMOUNT:
        status = marshal_nfs41_unmount(entry, pbOut, cbOut, len);
        break;
    case NFS41_OPEN:
        status = marshal_nfs41_open(entry, pbOut, cbOut, len);
        break;
    case NFS41_READ:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_WRITE:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_LOCK:
        status = marshal_nfs41_lock(entry, pbOut, cbOut, len);
        break;
    case NFS41_UNLOCK:
        status = marshal_nfs41_unlock(entry, pbOut, cbOut, len);
        break;
    case NFS41_CLOSE:
        status = marshal_nfs41_close(entry, pbOut, cbOut, len);
        break;
    case NFS41_DIR_QUERY:
        status = marshal_nfs41_dirquery(entry, pbOut, cbOut, len);
        break;
    case NFS41_FILE_QUERY:
        status = marshal_nfs41_filequery(entry, pbOut, cbOut, len);
        break;
    case NFS41_FILE_SET:
        status = marshal_nfs41_fileset(entry, pbOut, cbOut, len);
        break;
    case NFS41_EA_SET:
        status = marshal_nfs41_easet(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYMLINK:
        status = marshal_nfs41_symlink(entry, pbOut, cbOut, len);
        break;
    case NFS41_VOLUME_QUERY:
        status = marshal_nfs41_volume(entry, pbOut, cbOut, len);
        break;
    case NFS41_ACL_QUERY:
        status = marshal_nfs41_getacl(entry, pbOut, cbOut, len);
        break;
    case NFS41_ACL_SET:
        status = marshal_nfs41_setacl(entry, pbOut, cbOut, len);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        print_error("Unknown nfs41 ops %d\n", entry->opcode);
    }

    if (status == STATUS_SUCCESS)
        print_hexbuf(0, (unsigned char *)"upcall buffer", pbOut, *len);

    return status;
}

NTSTATUS nfs41_UpcallCreate(
    IN DWORD opcode,
    IN PSECURITY_CLIENT_CONTEXT clnt_sec_ctx,
    IN HANDLE session,
    IN HANDLE open_state,
    IN DWORD version,
    OUT nfs41_updowncall_entry **entry_out)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    SECURITY_SUBJECT_CONTEXT sec_ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;

    entry = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_entry), 
                NFS41_MM_POOLTAG);
    if (entry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlZeroMemory(entry, sizeof(nfs41_updowncall_entry));
    entry->xid = get_next_xid();
    entry->opcode = opcode;
    entry->state = NFS41_WAITING_FOR_UPCALL;
    entry->session = session;
    entry->open_state = open_state;
    entry->version = version;
    /*XXX KeInitializeEvent will bugcheck under verifier if allocated from PagedPool? */
    KeInitializeEvent(&entry->cond, SynchronizationEvent, FALSE);
    ExInitializeFastMutex(&entry->lock);

    if (clnt_sec_ctx == NULL) {
        SeCaptureSubjectContext(&sec_ctx);
        sec_qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        sec_qos.ImpersonationLevel = SecurityImpersonation;
        sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sec_qos.EffectiveOnly = 0;
        status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos, 1, &entry->sec_ctx);
        if (status != STATUS_SUCCESS) {
            print_error("SeCreateClientSecurityFromSubjectContext "
                "failed with %x\n", status);
            RxFreePool(entry);
        }
        entry->psec_ctx = &entry->sec_ctx;
        SeReleaseSubjectContext(&sec_ctx);
    } else
        entry->psec_ctx = clnt_sec_ctx;

    *entry_out = entry;
out:
    return status;
}

NTSTATUS nfs41_UpcallWaitForReply(
    IN nfs41_updowncall_entry *entry)
{
    NTSTATUS status = STATUS_SUCCESS;
    const char *opstring = opcode2string(entry->opcode);

    nfs41_AddEntry(upcallLock, upcall, entry);
    KeSetEvent(&upcallEvent, 0, FALSE);
    DbgP("@@@ Creating %s upcall entry=%p xid=%d\n", opstring, entry, entry->xid);
    if (!entry->async_op) {
        /* 02/03/2011 AGLO: it is not clear what the "right" waiting design should be.
         * Having non-interruptable waiting seems to be the right approach. However,
         * when things go wrong, the only wait to proceed is a reboot (since "waits" 
         * are not interruptable we can't stop a hung task. 
         * Having interruptable wait causes issues with security context.
         * For now, I'm making CLOSE non-interruptable but keeping the rest interruptable
         * so that we don't have to reboot all the time
         */
        /* 02/15/2011 cbodley: added NFS41_UNLOCK for the same reason. locking
         * tests were triggering an interrupted unlock, which led to a bugcheck
         * in CloseSrvOpen() */
#define MAKE_WAITONCLOSE_NONITERRUPTABLE
#ifdef MAKE_WAITONCLOSE_NONITERRUPTABLE
        if (entry->opcode == NFS41_CLOSE || entry->opcode == NFS41_UNLOCK)
            status = KeWaitForSingleObject(&entry->cond, Executive, 
                        KernelMode, FALSE, NULL);
        else
            status = KeWaitForSingleObject(&entry->cond, Executive, 
                        UserMode, TRUE, NULL);
#else

        status = KeWaitForSingleObject(&entry->cond, Executive, KernelMode, FALSE, NULL);
#endif
        print_wait_status(1, "[downcall]", status, opcode2string(entry->opcode), 
            entry, entry->xid);
    } else
        goto out;

    switch(status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_USER_APC:
    case STATUS_ALERTED:
    default:
        ExAcquireFastMutex(&entry->lock);
        if (entry->state == NFS41_DONE_PROCESSING) {
            DbgP("[downcall] finish processing %s entry=%p xid=%d\n", 
                opcode2string(entry->opcode), entry, entry->xid);
            ExReleaseFastMutex(&entry->lock);
            break;
        }
        DbgP("[upcall] abandoning %s entry=%p xid=%d\n", 
            opcode2string(entry->opcode), entry, entry->xid);
        entry->state = NFS41_NOT_WAITING;
        ExReleaseFastMutex(&entry->lock);
        goto out;
    }
    nfs41_RemoveEntry(downcallLock, downcall, entry);
out:
    return status;
}

NTSTATUS
nfs41_upcall (
    IN PRX_CONTEXT RxContext
    )
{
    NTSTATUS status = STATUS_SUCCESS; /* XXX */
    nfs41_updowncall_entry *entry = NULL;
    ULONG len = 0;
    PLIST_ENTRY pEntry;

    DbgEn();

process_upcall:
    nfs41_RemoveFirst(upcallLock, upcall, pEntry);
    if (pEntry) {
        entry = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry, 
                    nfs41_updowncall_entry, next);
        ExAcquireFastMutex(&entry->lock);
        nfs41_AddEntry(downcallLock, downcall, entry);
        status = handle_upcall(RxContext, entry, &len);
        if (status == STATUS_SUCCESS && 
                entry->state == NFS41_WAITING_FOR_UPCALL)
            entry->state = NFS41_WAITING_FOR_DOWNCALL;
        ExReleaseFastMutex(&entry->lock);
        if (status == STATUS_INSUFFICIENT_RESOURCES) {
            print_error("upcall buffer is too small\n");
            entry->status = status;
            KeSetEvent(&entry->cond, 0, FALSE);
            RxContext->InformationToReturn = 0;
        } else 
            RxContext->InformationToReturn = len;
    }
    else {
        DbgP("[upcall] About to go to sleep\n");
        status = KeWaitForSingleObject(&upcallEvent, Executive, UserMode, TRUE,
            (PLARGE_INTEGER) NULL);
        print_wait_status(1, "[upcall]", status, NULL, NULL, 0);
        switch (status) {
        case STATUS_SUCCESS: 
            goto process_upcall;
        case STATUS_USER_APC:
        case STATUS_ALERTED:
        default:
            goto out;
        }
    }
out:
    DbgEx();
    return status;
}

NTSTATUS
nfs41_downcall (
    IN PRX_CONTEXT RxContext
    )
{
    NTSTATUS status = STATUS_SUCCESS; /* XXX */
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    ULONG in_len = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    unsigned char *buf = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    PLIST_ENTRY pEntry;
    nfs41_updowncall_entry *tmp;
    nfs41_updowncall_entry *cur= NULL;
    DWORD found = 0;

    DbgEn();
    print_hexbuf(0, (unsigned char *)"downcall buffer", buf, in_len);

    tmp = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_entry), 
            NFS41_MM_POOLTAG);
    if (tmp == NULL) {
        goto out;
    }
    RtlZeroMemory(tmp, sizeof(nfs41_updowncall_entry));

    RtlCopyMemory(&tmp->xid, buf, sizeof(tmp->xid));
    buf += sizeof(tmp->xid);
    RtlCopyMemory(&tmp->opcode, buf, sizeof(tmp->opcode));
    buf += sizeof(tmp->opcode);
    RtlCopyMemory(&tmp->status, buf, sizeof(tmp->status));
    buf += sizeof(tmp->status);
    RtlCopyMemory(&tmp->errno, buf, sizeof(tmp->errno));
    buf += sizeof(tmp->errno);
    DbgP("[downcall] xid=%d opcode=%d status=%d errno=%d\n", tmp->xid, tmp->opcode, 
        tmp->status, tmp->errno);

    ExAcquireFastMutex(&downcallLock); 
    pEntry = &downcall->head;
    while (pEntry != NULL) {
        cur = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry, 
                nfs41_updowncall_entry, next);
        if (cur->xid == tmp->xid) {
            found = 1;
            break;
        }
        if (pEntry->Flink == &downcall->head) {
            DbgP("reached end of the list\n");
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&downcallLock); 
    if (!found) {
        print_error("Didn't find xid=%d entry\n", tmp->xid);
        goto out_free;
    }

    ExAcquireFastMutex(&cur->lock);
    SeStopImpersonatingClient();
    if (cur->state == NFS41_NOT_WAITING) {
            print_error("[downcall] Nobody is waiting for this request!!!\n");
            ExReleaseFastMutex(&cur->lock);
            nfs41_RemoveEntry(downcallLock, downcall, cur);
            SeDeleteClientSecurity(cur->psec_ctx);
            RxFreePool(cur);
            status = STATUS_UNSUCCESSFUL;
            goto out_free;
    }
    cur->state = NFS41_DONE_PROCESSING;
    cur->status = tmp->status;
    cur->errno = tmp->errno;
    status = STATUS_SUCCESS;

    if (!tmp->status) {
        switch (tmp->opcode) {
        case NFS41_MOUNT:
            RtlCopyMemory(&cur->session, buf, sizeof(HANDLE));
            buf += sizeof(HANDLE);
            RtlCopyMemory(&cur->version, buf, sizeof(DWORD));
            DbgP("[mount] session pointer 0x%x version %d\n", cur->session, cur->version);
            break;
        case NFS41_WRITE:
        case NFS41_READ:
            RtlCopyMemory(&cur->u.ReadWrite.len, buf, sizeof(cur->u.ReadWrite.len));
            DbgP("[read/write] returned len %ld\n", cur->u.ReadWrite.len);
#if 1
            /* 08/27/2010: it looks like we really don't need to call MmUnmapLockedPages()
             * eventhough we called MmMapLockedPagesSpecifyCache() as the MDL passed to us
             * is already locked. 
             */
            __try {
                MmUnmapLockedPages(cur->u.ReadWrite.buf, cur->u.ReadWrite.MdlAddress);
            } __except(EXCEPTION_EXECUTE_HANDLER) { 
                NTSTATUS code; 
                code = GetExceptionCode(); 
                print_error("Call to MmUnmapLockedPages failed due to"
                    " exception 0x%0x\n", code);
                status = STATUS_ACCESS_DENIED;
            }
#endif
            break;
        case NFS41_OPEN:
            RtlCopyMemory(&cur->u.Open.binfo, buf, sizeof(FILE_BASIC_INFORMATION));
            buf += sizeof(FILE_BASIC_INFORMATION);
            RtlCopyMemory(&cur->u.Open.sinfo, buf, sizeof(FILE_STANDARD_INFORMATION));
            buf += sizeof(FILE_STANDARD_INFORMATION);
            RtlCopyMemory(&cur->open_state, buf, sizeof(HANDLE));
            buf += sizeof(HANDLE);
            RtlCopyMemory(&cur->u.Open.mode, buf, sizeof(DWORD));
            buf += sizeof(DWORD);
            RtlCopyMemory(&cur->u.Open.changeattr, buf, sizeof(LONGLONG));
            buf += sizeof(LONGLONG);
            if (tmp->errno == ERROR_REPARSE) {
                RtlCopyMemory(&cur->u.Open.symlink_embedded, buf, sizeof(BOOLEAN));
                buf += sizeof(BOOLEAN);
                RtlCopyMemory(&cur->u.Open.symlink.MaximumLength, buf, sizeof(USHORT));
                buf += sizeof(USHORT);
                cur->u.Open.symlink.Length = cur->u.Open.symlink.MaximumLength - sizeof(WCHAR);
                cur->u.Open.symlink.Buffer = RxAllocatePoolWithTag(NonPagedPool, 
                    cur->u.Open.symlink.MaximumLength, NFS41_MM_POOLTAG);
                if (cur->u.Open.symlink.Buffer == NULL) {
                    cur->status = STATUS_INSUFFICIENT_RESOURCES;
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
                RtlCopyMemory(cur->u.Open.symlink.Buffer, buf, cur->u.Open.symlink.MaximumLength);
                DbgP("[open] ERROR_REPARSE -> '%wZ'\n", &cur->u.Open.symlink);
            }
            DbgP("[open] open_state 0x%x mode %o changeattr 0x%x\n",
                cur->open_state, cur->u.Open.mode, cur->u.Open.changeattr);
            break;
        case NFS41_DIR_QUERY:
        case NFS41_FILE_QUERY:
            RtlCopyMemory(&tmp->u.QueryFile.buf_len, buf, sizeof(ULONG));
            buf += sizeof(ULONG);
            if (tmp->u.QueryFile.buf_len > cur->u.QueryFile.buf_len) {
                cur->status = STATUS_BUFFER_TOO_SMALL;
                cur->u.QueryFile.buf_len = tmp->u.QueryFile.buf_len;
                break;
            }
            cur->u.QueryFile.buf_len = tmp->u.QueryFile.buf_len;
            RtlCopyMemory(cur->u.QueryFile.buf, buf, tmp->u.QueryFile.buf_len);
            break;
        case NFS41_SYMLINK:
            if (cur->u.Symlink.set)
                break;
            RtlCopyMemory(&cur->u.Symlink.target->Length, buf, sizeof(USHORT));
            buf += sizeof(USHORT);
            if (cur->u.Symlink.target->Length > cur->u.Symlink.target->MaximumLength) {
                cur->status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            RtlCopyMemory(cur->u.Symlink.target->Buffer, buf,
                cur->u.Symlink.target->Length);
            cur->u.Symlink.target->Length -= sizeof(UNICODE_NULL);
            break;
        case NFS41_VOLUME_QUERY:
            RtlCopyMemory(&tmp->u.Volume.buf_len, buf, sizeof(LONG));
            buf += sizeof(LONG);
            if (tmp->u.Volume.buf_len > cur->u.Volume.buf_len) {
                cur->status = STATUS_BUFFER_TOO_SMALL;
                cur->u.Volume.buf_len = tmp->u.Volume.buf_len;
                break;
            }
            cur->u.Volume.buf_len = tmp->u.Volume.buf_len;
            RtlCopyMemory(cur->u.Volume.buf, buf, tmp->u.Volume.buf_len);
            break;
        case NFS41_ACL_QUERY:
            RtlCopyMemory(&tmp->u.Acl.buf_len, buf, sizeof(DWORD));
            buf += sizeof(DWORD);
            if (tmp->u.Acl.buf_len > cur->u.Acl.buf_len) {
                cur->status = STATUS_BUFFER_TOO_SMALL;
                cur->u.Acl.buf_len = tmp->u.Acl.buf_len;
                break;
            } else {
                cur->u.Acl.buf = RxAllocatePoolWithTag(NonPagedPool, 
                    tmp->u.Acl.buf_len, NFS41_MM_POOLTAG);
                if (cur->u.Acl.buf == NULL) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto out_free;
                }
                RtlCopyMemory(cur->u.Acl.buf, buf, tmp->u.Acl.buf_len);
                cur->u.Acl.buf_len = tmp->u.Acl.buf_len;
            }
            break;
        }
    }
    DbgP("[downcall] About to signal waiting IO thread\n");
    ExReleaseFastMutex(&cur->lock);
    if (cur->async_op) {
        if (cur->status == STATUS_SUCCESS) {
            cur->u.ReadWrite.rxcontext->StoredStatus = STATUS_SUCCESS;
            cur->u.ReadWrite.rxcontext->InformationToReturn = cur->u.ReadWrite.len;
        } else {
            cur->u.ReadWrite.rxcontext->StoredStatus = map_readwrite_errors(cur->status);
            cur->u.ReadWrite.rxcontext->InformationToReturn = 0;
        }
        nfs41_RemoveEntry(downcallLock, downcall, cur);
        RxLowIoCompletion(cur->u.ReadWrite.rxcontext);
    } else
        KeSetEvent(&cur->cond, 0, FALSE);    

out_free:
    RxFreePool(tmp);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_shutdown_daemon(DWORD version)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry = NULL;

    DbgEn();
    status = nfs41_UpcallCreate(NFS41_SHUTDOWN, NULL, INVALID_HANDLE_VALUE,
        INVALID_HANDLE_VALUE, version, &entry);
    if (status)
        goto out;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    SeDeleteClientSecurity(&entry->sec_ctx);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

static NTSTATUS SharedMemoryInit(
    OUT PHANDLE phSection)
{
    NTSTATUS status;
    HANDLE hSection;
    UNICODE_STRING SectionName;
    SECURITY_DESCRIPTOR SecurityDesc;
    OBJECT_ATTRIBUTES SectionAttrs;
    LARGE_INTEGER nSectionSize;

    DbgEn();

    RtlInitUnicodeString(&SectionName, NFS41_SHARED_MEMORY_NAME);

    /* XXX: setting dacl=NULL grants access to everyone */
    status = RtlCreateSecurityDescriptor(&SecurityDesc,
        SECURITY_DESCRIPTOR_REVISION);
    if (status) {
        print_error("RtlCreateSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }
    status = RtlSetDaclSecurityDescriptor(&SecurityDesc, TRUE, NULL, FALSE);
    if (status) {
        print_error("RtlSetDaclSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }

    InitializeObjectAttributes(&SectionAttrs, &SectionName,
        0, NULL, &SecurityDesc);

    nSectionSize.QuadPart = sizeof(NFS41NP_SHARED_MEMORY);

    status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
        &SectionAttrs, &nSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_OBJECT_NAME_COLLISION:
        DbgP("section already created; returning success\n");
        status = STATUS_SUCCESS;
        goto out;
    default:
        DbgP("ZwCreateSection failed with %08X\n", status);
        goto out;
    }
out:
    DbgEx();
    return status;
}

static NTSTATUS SharedMemoryFree(
    IN HANDLE hSection)
{
    NTSTATUS status;
    DbgEn();
    status = ZwClose(hSection);
    DbgEx();
    return status;
}

NTSTATUS nfs41_Start(
    IN OUT struct _RX_CONTEXT *RxContext, 
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);

    DbgEn();

    status = SharedMemoryInit(&DevExt->SharedMemorySection);
    if (status) {
        print_error("InitSharedMemory failed with %08X\n", status);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    InterlockedCompareExchange((PLONG)&nfs41_start_state,
        NFS41_START_DRIVER_STARTED,
        NFS41_START_DRIVER_START_IN_PROGRESS);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_Stop(
    IN OUT struct _RX_CONTEXT * RxContext,
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DbgEn();
    status = SharedMemoryFree(DevExt->SharedMemorySection);
    DbgEx();
    return status;
}

HANDLE
GetConnectionHandle(
    IN PUNICODE_STRING ConnectionName,
    IN PVOID EaBuffer,
    IN ULONG EaLength
    )
{
    NTSTATUS status;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;

    DbgEn();
    InitializeObjectAttributes(&ObjectAttributes, ConnectionName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&Handle, SYNCHRONIZE, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT,
        EaBuffer, EaLength);
    if (!NT_SUCCESS(status))
        Handle = INVALID_HANDLE_VALUE;
    else
        DbgP("created handle %p\n", &Handle);

    DbgEx();
    return Handle;
}

NTSTATUS nfs41_GetConnectionInfoFromBuffer(
    IN PVOID Buffer,
    IN ULONG BufferLen,
    OUT PUNICODE_STRING pConnectionName,
    OUT PVOID *ppEaBuffer,
    OUT PULONG pEaLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    USHORT NameLength;
    USHORT EaPadding;
    ULONG EaLength;
    ULONG BufferLenExpected;
    PBYTE ptr;

    DbgEn();

    /* make sure buffer is at least big enough for header */
    if (BufferLen < sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG))
    {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Invalid input buffer.\n");
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    ptr = Buffer;
    NameLength = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaPadding = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaLength = *(PULONG)ptr;
    ptr += sizeof(ULONG);

    /* validate buffer length */
    BufferLenExpected = sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG) +
        NameLength + EaPadding + EaLength;
    if (BufferLen != BufferLenExpected)
    {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Received buffer of length %lu, but expected %lu bytes.\n",
            BufferLen, BufferLenExpected);
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    pConnectionName->Buffer = (PWCH)ptr;
    pConnectionName->Length = NameLength - sizeof(WCHAR);
    pConnectionName->MaximumLength = NameLength;
    DbgP("connection name %wZ\n", pConnectionName);

    if (EaLength)
        *ppEaBuffer = ptr + NameLength + EaPadding;
    else
        *ppEaBuffer = NULL;
    *pEaLength = EaLength;

out:
    DbgEx();
    return status;
}

NTSTATUS
nfs41_CreateConnection (
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp
    )
{
    NTSTATUS    status = STATUS_SUCCESS;
    HANDLE      Handle;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PVOID       Buffer = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG       BufferLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    UNICODE_STRING FileName;
    PVOID       EaBuffer;
    ULONG       EaLength;
    BOOLEAN     Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

    DbgEn();

    if (!Wait) {
        //just post right now!
        DbgP("returning STATUS_PENDING\n");
        *PostToFsp = TRUE;
        status = STATUS_PENDING;
        goto out;
    }

    status = nfs41_GetConnectionInfoFromBuffer(Buffer, BufferLen,
        &FileName, &EaBuffer, &EaLength);
    if (status != STATUS_SUCCESS)
        goto out;

    Handle = GetConnectionHandle(&FileName, EaBuffer, EaLength);
    if (Handle == INVALID_HANDLE_VALUE)
        status = STATUS_BAD_NETWORK_NAME;
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_unmount(HANDLE session, DWORD version)
{
    NTSTATUS        status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

    DbgEn();
    status = nfs41_UpcallCreate(NFS41_UNMOUNT, NULL, session, 
        INVALID_HANDLE_VALUE, version, &entry);
    if (status)
        goto out;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    SeDeleteClientSecurity(&entry->sec_ctx);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS
nfs41_DeleteConnection (
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PWCHAR ConnectName = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG ConnectNameLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    HANDLE Handle;
    UNICODE_STRING FileName;
    PFILE_OBJECT pFileObject;
    BOOLEAN Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

    DbgEn();

    if (!Wait) {
        //just post right now!
        *PostToFsp = TRUE;
        DbgP("returning STATUS_PENDING\n");
        status = STATUS_PENDING;
        goto out;
    }

    FileName.Buffer = ConnectName;
    FileName.Length = (USHORT) ConnectNameLen - sizeof(WCHAR);
    FileName.MaximumLength = (USHORT) ConnectNameLen;

    Handle = GetConnectionHandle(&FileName, NULL, 0);
    if (Handle == INVALID_HANDLE_VALUE)
        goto out;

    DbgP("GetConnectionHandle returned success\n");
    status = ObReferenceObjectByHandle(Handle, 0L, NULL, KernelMode,
                (PVOID *)&pFileObject, NULL);
    if (NT_SUCCESS(status)) {
        PV_NET_ROOT VNetRoot;

        DbgP("ObReferenceObjectByHandle worked ok %p\n", pFileObject);
        // VNetRoot exists as FOBx in the FsContext2
        VNetRoot = (PV_NET_ROOT) pFileObject->FsContext2;
        // make sure the node looks right
        if (NodeType(VNetRoot) == RDBSS_NTC_V_NETROOT)
        {
            DbgP("Calling RxFinalizeConnection for NetRoot %p from VNetRoot %p\n",
                VNetRoot->NetRoot, VNetRoot);
            status = RxFinalizeConnection(VNetRoot->NetRoot, VNetRoot, TRUE);
        }
        else
            status = STATUS_BAD_NETWORK_NAME;

        ObDereferenceObject(pFileObject);
    }
    ZwClose(Handle);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_DevFcbXXXControlFile(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    UCHAR op = RxContext->MajorFunction;
    PLOWIO_CONTEXT io_ctx = &RxContext->LowIoContext;
    ULONG fsop = io_ctx->ParamsFor.FsCtl.FsControlCode;
    ULONG state;
    ULONG in_len = io_ctx->ParamsFor.IoCtl.InputBufferLength;
    DWORD *buf = io_ctx->ParamsFor.IoCtl.pInputBuffer;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DWORD nfs41d_version = 0;

    //DbgEn();

    print_ioctl(0, op);
    switch(op) {
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        print_fs_ioctl(0, fsop);
        switch (fsop) {
        case IOCTL_NFS41_INVALCACHE:
            status = nfs41_invalidate_cache(RxContext);
            break;
        case IOCTL_NFS41_READ:
            status = nfs41_upcall(RxContext);
            break;
        case IOCTL_NFS41_WRITE:
            status = nfs41_downcall(RxContext);
            break;
        case IOCTL_NFS41_ADDCONN:
            status = nfs41_CreateConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_DELCONN:
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n", 
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }
            status = nfs41_DeleteConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_GETSTATE:
            state = RDR_NULL_STATE;

            if (io_ctx->ParamsFor.IoCtl.OutputBufferLength >= 
                    sizeof(ULONG) ) {
                // map the states to control app's equivalents
                print_driver_state(nfs41_start_state);
                switch (nfs41_start_state) {
                case NFS41_START_DRIVER_STARTABLE:
                case NFS41_START_DRIVER_STOPPED:
                    state = RDR_STOPPED;
                    break;
                case NFS41_START_DRIVER_START_IN_PROGRESS:
                    state = RDR_STARTING;
                    break;
                case NFS41_START_DRIVER_STARTED:
                    state = RDR_STARTED;
                    break;
                }
                *(ULONG *)io_ctx->ParamsFor.IoCtl.pOutputBuffer = state;
                RxContext->InformationToReturn = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else
                status = STATUS_INVALID_PARAMETER;
            break;
        case IOCTL_NFS41_START:
            print_driver_state(nfs41_start_state);
            if (in_len >= sizeof(DWORD)) {
                RtlCopyMemory(&nfs41d_version, buf, sizeof(DWORD));
                DbgP("NFS41 Daemon sent start request with version %d\n", nfs41d_version);
                DbgP("Currently used NFS41 Daemon version is %d\n", DevExt->nfs41d_version);
                DevExt->nfs41d_version = nfs41d_version;
            }
            switch(nfs41_start_state) {
            case NFS41_START_DRIVER_STARTABLE:
                (nfs41_start_driver_state)InterlockedCompareExchange(
                              (PLONG)&nfs41_start_state,
                              NFS41_START_DRIVER_START_IN_PROGRESS,
                              NFS41_START_DRIVER_STARTABLE);
                    //lack of break is intentional
            case NFS41_START_DRIVER_START_IN_PROGRESS:
                status = RxStartMinirdr(RxContext, &RxContext->PostRequest);
                if (status == STATUS_REDIRECTOR_STARTED) {
                    DbgP("redirector started\n");
                    status = STATUS_SUCCESS;
                } else if (status == STATUS_PENDING && 
                            RxContext->PostRequest == TRUE) {
                    DbgP("RxStartMinirdr pending %08lx\n", status);
                    status = STATUS_MORE_PROCESSING_REQUIRED;
                } 
                break;
            case NFS41_START_DRIVER_STARTED:
                status = STATUS_SUCCESS;
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case IOCTL_NFS41_STOP:
            if (nfs41_start_state == NFS41_START_DRIVER_STARTED)
                nfs41_shutdown_daemon(DevExt->nfs41d_version);
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n", 
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }

            state = (nfs41_start_driver_state)InterlockedCompareExchange(
                        (PLONG)&nfs41_start_state, 
                        NFS41_START_DRIVER_STARTABLE, 
                        NFS41_START_DRIVER_STARTED);

            status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
            DbgP("RxStopMinirdr status %08lx\n", status);
            if (status == STATUS_PENDING && RxContext->PostRequest == TRUE )
                status = STATUS_MORE_PROCESSING_REQUIRED;
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
        };
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    };

    //DbgEx();
    return status;
}

NTSTATUS
_nfs41_CreateSrvCall(
      PMRX_SRVCALL_CALLBACK_CONTEXT  pCallbackContext)
{
    NTSTATUS    status = STATUS_SUCCESS;
    PMRX_SRVCALL_CALLBACK_CONTEXT SCCBC = pCallbackContext;
    PMRX_SRV_CALL pSrvCall;
    PMRX_SRVCALLDOWN_STRUCTURE SrvCalldownStructure =
        (PMRX_SRVCALLDOWN_STRUCTURE)(SCCBC->SrvCalldownStructure);
    PNFS41_SERVER_ENTRY pServerEntry = NULL;

    DbgEn();

    pSrvCall = SrvCalldownStructure->SrvCall;

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );
    print_srv_call(0, pSrvCall);

    // validate the server name with the test name of 'pnfs'
    DbgP("SrvCall: Connection Name Length: %d %wZ\n",
        pSrvCall->pSrvCallName->Length, pSrvCall->pSrvCallName);

    if (pSrvCall->pSrvCallName->Length > SERVER_NAME_BUFFER_SIZE) {
        print_error("Server name '%wZ' too long for server entry (max %u)\n",
            pSrvCall->pSrvCallName, SERVER_NAME_BUFFER_SIZE);
        status = STATUS_NAME_TOO_LONG;
        goto out;
    }

    /* Let's create our own representation of the server */
    pServerEntry = (PNFS41_SERVER_ENTRY)RxAllocatePoolWithTag(PagedPool, 
        sizeof(NFS41_SERVER_ENTRY), NFS41_MM_POOLTAG);
    if (pServerEntry == NULL) {
        print_error("failed to allocate memory for pServerEntry\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlZeroMemory(pServerEntry, sizeof(NFS41_SERVER_ENTRY));

    pServerEntry->Name.Buffer = pServerEntry->NameBuffer;
    pServerEntry->Name.Length = pSrvCall->pSrvCallName->Length;
    pServerEntry->Name.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    RtlCopyMemory(pServerEntry->Name.Buffer, pSrvCall->pSrvCallName->Buffer,
        pServerEntry->Name.Length);
    DbgP("copying server name %wZ into server entry %p\n", 
        &pServerEntry->Name, pServerEntry);

    pCallbackContext->RecommunicateContext = pServerEntry;
    DbgP("saving pServerEntry %p in RecommunicateContext\n", pServerEntry);
    InterlockedExchangePointer(&pServerEntry->pRdbssSrvCall, pSrvCall);
    DbgP("saving pSrvCall %p in pServerEntry's pRdbssSrvCall\n", pSrvCall);

out:
    SCCBC->Status = status;
    SrvCalldownStructure->CallBack(SCCBC);

    DbgEx();
    return status;
}

NTSTATUS nfs41_CreateSrvCall(
    PMRX_SRV_CALL pSrvCall,
    PMRX_SRVCALL_CALLBACK_CONTEXT pCallbackContext)
{
    NTSTATUS status;

    DbgEn();

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );

    if (IoGetCurrentProcess() == RxGetRDBSSProcess()) {
        DbgP("executing with RDBSS context\n");
        status = _nfs41_CreateSrvCall(pCallbackContext);
    } else {
        DbgP("dispatching CreateSrvCall to a system thread\n");
        status = RxDispatchToWorkerThread(nfs41_dev, DelayedWorkQueue, 
            _nfs41_CreateSrvCall, pCallbackContext);
        if (status != STATUS_SUCCESS) {
            print_error("RxDispatchToWorkerThread returned status %08lx\n", status);
            pCallbackContext->Status = status;
            pCallbackContext->SrvCalldownStructure->CallBack(pCallbackContext);
            status = STATUS_PENDING;
        }
    }
    /* RDBSS expects MRxCreateSrvCall to return STATUS_PENDING */
    if (status == STATUS_SUCCESS) {
        DbgP("mapping SUCCESS returned status to PENDING\n");
        status = STATUS_PENDING;
    } 

    DbgEx();
    return status;
}

NTSTATUS nfs41_SrvCallWinnerNotify(
    IN OUT PMRX_SRV_CALL pSrvCall, 
    IN BOOLEAN ThisMinirdrIsTheWinner,
    IN OUT PVOID pSrvCallContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry;

    DbgEn();
    pServerEntry = (PNFS41_SERVER_ENTRY)pSrvCallContext;

    if (!ThisMinirdrIsTheWinner) {
        ASSERT(1);
        goto out;
    }

    pSrvCall->Context = pServerEntry;
    DbgP("This minirdr is the winner SrvCall context %p points to server entry %p\n", 
        pSrvCall->Context, pServerEntry);
out:
    DbgEx();
    return status;
}

static NTSTATUS map_mount_errors(DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_NETWORK_UNREACHABLE:
    case ERROR_BAD_NET_RESP:    return STATUS_UNEXPECTED_NETWORK_ERROR;
    case ERROR_BAD_NETPATH:     return STATUS_BAD_NETWORK_PATH;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INSUFFICIENT_RESOURCES\n", status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

NTSTATUS nfs41_mount(PUNICODE_STRING srv_name, PUNICODE_STRING root, 
                     DWORD sec_flavor, PHANDLE session, DWORD *version)
{
    NTSTATUS        status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

    DbgEn();
    status = nfs41_UpcallCreate(NFS41_MOUNT, NULL, INVALID_HANDLE_VALUE,
        INVALID_HANDLE_VALUE, *version, &entry);
    if (status)
        goto out;
    entry->u.Mount.srv_name = srv_name;
    entry->u.Mount.root = root;
    entry->u.Mount.sec_flavor = sec_flavor;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    SeDeleteClientSecurity(&entry->sec_ctx);
    *session = entry->session;

    /* map windows ERRORs to NTSTATUS */
    status = map_mount_errors(entry->status);
    if (status == STATUS_SUCCESS)
        *version = entry->version;
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

/* TODO: move mount config stuff to another file -cbodley */

void nfs41_MountConfig_InitDefaults(
    OUT PNFS41_MOUNT_CONFIG Config)
{
    RtlZeroMemory(Config, sizeof(NFS41_MOUNT_CONFIG));

    Config->ReadSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->WriteSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->ReadOnly = FALSE;
    Config->SrvName.Length = 0;
    Config->SrvName.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    Config->SrvName.Buffer = Config->srv_buffer;
    Config->MntPt.Length = 0;
    Config->MntPt.MaximumLength = MAX_PATH;
    Config->MntPt.Buffer = Config->mntpt_buffer;
    Config->SecFlavor.Length = 0;
    Config->SecFlavor.MaximumLength = MAX_SEC_FLAVOR_LEN;
    Config->SecFlavor.Buffer = Config->sec_flavor;
    RtlCopyUnicodeString(&Config->SecFlavor, &AUTH_SYS_NAME);
}

static NTSTATUS nfs41_MountConfig_ParseBoolean(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT PBOOLEAN Value)
{
    NTSTATUS status = STATUS_SUCCESS;

    /* if no value is specified, assume TRUE
     * if a value is specified, it must be a '1' */
    if (Option->EaValueLength == 0 || *usValue->Buffer == L'1')
        *Value = TRUE;
    else
        *Value = FALSE;

    DbgP("    '%ls' -> '%wZ' -> %u\n",
        (LPWSTR)Option->EaName, *usValue, *Value);
    return status;
}

static NTSTATUS nfs41_MountConfig_ParseDword(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT PDWORD Value,
    IN DWORD Minimum,
    IN DWORD Maximum)
{
    NTSTATUS status;
    LPWSTR Name = (LPWSTR)Option->EaName;

    if (Option->EaValueLength)
    {
        status = RtlUnicodeStringToInteger(usValue, 0, Value);
        if (status == STATUS_SUCCESS)
        {
            if (*Value < Minimum)
                *Value = Minimum;
            if (*Value > Maximum)
                *Value = Maximum;
            DbgP("    '%ls' -> '%wZ' -> %lu\n", Name, *usValue, *Value);
        }
        else
            print_error("Failed to convert %s='%wZ' to unsigned long.\n",
                Name, *usValue);
    }
    else
        status = STATUS_INVALID_PARAMETER;

    return status;
}

NTSTATUS nfs41_MountConfig_ParseOptions(
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength,
    IN OUT PNFS41_MOUNT_CONFIG Config)
{
    NTSTATUS        status = STATUS_SUCCESS;
    PFILE_FULL_EA_INFORMATION Option;
    LPWSTR          Name;
    size_t          NameLen;
    UNICODE_STRING  usValue;
    DbgEn();

    Option = EaBuffer;
    while (status == STATUS_SUCCESS)
    {
        Name = (LPWSTR)Option->EaName;
        NameLen = Option->EaNameLength/sizeof(WCHAR);

        usValue.Length = usValue.MaximumLength = Option->EaValueLength;
        usValue.Buffer = (PWCH)(Option->EaName +
            Option->EaNameLength + sizeof(WCHAR));

        if (wcsncmp(L"ro", Name, NameLen) == 0)
        {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                &Config->ReadOnly);
        }
        else if (wcsncmp(L"rsize", Name, NameLen) == 0)
        {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->ReadSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"wsize", Name, NameLen) == 0)
        {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->WriteSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"srvname", Name, NameLen) == 0)
        {
            if (usValue.Length > Config->SrvName.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SrvName, &usValue);
        }
        else if (wcsncmp(L"mntpt", Name, NameLen) == 0)
        {
            if (usValue.Length > Config->MntPt.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->MntPt, &usValue);
        }
        else if (wcsncmp(L"sec", Name, NameLen) == 0)
        {
            if (usValue.Length > Config->SecFlavor.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SecFlavor, &usValue);
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
            print_error("Unrecognized option '%ls' -> '%wZ'\n",
                Name, usValue);
        }

        if (Option->NextEntryOffset == 0)
            break;

        Option = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Option + Option->NextEntryOffset);
    }

    DbgEx();
    return status;
}

static NTSTATUS has_nfs_prefix(
    IN PUNICODE_STRING SrvCallName,
    IN PUNICODE_STRING NetRootName)
{
    NTSTATUS status = STATUS_BAD_NETWORK_NAME;

    if (NetRootName->Length == SrvCallName->Length + NfsPrefix.Length) {
        const UNICODE_STRING NetRootPrefix = {
            NfsPrefix.Length,
            NetRootName->MaximumLength - SrvCallName->Length,
            &NetRootName->Buffer[SrvCallName->Length/2]
        };
        if (RtlCompareUnicodeString(&NetRootPrefix, &NfsPrefix, FALSE) == 0)
            status = STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS map_sec_flavor(
    IN PUNICODE_STRING sec_flavor_name,
    OUT PDWORD sec_flavor)
{
    if (RtlCompareUnicodeString(sec_flavor_name, &AUTH_SYS_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTH_SYS;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5I_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5I;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5P_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5P;
    else return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_CreateVNetRoot(
    IN OUT PMRX_CREATENETROOT_CONTEXT pCreateNetRootContext)
{
    NTSTATUS        status = STATUS_SUCCESS;
    NFS41_MOUNT_CONFIG Config;
    PMRX_V_NET_ROOT pVNetRoot = (PMRX_V_NET_ROOT)pCreateNetRootContext->pVNetRoot;
    PMRX_NET_ROOT   pNetRoot = pVNetRoot->pNetRoot;
    PMRX_SRV_CALL   pSrvCall = pNetRoot->pSrvCall;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(pVNetRoot);
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(pNetRoot);
    NFS41GetDeviceExtension(pCreateNetRootContext->RxContext,DevExt);
    DWORD nfs41d_version = DevExt->nfs41d_version;
    ASSERT((NodeType(pNetRoot) == RDBSS_NTC_NETROOT) &&
        (NodeType(pNetRoot->pSrvCall) == RDBSS_NTC_SRVCALL));

    DbgEn();
    print_srv_call(0, pSrvCall);
    print_net_root(0, pNetRoot);
    print_v_net_root(1, pVNetRoot);

    DbgP("pVNetRoot=%p pNetRoot=%p pSrvCall=%p\n", pVNetRoot, pNetRoot, pSrvCall);
    DbgP("pNetRoot=%wZ Type=%d pSrvCallName=%wZ VirtualNetRootStatus=0x%x "
        "NetRootStatus=0x%x\n", pNetRoot->pNetRootName, 
        pNetRoot->Type, pSrvCall->pSrvCallName, 
        pCreateNetRootContext->VirtualNetRootStatus, 
        pCreateNetRootContext->NetRootStatus);

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        print_error("Unsupported NetRoot Type %u\n", pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    /* In order to cooperate with other network providers, we must
     * only claim paths of the form '\\server\nfs4\path' */
    status = has_nfs_prefix(pSrvCall->pSrvCallName, pNetRoot->pNetRootName);
    if (status) {
        print_error("NetRootName %wZ doesn't match '\\nfs4'!\n",
            pNetRoot->pNetRootName);
        goto out;
    }
    pNetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
    pNetRoot->DeviceType = FILE_DEVICE_DISK;

    nfs41_MountConfig_InitDefaults(&Config);

    if (pCreateNetRootContext->RxContext->Create.EaLength) {
        /* parse the extended attributes for mount options */
        status = nfs41_MountConfig_ParseOptions(
            pCreateNetRootContext->RxContext->Create.EaBuffer,
            pCreateNetRootContext->RxContext->Create.EaLength,
            &Config);
        if (status != STATUS_SUCCESS)
            goto out;
    } else {
        /* use the SRV_CALL name (without leading \) as the hostname */
        Config.SrvName.Buffer = pSrvCall->pSrvCallName->Buffer + 1;
        Config.SrvName.Length =
            pSrvCall->pSrvCallName->Length - sizeof(WCHAR);
        Config.SrvName.MaximumLength =
            pSrvCall->pSrvCallName->MaximumLength - sizeof(WCHAR);
    }

    status = map_sec_flavor(&Config.SecFlavor, &pVNetRootContext->sec_flavor);
    if (status != STATUS_SUCCESS) {
        DbgP("Invalid rpcsec security flavor %wZ\n", &Config.SecFlavor);
        goto out;
    }

    if (pVNetRootContext->sec_flavor == RPCSEC_AUTH_SYS && 
            pNetRootContext->auth_sys_session) {
        pVNetRootContext->session = pNetRootContext->auth_sys_session;
        DbgP("Using existing AUTH_SYS session 0x%x\n", pVNetRootContext->session);
        goto out;
    } else if (pVNetRootContext->sec_flavor != RPCSEC_AUTH_SYS &&
                pNetRootContext->gss_session) {    
        pVNetRootContext->session = pNetRootContext->gss_session;
        DbgP("Using existing AUTHGSS session 0x%x\n", pVNetRootContext->session);
        goto out;
    }

    /* send the mount upcall */
    DbgP("Server Name %wZ Mount Point %wZ SecFlavor %wZ\n",
        &Config.SrvName, &Config.MntPt, &Config.SecFlavor);
    status = nfs41_mount(&Config.SrvName, &Config.MntPt, pVNetRootContext->sec_flavor,
        &pVNetRootContext->session, &nfs41d_version);
    if (status != STATUS_SUCCESS)
        goto out;
    pNetRootContext->nfs41d_version = nfs41d_version;
    pNetRootContext->do_umount = TRUE;
    if (pVNetRootContext->sec_flavor == RPCSEC_AUTH_SYS)
        pNetRootContext->auth_sys_session = pVNetRootContext->session;
    else
        pNetRootContext->gss_session = pVNetRootContext->session;
    DbgP("Saving new session 0x%x\n", pVNetRootContext->session);

out:
    /* AGLO do we need to worry about handling new netroot vs using existing one */
    pCreateNetRootContext->VirtualNetRootStatus = status;
    pCreateNetRootContext->NetRootStatus = status;
    DbgP("initiating net root callback with status %08lx\n", status);
    pCreateNetRootContext->Callback(pCreateNetRootContext);

    /* RDBSS expects that MRxCreateVNetRoot returns STATUS_PENDING 
     * on success or failure */
    status = STATUS_PENDING;

    DbgEx();
    return status;
}

VOID nfs41_ExtractNetRootName(
    IN PUNICODE_STRING FilePathName,
    IN PMRX_SRV_CALL   SrvCall,
    OUT PUNICODE_STRING NetRootName,
    OUT PUNICODE_STRING RestOfName OPTIONAL)
{
    ULONG length = FilePathName->Length;
    PWCH w = FilePathName->Buffer;
    PWCH wlimit = (PWCH)(((PCHAR)w)+length);
    PWCH wlow;

    DbgEn();
    DbgP("Input: pSrvCall %p\n", SrvCall);
    DbgP("Input: FilePathName=%wZ SrvCallName=%wZ\n", 
        FilePathName, SrvCall->pSrvCallName);

    w += (SrvCall->pSrvCallName->Length/sizeof(WCHAR));
    NetRootName->Buffer = wlow = w;
    /* parse the entire path into NetRootName */
#if USE_ENTIRE_PATH
    w = wlimit;
#else
    for (;;) {
        if (w >= wlimit)
            break;
        if ((*w == OBJ_NAME_PATH_SEPARATOR) && (w != wlow))
            break;
        w++;
    }
#endif
    NetRootName->Length = NetRootName->MaximumLength
                = (USHORT)((PCHAR)w - (PCHAR)wlow);
    DbgP("Output: NetRootName=%wZ\n", NetRootName);
    DbgR();
    return;

}

NTSTATUS nfs41_FinalizeSrvCall(
    PMRX_SRV_CALL    pSrvCall,
    BOOLEAN    Force)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry = (PNFS41_SERVER_ENTRY)(pSrvCall->Context);

    DbgEn();
    print_srv_call(0, pSrvCall);

    if (pSrvCall->Context == NULL)
        goto out;

    InterlockedCompareExchangePointer(&pServerEntry->pRdbssSrvCall, NULL, pSrvCall);
    DbgP("freeing server name %wZ and server entry %p\n", 
        &pServerEntry->Name, pServerEntry);
    RxFreePool(pServerEntry);

    pSrvCall->Context = NULL;
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_FinalizeNetRoot(
    IN OUT PMRX_NET_ROOT pNetRoot,
    IN     PBOOLEAN      ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension((PMRX_NET_ROOT)pNetRoot);
    nfs41_updowncall_entry *tmp;
    
    DbgEn();
    print_net_root(1, pNetRoot);

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (pNetRootContext == NULL || (pNetRootContext->auth_sys_session == NULL &&
            pNetRootContext->gss_session == NULL)) {
        print_error("No valid session has been established\n");
        goto out;
    }

    if (pNetRoot->NumberOfFcbs > 0 || pNetRoot->NumberOfSrvOpens > 0) {
        print_error("%d open Fcbs %d open SrvOpens\n", pNetRoot->NumberOfFcbs, 
            pNetRoot->NumberOfSrvOpens);
        goto out;
    }

    if (pNetRootContext->auth_sys_session && pNetRootContext->do_umount) {
        status = nfs41_unmount(pNetRootContext->auth_sys_session, pNetRootContext->nfs41d_version);
        if (status) {
            print_error("nfs41_mount AUTH_SYS failed with %d\n", status);
            goto out;
        }
    }
    if (pNetRootContext->gss_session) {
        status = nfs41_unmount(pNetRootContext->gss_session, pNetRootContext->nfs41d_version);
        if (status) {
            print_error("nfs41_mount AUTHGSS failed with %d\n", status);
            goto out;
        }
    }
    // check if there is anything waiting in the upcall or downcall queue
    do {
        nfs41_GetFirstEntry(upcallLock, upcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from upcall list\n");
            nfs41_RemoveEntry(upcallLock, upcall, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);

    do {
        nfs41_GetFirstEntry(downcallLock, downcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from downcall list\n");
            nfs41_RemoveEntry(downcallLock, downcall, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);
out:
    DbgEx();
    return status;
}


NTSTATUS nfs41_FinalizeVNetRoot(
    IN OUT PMRX_V_NET_ROOT pVNetRoot,
    IN     PBOOLEAN ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    print_v_net_root(1, pVNetRoot);
    if (pVNetRoot->pNetRoot->Type != NET_ROOT_DISK && 
            pVNetRoot->pNetRoot->Type != NET_ROOT_WILD)
        status = STATUS_NOT_SUPPORTED;
    DbgEx();
    return status;
}

BOOLEAN isDataAccess(ACCESS_MASK mask) 
{
    if ((mask & FILE_READ_DATA) ||
        (mask & FILE_WRITE_DATA) ||
        (mask & FILE_APPEND_DATA))
        return TRUE;
    return FALSE;
}

BOOLEAN has_file_changed(
    IN LONGLONG new_changeattr, 
    IN PFILE_BASIC_INFORMATION new_binfo, 
    IN PNFS41_FCB nfs41_fcb)
{
    if (new_changeattr != nfs41_fcb->changeattr && nfs41_fcb->changeattr)
        return TRUE;
    if (new_binfo->ChangeTime.QuadPart != nfs41_fcb->BasicInfo.ChangeTime.QuadPart)
        return TRUE;
    return FALSE;
}

void print_open_args(PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    //DbgP("RxContext->FsdUid %ld\n", RxContext->FsdUid);
    //DbgP("RxInferFileType returns %d\n", RxInferFileType(RxContext));
    print_nt_create_params(1, RxContext->Create.NtCreateParameters);
}

static NTSTATUS map_open_errors(DWORD status, int len)
{
    switch (status) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_ACCESS_DENIED:
        if (len > 0)                    return STATUS_NETWORK_ACCESS_DENIED;
        else                            return STATUS_SUCCESS;
    case ERROR_INVALID_NAME:            return STATUS_OBJECT_NAME_INVALID;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_FILENAME_EXCED_RANGE:    return STATUS_NAME_TOO_LONG;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_BAD_NETPATH:             return STATUS_BAD_NETWORK_PATH;
    case ERROR_SHARING_VIOLATION:       return STATUS_SHARING_VIOLATION;
    case ERROR_REPARSE:                 return STATUS_REPARSE;
    case ERROR_TOO_MANY_LINKS:          return STATUS_TOO_MANY_LINKS;
    default:
        print_error("[ERROR] nfs41_Create: upcall returned %d returning "
            "STATUS_INSUFFICIENT_RESOURCES\n", status);
    case ERROR_OUTOFMEMORY:             return STATUS_INSUFFICIENT_RESOURCES;
    }
}
static DWORD map_disposition_to_create_retval(DWORD disposition, DWORD errno)
{
    switch(disposition) {
    case FILE_SUPERSEDE:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_SUPERSEDED;
    case FILE_CREATE:                       return FILE_CREATED;
    case FILE_OPEN:                         return FILE_OPENED;
    case FILE_OPEN_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OPENED;
    case FILE_OVERWRITE:                    return FILE_OVERWRITTEN;
    case FILE_OVERWRITE_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OVERWRITTEN;
    default:
        print_error("unknown disposition %d\n", disposition);
        return FILE_OPENED;
    }
}

NTSTATUS nfs41_Create(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    __notnull PMRX_FCB Fcb = RxContext->pFcb;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    FCB_INIT_PACKET InitPacket;
    RX_FILE_TYPE StorageType = 0;
    NT_CREATE_PARAMETERS params = RxContext->Create.NtCreateParameters;
    nfs41_updowncall_entry *entry = NULL;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FOBX nfs41_fobx = NULL;
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)Fcb->Context;
    PFILE_FULL_EA_INFORMATION eainfo = NULL;
    nfs3_attrs *attrs = NULL;
    BOOLEAN file_changed = FALSE;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    ASSERT( NodeType(SrvOpen) == RDBSS_NTC_SRVOPEN );

    DbgEn();
    print_open_args(RxContext);
    if (RxContext->CurrentIrp->AssociatedIrp.SystemBuffer)
        print_ea_info(1, RxContext->CurrentIrp->AssociatedIrp.SystemBuffer);

    if (Fcb->pNetRoot->Type != NET_ROOT_DISK && 
            Fcb->pNetRoot->Type != NET_ROOT_WILD) {
        print_error("Unsupported NetRoot Type %u\n", Fcb->pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (FlagOn(Fcb->FcbState, FCB_STATE_PAGING_FILE )) {
        print_error("FCB_STATE_PAGING_FILE not implemented\n");
        status = STATUS_NOT_IMPLEMENTED;
        goto out;
    }
    
    if (pNetRootContext->auth_sys_session == NULL && pNetRootContext->gss_session == NULL) {
        print_error("No valid session established\n");
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_OPEN, NULL, pVNetRootContext->session, 
        INVALID_HANDLE_VALUE, pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.Open.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Open.access_mask = params.DesiredAccess;
    entry->u.Open.access_mode = params.ShareAccess;
    entry->u.Open.attrs = params.FileAttributes;
    entry->u.Open.disp = params.Disposition;
    entry->u.Open.copts = params.CreateOptions;
    if (isDataAccess(params.DesiredAccess))
        entry->u.Open.open_owner_id = get_next_open_owner();
    // if we are creating a file check if nfsv3attributes were passed in
    if (params.Disposition != FILE_OPEN && params.Disposition != FILE_OVERWRITE) {
        if (RxContext->CurrentIrp->AssociatedIrp.SystemBuffer) {
            eainfo = (PFILE_FULL_EA_INFORMATION)
                RxContext->CurrentIrp->AssociatedIrp.SystemBuffer;
            if (AnsiStrEq(&NfsV3Attributes, eainfo->EaName, eainfo->EaNameLength)) {
                attrs = (nfs3_attrs *)(eainfo->EaName + eainfo->EaNameLength + 1);
                DbgP("creating file with mode %o\n", attrs->mode); 
                entry->u.Open.mode = attrs->mode;
            }
        }
        if (!entry->u.Open.mode)
            entry->u.Open.mode = 0777;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    SeDeleteClientSecurity(&entry->sec_ctx);

    if (entry->status == NO_ERROR && entry->errno == ERROR_REPARSE) {
        /* symbolic link handling. when attempting to open a symlink when the
         * FILE_OPEN_REPARSE_POINT flag is not set, replace the filename with
         * the symlink target's by calling RxPrepareToReparseSymbolicLink()
         * and returning STATUS_REPARSE. the object manager will attempt to
         * open the new path, and return its handle for the original open */
        PRDBSS_DEVICE_OBJECT DeviceObject = RxContext->RxDeviceObject;
        PV_NET_ROOT VNetRoot = (PV_NET_ROOT)RxContext->pRelevantSrvOpen->pVNetRoot;
        PUNICODE_STRING VNetRootPrefix = &VNetRoot->PrefixEntry.Prefix;
        UNICODE_STRING AbsPath;
        PCHAR buf;
        BOOLEAN ReparseRequired;

        /* allocate the string for RxPrepareToReparseSymbolicLink(), and
         * format an absolute path "DeviceName+VNetRootName+symlink" */
        AbsPath.Length = DeviceObject->DeviceName.Length +
            VNetRootPrefix->Length + entry->u.Open.symlink.Length;
        AbsPath.MaximumLength = AbsPath.Length + sizeof(UNICODE_NULL);
        AbsPath.Buffer = RxAllocatePoolWithTag(NonPagedPool,
            AbsPath.MaximumLength, NFS41_MM_POOLTAG);
        if (AbsPath.Buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_free;
        }

        buf = (PCHAR)AbsPath.Buffer;
        RtlCopyMemory(buf, DeviceObject->DeviceName.Buffer, DeviceObject->DeviceName.Length);
        buf += DeviceObject->DeviceName.Length;
        RtlCopyMemory(buf, VNetRootPrefix->Buffer, VNetRootPrefix->Length);
        buf += VNetRootPrefix->Length;
        RtlCopyMemory(buf, entry->u.Open.symlink.Buffer, entry->u.Open.symlink.Length);
        RxFreePool(entry->u.Open.symlink.Buffer);
        buf += entry->u.Open.symlink.Length;
        *(PWCHAR)buf = UNICODE_NULL;

        status = RxPrepareToReparseSymbolicLink(RxContext,
            entry->u.Open.symlink_embedded, &AbsPath, TRUE, &ReparseRequired);
        DbgP("RxPrepareToReparseSymbolicLink(%u, '%wZ') returned %08lX, "
            "FileName is '%wZ'\n", entry->u.Open.symlink_embedded,
            &AbsPath, status, &RxContext->CurrentIrpSp->FileObject->FileName);
        if (status == STATUS_SUCCESS)
            status = ReparseRequired ? STATUS_REPARSE :
                STATUS_OBJECT_PATH_NOT_FOUND;
        goto out_free;
    }

    status = map_open_errors(entry->status, SrvOpen->pAlreadyPrefixedName->Length);
    if (status != STATUS_SUCCESS) {
        print_open_error(1, status);
        goto out_free;
    }

    if (!RxIsFcbAcquiredExclusive(Fcb)) {
        ASSERT(!RxIsFcbAcquiredShared(Fcb));
        RxAcquireExclusiveFcbResourceInMRx(Fcb);
    }

    RxContext->pFobx = RxCreateNetFobx(RxContext, SrvOpen);
    if( RxContext->pFobx == NULL ) {
        status =  STATUS_INSUFFICIENT_RESOURCES;
        goto out_free;
    }
    print_fobx(1, RxContext->pFobx);
    nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    nfs41_fobx->nfs41_open_state = entry->open_state;
    {
        SECURITY_SUBJECT_CONTEXT sec_ctx;
        SECURITY_QUALITY_OF_SERVICE sec_qos;
        SeCaptureSubjectContext(&sec_ctx);
        sec_qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        sec_qos.ImpersonationLevel = SecurityImpersonation;
        sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sec_qos.EffectiveOnly = 0;
        status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos, 1, &nfs41_fobx->sec_ctx);
        if (status != STATUS_SUCCESS) {
            print_error("SeCreateClientSecurityFromSubjectContext "
                "failed with %x\n", status);
            RxFreePool(entry);
        }
        DbgP("Created client security token %p\n", nfs41_fobx->sec_ctx.ClientToken);
        SeReleaseSubjectContext(&sec_ctx);
    }

    // we get attributes only for data access and file (not directories)
    if (Fcb->OpenCount > 0)
        file_changed = has_file_changed(entry->u.Open.changeattr, 
            &entry->u.Open.binfo, nfs41_fcb);
    if (Fcb->OpenCount == 0 || file_changed) {
        print_basic_info(1, &entry->u.Open.binfo);
        print_std_info(1, &entry->u.Open.sinfo);
        RtlCopyMemory(&nfs41_fcb->BasicInfo, &entry->u.Open.binfo, 
            sizeof(entry->u.Open.binfo));
        RtlCopyMemory(&nfs41_fcb->StandardInfo, &entry->u.Open.sinfo, 
            sizeof(entry->u.Open.sinfo));
        nfs41_fcb->mode = entry->u.Open.mode;
        nfs41_fcb->changeattr = entry->u.Open.changeattr;
        nfs41_fcb->Flags = FCB_BASIC_INFO_CACHED | FCB_STANDARD_INFO_CACHED;

        RxFormInitPacket(InitPacket,
            &entry->u.Open.binfo.FileAttributes,
            &entry->u.Open.sinfo.NumberOfLinks,
            &entry->u.Open.binfo.CreationTime,
            &entry->u.Open.binfo.LastAccessTime,
            &entry->u.Open.binfo.LastWriteTime,
            &entry->u.Open.binfo.ChangeTime,
            &entry->u.Open.sinfo.AllocationSize,
            &entry->u.Open.sinfo.EndOfFile,
            &entry->u.Open.sinfo.EndOfFile);

        if (entry->u.Open.sinfo.Directory)
            StorageType = FileTypeDirectory;
        else
            StorageType = FileTypeFile;

        RxFinishFcbInitialization(Fcb, RDBSS_STORAGE_NTC(StorageType), 
                                    &InitPacket);
    }
    else {
        DbgP("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
        if (nfs41_fcb->Flags) {
            print_basic_info(1, &nfs41_fcb->BasicInfo);
            print_std_info(1, &nfs41_fcb->StandardInfo);
        }
    }

    if (file_changed && !nfs41_fcb->StandardInfo.Directory) {
        ULONG flag = DISABLE_CACHING;
        DbgP("file object %wZ changed\n", SrvOpen->pAlreadyPrefixedName);
        RxIndicateChangeOfBufferingStateForSrvOpen(SrvOpen->pVNetRoot->pNetRoot->pSrvCall, 
            SrvOpen, SrvOpen->Key, ULongToPtr(flag));
    } else if (!file_changed && !nfs41_fcb->StandardInfo.Directory) {
#if 0
        SrvOpen->BufferingFlags |= FCB_STATE_DISABLE_LOCAL_BUFFERING;
#else
        // turn on read caching
        if (params.DesiredAccess & FILE_READ_DATA)
            SrvOpen->BufferingFlags |= 
                (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED);
        // turn on write caching only if the file opened for both reading and writing
        // we current CANT turn on write-only caching because RDBSS translates a write
        // into a read first which leads to a NFS4ERR_IO error from the server because 
        // the file was opened read-only.
        if (/*(params.DesiredAccess & FILE_READ_DATA) && */
                (params.DesiredAccess & FILE_WRITE_DATA || 
                params.DesiredAccess & FILE_APPEND_DATA))
            SrvOpen->BufferingFlags |= 
                (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
#endif
    }

    if (params.CreateOptions & FILE_WRITE_THROUGH ||
        params.CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING) {
            DbgP("Disable caching\n");
            SrvOpen->BufferingFlags |= FCB_STATE_DISABLE_LOCAL_BUFFERING;
    }

    if (params.CreateOptions & FILE_DELETE_ON_CLOSE) {
        DbgP("We need to delete this file on close\n");
        nfs41_fcb->StandardInfo.DeletePending = TRUE;
    }

    RxContext->Create.ReturnedCreateInformation = 
        map_disposition_to_create_retval(params.Disposition, entry->errno);

    RxContext->pFobx->OffsetOfNextEaToReturn = 1;
    RxContext->CurrentIrp->IoStatus.Information = 
        RxContext->Create.ReturnedCreateInformation;
    status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;

out_free:
    if (entry)
        RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_CollapseOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_ShouldTryToCollapseThisOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
    DbgEn();
    if (RxContext->pRelevantSrvOpen == NULL) 
        status = STATUS_SUCCESS;
    else
        print_debug_header(RxContext);

    DbgEx();
    return status;
}

ULONG nfs41_ExtendForCache(
    IN OUT PRX_CONTEXT      RxContext,
    IN     PLARGE_INTEGER   pNewFileSize,
    OUT    PLARGE_INTEGER   pNewAllocationSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;

    DbgEn();
    print_debug_header(RxContext);
    DbgP("input: byte count 0x%x filesize 0x%x alloc size 0x%x\n", 
        LowIoContext->ParamsFor.ReadWrite.ByteCount, *pNewFileSize, *pNewAllocationSize);
    pNewAllocationSize->QuadPart = pNewFileSize->QuadPart + 8192;
    nfs41_fcb->StandardInfo.AllocationSize.QuadPart = pNewAllocationSize->QuadPart;
    nfs41_fcb->StandardInfo.EndOfFile.QuadPart = pNewFileSize->QuadPart;
    DbgP("new filesize 0x%x new allocation size 0x%x\n", *pNewFileSize, 
        *pNewAllocationSize);

    DbgEx();
    return status;
}


ULONG nfs41_ExtendForNonCache(
    IN OUT PRX_CONTEXT      RxContext,
    IN     PLARGE_INTEGER   pNewFileSize,
       OUT PLARGE_INTEGER   pNewAllocationSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_Truncate (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_ZeroExtend(
    IN PRX_CONTEXT  RxContext
    )
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_CleanupFobx (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_CLOSE
    RxCaptureFcb;
    RxCaptureFobx;
    DbgEn();
    print_fcb(1, capFcb);
    print_fobx(1, capFobx);
    DbgEx();
#endif
    return status;
}

void print_close_args(PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
}

static NTSTATUS map_close_errors(DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_NETNAME_DELETED: return STATUS_NETWORK_NAME_DELETED;
    case ERROR_NOT_EMPTY:       return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_INVALID:    return STATUS_FILE_INVALID;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INTERNAL_ERROR\n", status);
    case ERROR_INTERNAL_ERROR: return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS nfs41_CloseSrvOpen (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_close_args(RxContext);

    status = nfs41_UpcallCreate(NFS41_CLOSE, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state, 
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    if (!RxContext->pFcb->OpenCount) {
        entry->u.Close.remove = nfs41_fcb->StandardInfo.DeletePending;
        entry->u.Close.renamed = nfs41_fcb->Renamed;
        entry->u.Close.filename = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    } else if (nfs41_fcb->StandardInfo.DeletePending && nfs41_fcb->StandardInfo.Directory) {
        entry->u.Close.remove = nfs41_fcb->StandardInfo.DeletePending;
        entry->u.Close.filename = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    /* map windows ERRORs to NTSTATUS */
    status = map_close_errors(entry->status);
    RxFreePool(entry);
    SeDeleteClientSecurity(&nfs41_fobx->sec_ctx);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_Flush(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_ForcedClose (
    IN OUT PMRX_SRV_OPEN SrvOpen)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_CLOSE
    DbgEn();
    print_srv_open(1, SrvOpen);
    print_fcb(1, SrvOpen->pFcb);
    print_v_net_root(1, SrvOpen->pVNetRoot);
#ifdef TESTING_CACHE_INVALIDATIO
    if (SrvOpen == saved_srv_open) {
        DbgP("closing saved SRV_OPEN\n");
        saved_srv_open = NULL;
        saved_srv_call = NULL;
    }
#endif
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_DeallocateForFcb (
    IN OUT PMRX_FCB pFcb)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_CLOSE
    DbgEn();
    print_fcb(1, pFcb);
    print_net_root(1, pFcb->pNetRoot);
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_DeallocateForFobx (
    IN OUT PMRX_FOBX pFobx)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_CLOSE
    DbgEn();
    print_fobx(1, pFobx);
    print_srv_open(1, pFobx->pSrvOpen);
    DbgEx();
#endif
    return status;
}

void print_debug_filedirquery_header(PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = %s\n", 
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext), 
        print_file_information_class(RxContext->Info.FileInformationClass));
}

void print_querydir_args(PRX_CONTEXT RxContext)
{
    print_debug_filedirquery_header(RxContext);
    DbgP("Filter='%wZ', Index=%d, Restart/Single/Specified/Init=%d/%d/%d/%d\n",
        &RxContext->pFobx->UnicodeQueryTemplate, RxContext->QueryDirectory.FileIndex,
        RxContext->QueryDirectory.RestartScan,
        RxContext->QueryDirectory.ReturnSingleEntry,
        RxContext->QueryDirectory.IndexSpecified,
        RxContext->QueryDirectory.InitialQuery);
}

static NTSTATUS map_querydir_errors(DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    case ERROR_FILE_NOT_FOUND:      return STATUS_NO_SUCH_FILE;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_NO_MORE_FILES:       return STATUS_NO_MORE_FILES;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryDirectory (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    PUNICODE_STRING Filter = &RxContext->pFobx->UnicodeQueryTemplate;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_querydir_args(RxContext);

    switch (InfoClass) {
        /* classes handled in readdir_copy_entry() and readdir_size_for_entry() */
    case FileNamesInformation:
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileIdBothDirectoryInformation:
        break;
    default:
        print_error("unhandled dir query class %d\n", InfoClass);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_DIR_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.QueryFile.InfoClass = InfoClass;
    entry->u.QueryFile.buf_len = RxContext->Info.LengthRemaining;
    entry->u.QueryFile.buf = RxContext->Info.Buffer;
    entry->u.QueryFile.filter = Filter;
    entry->u.QueryFile.initial_query = RxContext->QueryDirectory.InitialQuery;
    entry->u.QueryFile.restart_scan = RxContext->QueryDirectory.RestartScan;
    entry->u.QueryFile.return_single = RxContext->QueryDirectory.ReturnSingleEntry;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        print_error("ERROR: buffer too small provided %d need %d\n", 
            RxContext->Info.LengthRemaining, entry->u.QueryFile.buf_len);
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        RtlCopyMemory(RxContext->Info.Buffer, entry->u.QueryFile.buf, 
            entry->u.QueryFile.buf_len);
        RxContext->Info.LengthRemaining -= entry->u.QueryFile.buf_len;
        status = STATUS_SUCCESS;
    } else {
        /* map windows ERRORs to NTSTATUS */
        status = map_querydir_errors(entry->status);
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

void print_queryvolume_args(PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = %s BufferLen = %d\n", 
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext), 
        print_fs_information_class(RxContext->Info.FileInformationClass), 
        RxContext->Info.LengthRemaining);
}

static NTSTATUS map_volume_errors(DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_VC_DISCONNECTED:     return STATUS_CONNECTION_DISCONNECTED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryVolumeInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG   RemainingLength = RxContext->Info.LengthRemaining;
    FS_INFORMATION_CLASS InfoClass = RxContext->Info.FsInformationClass;
    ULONG   SizeUsed;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    nfs41_updowncall_entry *entry;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_queryvolume_args(RxContext);

    switch (InfoClass) {
        case FileFsVolumeInformation:
        {
            PFILE_FS_VOLUME_INFORMATION pVolInfo = RxContext->Info.Buffer;
            DECLARE_CONST_UNICODE_STRING(Label, L"PnfsLabel");

            SizeUsed = sizeof(FILE_FS_VOLUME_INFORMATION) + Label.Length;
            if (RemainingLength < SizeUsed) {
#if 0
                status = STATUS_BUFFER_TOO_SMALL;
                RxContext->InformationToReturn = SizeUsed;
#else
                /* Have to have status success for Notepad to be happy */
                status = STATUS_SUCCESS;
#endif
                goto out;
            }
            RtlZeroMemory(pVolInfo, sizeof(FILE_FS_VOLUME_INFORMATION));
            pVolInfo->VolumeCreationTime.QuadPart = 0;
            pVolInfo->VolumeSerialNumber = 0xBABAFACE;
            pVolInfo->SupportsObjects = FALSE;
            RtlCopyMemory(&pVolInfo->VolumeLabel[0], (PVOID)Label.Buffer, Label.Length);
            RxContext->Info.LengthRemaining -= SizeUsed;
            status = STATUS_SUCCESS;
            goto out;
        }

        case FileFsDeviceInformation:
        {
            PFILE_FS_DEVICE_INFORMATION pDevInfo = RxContext->Info.Buffer;

            SizeUsed = sizeof(FILE_FS_DEVICE_INFORMATION);
            if (RemainingLength < SizeUsed) {
                status = STATUS_BUFFER_TOO_SMALL;
                RxContext->InformationToReturn = SizeUsed;
                goto out;
            }
            RtlZeroMemory(pDevInfo, SizeUsed);
            pDevInfo->DeviceType = RxContext->pFcb->pNetRoot->DeviceType;
            pDevInfo->Characteristics = FILE_REMOTE_DEVICE; // | FILE_READ_ONLY_DEVICE;
            RxContext->Info.LengthRemaining -= SizeUsed;
            status = STATUS_SUCCESS;
            goto out;
        }

        case FileFsAttributeInformation:
            /* used cached fs attributes if available */
            if (pVNetRootContext->FsAttrsLen) {
                const LONG len = pVNetRootContext->FsAttrsLen;
                if (RxContext->Info.LengthRemaining < len) {
                    RxContext->InformationToReturn = len;
                    status = STATUS_BUFFER_TOO_SMALL;
                    goto out;
                }
                RtlCopyMemory(RxContext->Info.Buffer,
                    pVNetRootContext->FsAttrs, len);
                RxContext->Info.LengthRemaining -= len;
                status = STATUS_SUCCESS;
                goto out;
            }
            /* else fall through and send the upcall */
        case FileFsSizeInformation:
        case FileFsFullSizeInformation:
            break;

        default:
            print_error("unhandled fs query class %d\n", InfoClass);
            status = STATUS_INVALID_PARAMETER;
            goto out;
    }

    status = nfs41_UpcallCreate(NFS41_VOLUME_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state, 
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.Volume.query = InfoClass;
    entry->u.Volume.buf = RxContext->Info.Buffer;
    entry->u.Volume.buf_len = RxContext->Info.LengthRemaining;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.Volume.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        if (InfoClass == FileFsAttributeInformation) {
            /* fill in the FileSystemName */
            PFILE_FS_ATTRIBUTE_INFORMATION attrs =
                (PFILE_FS_ATTRIBUTE_INFORMATION)RxContext->Info.Buffer;
            DECLARE_CONST_UNICODE_STRING(FsName, FS_NAME);
            entry->u.Volume.buf_len += FsName.Length;
            if (entry->u.Volume.buf_len > RxContext->Info.LengthRemaining) {
                RxContext->InformationToReturn = entry->u.Volume.buf_len;
                status = STATUS_BUFFER_TOO_SMALL;
                goto out;
            }
            RtlCopyMemory(attrs->FileSystemName, FsName.Buffer,
                FsName.MaximumLength); /* 'MaximumLength' to include null */
            attrs->FileSystemNameLength = FsName.Length;

            /* save fs attributes with the vnetroot */
            if (entry->u.Volume.buf_len <= FS_ATTR_LEN) {
                RtlCopyMemory(&pVNetRootContext->FsAttrs,
                    RxContext->Info.Buffer, entry->u.Volume.buf_len);
                pVNetRootContext->FsAttrsLen = entry->u.Volume.buf_len;
            }
        }
        RxContext->Info.LengthRemaining -= entry->u.Volume.buf_len;
        status = STATUS_SUCCESS;
    } else {
        status = map_volume_errors(entry->status);
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_SetVolumeInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

void print_nfs3_attrs(nfs3_attrs *attrs)
{
    DbgP("type=%d mode=%o nlink=%d size=%d atime=%x mtime=%x ctime=%x\n",
        attrs->type, attrs->mode, attrs->nlink, attrs->size, attrs->atime,
        attrs->mtime, attrs->ctime);
}

void file_time_to_nfs_time(
    IN const PLARGE_INTEGER file_time,
    OUT LONGLONG *nfs_time)
{
    LARGE_INTEGER diff = unix_time_diff;
    diff.QuadPart = file_time->QuadPart - diff.QuadPart;
    *nfs_time = diff.QuadPart / 10000000;
}

void create_nfs3_attrs(nfs3_attrs *attrs, PNFS41_FCB nfs41_fcb)
{
    RtlZeroMemory(attrs, sizeof(nfs3_attrs));
    if (nfs41_fcb->BasicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        attrs->type = NF3LNK;
    else if (nfs41_fcb->StandardInfo.Directory)
        attrs->type = NF3DIR;
    else
        attrs->type = NF3REG;
    attrs->mode = nfs41_fcb->mode;
    attrs->nlink = nfs41_fcb->StandardInfo.NumberOfLinks;
    attrs->size.QuadPart = attrs->used.QuadPart = 
        nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.LastAccessTime, &attrs->atime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.ChangeTime, &attrs->mtime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.CreationTime, &attrs->ctime);
}

NTSTATUS nfs41_QueryEaInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    PFILE_GET_EA_INFORMATION query = (PFILE_GET_EA_INFORMATION)
        RxContext->CurrentIrpSp->Parameters.QueryEa.EaList;
    PFILE_FULL_EA_INFORMATION info;
    DbgEn();
    print_debug_header(RxContext);
    if (RxContext->CurrentIrpSp->Parameters.QueryEa.EaList) {
        DbgP("Looking for a specific EA?\n");
        print_get_ea(1, query);

        if (AnsiStrEq(&NfsV3Attributes, query->EaName, query->EaNameLength)) {
            nfs3_attrs attrs;

            const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
                NfsV3Attributes.Length + sizeof(nfs3_attrs) - sizeof(CHAR);
            if (LengthRequired > RxContext->Info.LengthRemaining) {
                status = STATUS_BUFFER_TOO_SMALL;
                RxContext->InformationToReturn = LengthRequired;
                goto out;
            }

            create_nfs3_attrs(&attrs, nfs41_fcb);
            DbgP("returning fake v3attrs EA\n");
            print_nfs3_attrs(&attrs);

            info = RxContext->Info.Buffer;
            info->NextEntryOffset = 0;
            info->Flags = 0;
            info->EaNameLength = (UCHAR)NfsV3Attributes.Length;
            info->EaValueLength = sizeof(nfs3_attrs);
            RtlCopyMemory(info->EaName, NfsV3Attributes.Buffer, NfsV3Attributes.Length);
            RtlCopyMemory(info->EaName + info->EaNameLength + 1, &attrs, 
                sizeof(nfs3_attrs));
            RxContext->Info.LengthRemaining = LengthRequired;
            status = STATUS_SUCCESS;
        } else if (AnsiStrEq(&NfsActOnLink, query->EaName, query->EaNameLength)
            || AnsiStrEq(&NfsSymlinkTargetName, query->EaName, query->EaNameLength)) {

            const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
                NfsActOnLink.Length - sizeof(CHAR);
            if (LengthRequired > RxContext->Info.LengthRemaining) {
                status = STATUS_BUFFER_TOO_SMALL;
                RxContext->InformationToReturn = LengthRequired;
                goto out;
            }

            DbgP("returning fake link EA\n");
            info = RxContext->Info.Buffer;
            info->NextEntryOffset = 0;
            info->Flags = 0;
            info->EaNameLength = (UCHAR)NfsActOnLink.Length;
            info->EaValueLength = 0;
            RtlCopyMemory(info->EaName, NfsActOnLink.Buffer, NfsActOnLink.Length);
            RxContext->Info.LengthRemaining = LengthRequired;
            status = STATUS_SUCCESS;
        } else
            print_error("Couldn't match %s\n", query->EaName);       
    }
out:
    DbgEx();
    return status;
}

static NTSTATUS map_setea_error(DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_NOT_EMPTY:               return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_IMPLEMENTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n", error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS nfs41_SetEaInformation (
    IN OUT struct _RX_CONTEXT *RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    PFILE_FULL_EA_INFORMATION eainfo = 
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer;        
    nfs3_attrs *attrs = NULL;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_debug_header(RxContext);
    print_ea_info(1, eainfo);
    if (AnsiStrEq(&NfsV3Attributes, eainfo->EaName, eainfo->EaNameLength)) {
        attrs = (nfs3_attrs *)(eainfo->EaName + eainfo->EaNameLength + 1);
        print_nfs3_attrs(attrs);
        DbgP("old mode is %x new mode is %x\n", nfs41_fcb->mode, attrs->mode);
        nfs41_fcb->mode = attrs->mode;
    } else
        goto out;

    status = nfs41_UpcallCreate(NFS41_EA_SET, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.SetEa.mode = attrs->mode;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_setea_error(entry->status);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

static void print_acl_args(SECURITY_INFORMATION info)
{
    DbgP("Security query: %s %s %s\n",
        (info & OWNER_SECURITY_INFORMATION)?"OWNER":"",
        (info & GROUP_SECURITY_INFORMATION)?"GROUP":"",
        (info & DACL_SECURITY_INFORMATION)?"DACL":"",
        (info & SACL_SECURITY_INFORMATION)?"SACL":"");
}

static NTSTATUS map_query_acl_error(DWORD error)
{
    switch (error) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_NOT_SUPPORTED:       return STATUS_NOT_SUPPORTED;
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:      return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QuerySecurityInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.SecurityInformation;

    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);

    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION)
        goto out;

    status = nfs41_UpcallCreate(NFS41_ACL_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.Acl.query = info_class;
    /* we can't provide RxContext->CurrentIrp->UserBuffer to the upcall thread 
     * because it becomes an invalid pointer with that execution context
     */
    entry->u.Acl.buf_len = RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length;
    DbgP("security buffer len %d\n", entry->u.Acl.buf_len); 

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        DbgP("nfs41_QuerySecurityInformation: provided buffer size=%d but we need %d\n",
                RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length, 
                entry->u.Acl.buf_len);
        status = STATUS_BUFFER_TOO_SMALL;
        RxContext->InformationToReturn = entry->u.Acl.buf_len;
    } else if (entry->status == STATUS_SUCCESS) {
        if (RtlValidSecurityDescriptor(entry->u.Acl.buf)) {
            DbgP("Received a valid security descriptor\n");
            if (MmIsAddressValid(RxContext->CurrentIrp->UserBuffer)) {
                PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
                    RxContext->CurrentIrp->UserBuffer;
                DbgP("Received a valid user pointer\n");
                RtlCopyMemory(sec_desc, entry->u.Acl.buf, entry->u.Acl.buf_len); 
            } else {
                DbgP("Received invalid user pointer\n");
                status = STATUS_INTERNAL_ERROR;
            }
        } else {
            DbgP("Received invalid security descriptor\n");
            status = STATUS_INTERNAL_ERROR;
        }
        RxFreePool(entry->u.Acl.buf);
        RxContext->IoStatusBlock.Information = RxContext->InformationToReturn = 
            entry->u.Acl.buf_len;
        if (!status)
            RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
    } else {
        status = map_query_acl_error(entry->status);
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_SetSecurityInformation (
    IN OUT struct _RX_CONTEXT *RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    PSECURITY_DESCRIPTOR sec_desc = RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityDescriptor;
    SECURITY_INFORMATION info_class = 
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityInformation;
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);

    /* check that ACL is present */
    if (info_class & DACL_SECURITY_INFORMATION) {
        PACL acl;
        BOOLEAN present, dacl_default;
        status = RtlGetDaclSecurityDescriptor(sec_desc, &present, &acl, &dacl_default);
        if (status) {
            DbgP("RtlGetDaclSecurityDescriptor failed %x\n", status);
            goto out;
        }
        if (present == FALSE) {
            DbgP("NO ACL present\n");
            goto out;
        }
    }

    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION)
        goto out;

    status = nfs41_UpcallCreate(NFS41_ACL_SET, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.Acl.query = info_class;
    entry->u.Acl.buf = sec_desc;
    entry->u.Acl.buf_len = RtlLengthSecurityDescriptor(sec_desc);

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    status = map_query_acl_error(entry->status);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_QueryQuotaInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_SetQuotaInformation (
    IN OUT struct _RX_CONTEXT *RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_SetVolumeInfo (
    IN OUT struct _RX_CONTEXT *RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED; //STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

void print_queryfile_args(PRX_CONTEXT RxContext)
{
    print_debug_filedirquery_header(RxContext);
}

static NTSTATUS map_queryfile_error(DWORD error)
{
    switch (error) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryFileInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    switch (InfoClass) {
    case FileEaInformation:
    {
        PFILE_EA_INFORMATION info =
            (PFILE_EA_INFORMATION)RxContext->Info.Buffer;
        info->EaSize = 0;
        RxContext->Info.LengthRemaining -= sizeof(FILE_EA_INFORMATION);
        status = STATUS_SUCCESS;
        goto out;
    }
#ifdef FCB_ATTR_CACHING
    case FileBasicInformation:
        if(nfs41_fcb->Flags & FCB_BASIC_INFO_CACHED) {
            RtlCopyMemory(RxContext->Info.Buffer, &nfs41_fcb->BasicInfo, 
                sizeof(nfs41_fcb->BasicInfo));
            RxContext->Info.LengthRemaining -= sizeof(nfs41_fcb->BasicInfo);
            status = STATUS_SUCCESS;
            goto out;
        }
        break;
    case FileStandardInformation:
        if(nfs41_fcb->Flags & FCB_STANDARD_INFO_CACHED) {
            RtlCopyMemory(RxContext->Info.Buffer, &nfs41_fcb->StandardInfo, 
                sizeof(nfs41_fcb->StandardInfo));
            RxContext->Info.LengthRemaining -= sizeof(nfs41_fcb->StandardInfo);
            status = STATUS_SUCCESS;
            goto out;
        }
        break;
#else
    case FileBasicInformation:
    case FileStandardInformation:
#endif
    case FileInternalInformation: 
    case FileAttributeTagInformation:
        break;
    default:
        print_error("unhandled file query class %d\n", InfoClass);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    print_queryfile_args(RxContext);

    status = nfs41_UpcallCreate(NFS41_FILE_QUERY, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.QueryFile.InfoClass = InfoClass;
    entry->u.QueryFile.buf = RxContext->Info.Buffer;
    entry->u.QueryFile.buf_len = RxContext->Info.LengthRemaining;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        BOOLEAN DeletePending = FALSE;
        RxContext->Info.LengthRemaining -= entry->u.QueryFile.buf_len;
        status = STATUS_SUCCESS;

        switch (InfoClass) {
        case FileBasicInformation:
            RtlCopyMemory(&nfs41_fcb->BasicInfo, RxContext->Info.Buffer, 
                sizeof(nfs41_fcb->BasicInfo));
            nfs41_fcb->Flags |= FCB_BASIC_INFO_CACHED;
            print_basic_info(1, &nfs41_fcb->BasicInfo);
            break;
        case FileStandardInformation:
#ifndef FCB_ATTR_CACHING
            /* this a fix for RDBSS behaviour when it first calls ExtendForCache,
             * then it sends a file query irp for standard attributes and 
             * expects to receive EndOfFile of value set by the ExtendForCache.
             * It seems to cache the filesize based on that instead of sending
             * a file size query for after doing the write. 
             */
        {
            PFILE_STANDARD_INFORMATION std_info;
            std_info = (PFILE_STANDARD_INFORMATION)RxContext->Info.Buffer;
            if (nfs41_fcb->StandardInfo.AllocationSize.QuadPart > 
                    std_info->AllocationSize.QuadPart) {
                DbgP("Old AllocationSize is bigger: saving %x\n", 
                    nfs41_fcb->StandardInfo.AllocationSize.QuadPart);
                std_info->AllocationSize.QuadPart = 
                    nfs41_fcb->StandardInfo.AllocationSize.QuadPart;
            }
            if (nfs41_fcb->StandardInfo.EndOfFile.QuadPart > 
                    std_info->EndOfFile.QuadPart) {
                DbgP("Old EndOfFile is bigger: saving %x\n", 
                    nfs41_fcb->StandardInfo.EndOfFile);
                std_info->EndOfFile.QuadPart = 
                    nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
            }
        }
#endif
            if (nfs41_fcb->StandardInfo.DeletePending)
                DeletePending = TRUE;
            RtlCopyMemory(&nfs41_fcb->StandardInfo, RxContext->Info.Buffer, 
                sizeof(nfs41_fcb->StandardInfo));
            nfs41_fcb->StandardInfo.DeletePending = DeletePending;
            nfs41_fcb->Flags |= FCB_STANDARD_INFO_CACHED;
            print_std_info(1, &nfs41_fcb->StandardInfo);
            break;
        }
    } else {
        status = map_queryfile_error(entry->status);
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

void print_setfile_args(PRX_CONTEXT RxContext)
{
    print_debug_filedirquery_header(RxContext);
}

static NTSTATUS map_setfile_error(DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_NOT_EMPTY:               return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_NOT_SAME_DEVICE:         return STATUS_NOT_SAME_DEVICE;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_IMPLEMENTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n", error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS nfs41_SetFileInformation (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    PUNICODE_STRING FileName = GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    FILE_RENAME_INFORMATION rinfo;
    PFILE_OBJECT fo = RxContext->CurrentIrpSp->FileObject;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_setfile_args(RxContext);
    switch (InfoClass) {
    case FileRenameInformation:
    {
        PFILE_RENAME_INFORMATION rinfo = 
            (PFILE_RENAME_INFORMATION)RxContext->Info.Buffer;
        UNICODE_STRING dst = { (USHORT)rinfo->FileNameLength,
            (USHORT)rinfo->FileNameLength, rinfo->FileName };
        if (rinfo->RootDirectory) {
            status = STATUS_NOT_SUPPORTED;
            goto out;
        }
        DbgP("Attempting to rename to '%wZ'\n", dst);
        nfs41_fcb->Flags = 0;
    }
    break;
    case FileLinkInformation:
    {
        PFILE_LINK_INFORMATION linfo = 
            (PFILE_LINK_INFORMATION)RxContext->Info.Buffer;
        UNICODE_STRING dst = { (USHORT)linfo->FileNameLength,
            (USHORT)linfo->FileNameLength, linfo->FileName };
        if (linfo->RootDirectory) {
            status = STATUS_NOT_SUPPORTED;
            goto out;
        }
        DbgP("Attempting to add link as '%wZ'\n", dst);
        nfs41_fcb->Flags = 0;
    }
    break;
    case FileDispositionInformation:
    {
        PFILE_DISPOSITION_INFORMATION dinfo =
            (PFILE_DISPOSITION_INFORMATION)RxContext->Info.Buffer;
        if (dinfo->DeleteFile) {
            // we can delete directories right away
            if (nfs41_fcb->StandardInfo.Directory)
                break;
            nfs41_fcb->Flags = 0;
            nfs41_fcb->StandardInfo.DeletePending = TRUE;
            if (RxContext->pFcb->OpenCount > 1) {
                rinfo.ReplaceIfExists = 0;
                rinfo.RootDirectory = INVALID_HANDLE_VALUE;
                rinfo.FileNameLength = 0;
                rinfo.FileName[0] = L'\0';
                InfoClass = FileRenameInformation;
                nfs41_fcb->Renamed = TRUE;
                break;
            }
        }
        status = STATUS_SUCCESS;
        goto out;
    }
    case FileBasicInformation:
    case FileAllocationInformation:
        nfs41_fcb->Flags = 0;
        break;
    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION info =
            (PFILE_END_OF_FILE_INFORMATION)RxContext->Info.Buffer;
        nfs41_fcb->StandardInfo.AllocationSize =
            nfs41_fcb->StandardInfo.EndOfFile = info->EndOfFile;
        nfs41_fcb->Flags = 0;
        break;
    }
    default:
        print_error("unknown set_file information class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_FILE_SET, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.SetFile.filename = FileName;
    entry->u.SetFile.InfoClass = InfoClass;
    switch(InfoClass) {
    case FileAllocationInformation:
    case FileEndOfFileInformation:
        entry->u.SetFile.open_owner_id = get_next_open_owner();
        if (fo->ReadAccess)
            entry->u.SetFile.access_mask = FILE_READ_DATA;
        if (fo->WriteAccess)
            entry->u.SetFile.access_mask |= FILE_WRITE_DATA;
        if (fo->SharedRead)
            entry->u.SetFile.access_mode = FILE_SHARE_READ;
        if (fo->SharedWrite)
            entry->u.SetFile.access_mode |= FILE_SHARE_WRITE;
    }
    if (RxContext->Info.FileInformationClass == FileDispositionInformation && 
        InfoClass == FileRenameInformation) {
        entry->u.SetFile.buf = &rinfo;
        entry->u.SetFile.buf_len = sizeof(rinfo);
    } else {
        entry->u.SetFile.buf = RxContext->Info.Buffer;
        entry->u.SetFile.buf_len = RxContext->Info.Length;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_setfile_error(entry->status);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_SetFileInformationAtCleanup(
      IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    DbgEn();
    status = nfs41_SetFileInformation(RxContext);
    DbgEx();
    return status;
}

NTSTATUS nfs41_IsValidDirectory (
    IN OUT PRX_CONTEXT RxContext,
    IN PUNICODE_STRING DirectoryName)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_PreparseName(
    IN OUT PRX_CONTEXT  RxContext,
    IN PUNICODE_STRING  Name
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    //DbgEn();
    //DbgEx();
    return status;
}

NTSTATUS nfs41_ComputeNewBufferingState(
    IN OUT PMRX_SRV_OPEN pSrvOpen,
    IN     PVOID         pMRxContext,
       OUT ULONG         *pNewBufferingState)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG flag;
    DbgEn();
    flag = PtrToUlong(pMRxContext);
    DbgP("pSrvOpen %p Flags %08x\n", pSrvOpen, pSrvOpen->BufferingFlags);
    switch(flag) {
    case DISABLE_CACHING:
        if (pSrvOpen->BufferingFlags & 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED))
            pSrvOpen->BufferingFlags &= 
                ~(FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED);
        if (pSrvOpen->BufferingFlags & 
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED))
            pSrvOpen->BufferingFlags &= 
                ~(FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
        pSrvOpen->BufferingFlags |= FCB_STATE_DISABLE_LOCAL_BUFFERING;
        break;
    case ENABLE_READ_CACHING:
        pSrvOpen->BufferingFlags |= 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED);
        break;
    case ENABLE_WRITE_CACHING:
        pSrvOpen->BufferingFlags |= 
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
        break;
    case ENABLE_READWRITE_CACHING:
        pSrvOpen->BufferingFlags = 
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED | 
            FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
    }
    DbgP("new Flags %08x\n", pSrvOpen->BufferingFlags);
    *pNewBufferingState = pSrvOpen->BufferingFlags;

    DbgEx();
    return status;
}

void print_readwrite_args(PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    PIO_STACK_LOCATION IrpSp = RxContext->CurrentIrpSp;
    PIRP Irp = RxContext->CurrentIrp;

    print_debug_header(RxContext);
    DbgP("Irp flags: paging io %ld noncachedio %ld syncio %ld\n", 
        FlagOn(Irp->Flags, IRP_PAGING_IO), 
        FlagOn(Irp->Flags, IRP_NOCACHE), 
        FlagOn(IrpSp->FileObject->Flags, FO_SYNCHRONOUS_IO));
    DbgP("Bytecount 0x%x Byteoffset 0x%x Buffer %p\n", 
        LowIoContext->ParamsFor.ReadWrite.ByteCount, 
        LowIoContext->ParamsFor.ReadWrite.ByteOffset, 
        LowIoContext->ParamsFor.ReadWrite.Buffer);
}

void enable_caching(PMRX_SRV_OPEN SrvOpen)
{
    ULONG flag = 0;
    if (SrvOpen->DesiredAccess & FILE_READ_DATA)
        flag = ENABLE_READ_CACHING;
    if (SrvOpen->DesiredAccess & FILE_WRITE_DATA)
        flag = ENABLE_WRITE_CACHING;
    if ((SrvOpen->DesiredAccess & FILE_READ_DATA) && 
        (SrvOpen->DesiredAccess & FILE_WRITE_DATA))
        flag = ENABLE_READWRITE_CACHING;

    print_caching_level(1, flag);

    if (!flag)
        return;

    RxIndicateChangeOfBufferingStateForSrvOpen(SrvOpen->pVNetRoot->pNetRoot->pSrvCall, 
        SrvOpen, SrvOpen->Key, ULongToPtr(flag));
}

static NTSTATUS map_readwrite_errors(DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_HANDLE_EOF:              return STATUS_END_OF_FILE;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    case ERROR_LOCK_VIOLATION:          return STATUS_FILE_LOCK_CONFLICT;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_NET_WRITE_FAULT\n", status);
    case ERROR_NET_WRITE_FAULT:         return STATUS_NET_WRITE_FAULT;
    }
}

NTSTATUS nfs41_Read (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    BOOLEAN async = FALSE;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_readwrite_args(RxContext);

    status = nfs41_UpcallCreate(NFS41_READ, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->u.ReadWrite.len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;
    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags, FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (async) {
        DbgP("This is asynchronous read, returning control back to the user\n");
        status = STATUS_PENDING;
        goto out;
    }

    if (entry->status == NO_ERROR) {
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->u.ReadWrite.len;
        nfs41_fcb->Flags = 0;

        if (!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags, 
                LOWIO_READWRITEFLAG_PAGING_IO) && 
                (SrvOpen->DesiredAccess & FILE_READ_DATA) &&
                !(SrvOpen->BufferingFlags & 
                (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED)))
            enable_caching(SrvOpen);
    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_Write (
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_FCB nfs41_fcb = (PNFS41_FCB)(RxContext->pFcb)->Context;
    BOOLEAN async = FALSE;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_readwrite_args(RxContext);

    status = nfs41_UpcallCreate(NFS41_WRITE, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->u.ReadWrite.len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;

    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags, FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (async) {
        DbgP("This is asynchronous write, returning control back to the user\n");
        status = STATUS_PENDING;
        goto out;
    }
    
    if (entry->status == NO_ERROR) {
        //update cached file attributes
        nfs41_fcb->StandardInfo.EndOfFile.QuadPart = entry->u.ReadWrite.len + 
            entry->u.ReadWrite.offset;
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->u.ReadWrite.len;
        nfs41_fcb->Flags = 0;
        
        if (!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags, 
                LOWIO_READWRITEFLAG_PAGING_IO) && 
                (SrvOpen->DesiredAccess & FILE_WRITE_DATA) &&
                (SrvOpen->DesiredAccess & FILE_READ_DATA) &&
                !(SrvOpen->BufferingFlags & 
                (FCB_STATE_WRITEBUFFERING_ENABLED | FCB_STATE_WRITECACHING_ENABLED)))
            enable_caching(SrvOpen);
    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_IsLockRealizable (
    IN OUT PMRX_FCB pFcb,
    IN PLARGE_INTEGER  ByteOffset,
    IN PLARGE_INTEGER  Length,
    IN ULONG  LowIoLockFlags)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        ByteOffset->QuadPart,Length->QuadPart,
        BooleanFlagOn(LowIoLockFlags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(LowIoLockFlags, SL_FAIL_IMMEDIATELY));
    DbgEx();
    return status;
}

static NTSTATUS map_lock_errors(DWORD status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_LOCK_FAILED:         return STATUS_LOCK_NOT_GRANTED;
    case ERROR_NOT_LOCKED:          return STATUS_RANGE_NOT_LOCKED;
    case ERROR_ATOMIC_LOCKS_NOT_SUPPORTED: return STATUS_UNSUCCESSFUL;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_SHARING_VIOLATION:   return STATUS_SHARING_VIOLATION;
    case ERROR_FILE_INVALID:        return STATUS_FILE_INVALID;
    /* if we return ERROR_INVALID_PARAMETER, Windows translates that to
     * success!! */
    case ERROR_INVALID_PARAMETER:   return STATUS_LOCK_NOT_GRANTED;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static void print_lock_args(PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    print_debug_header(RxContext);
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        LowIoContext->ParamsFor.Locks.ByteOffset,
        LowIoContext->ParamsFor.Locks.Length,
        BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY));
}


/* use exponential backoff between polls for blocking locks */
#define MSEC_TO_RELATIVE_WAIT   (-10000)
#define MIN_LOCK_POLL_WAIT      (500 * MSEC_TO_RELATIVE_WAIT) /* 500ms */
#define MAX_LOCK_POLL_WAIT      (30000 * MSEC_TO_RELATIVE_WAIT) /* 30s */

static void denied_lock_backoff(
    IN OUT PLARGE_INTEGER delay)
{
    if (delay->QuadPart == 0)
        delay->QuadPart = MIN_LOCK_POLL_WAIT;
    else
        delay->QuadPart <<= 1;

    if (delay->QuadPart < MAX_LOCK_POLL_WAIT)
        delay->QuadPart = MAX_LOCK_POLL_WAIT;
}

NTSTATUS nfs41_Lock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    LARGE_INTEGER poll_delay = {0};
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_lock_args(RxContext);

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_LOCK, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;
    entry->u.Lock.offset = LowIoContext->ParamsFor.Locks.ByteOffset;
    entry->u.Lock.length = LowIoContext->ParamsFor.Locks.Length;
    entry->u.Lock.exclusive = BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK);
    entry->u.Lock.blocking = !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY);

retry_upcall:
    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    /* blocking locks keep trying until it succeeds */
    if (entry->status == ERROR_LOCK_FAILED && entry->u.Lock.blocking) {
        denied_lock_backoff(&poll_delay);
        DbgP("returned ERROR_LOCK_FAILED; retrying in %llums\n",
            poll_delay.QuadPart / MSEC_TO_RELATIVE_WAIT);
        KeDelayExecutionThread(KernelMode, FALSE, &poll_delay);
        entry->state = NFS41_WAITING_FOR_UPCALL;
        goto retry_upcall;
    }

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;

    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

static void print_unlock_args(PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    print_debug_header(RxContext);
    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        PLOWIO_LOCK_LIST lock = LowIoContext->ParamsFor.Locks.LockList;
        DbgP("LOWIO_OP_UNLOCK_MULTIPLE:");
        while (lock) {
            DbgP(" (offset=%llu, length=%llu)", lock->ByteOffset, lock->Length);
            lock = lock->Next;
        }
        DbgP("\n");
    } else {
        DbgP("LOWIO_OP_UNLOCK: offset=%llu, length=%llu\n",
            LowIoContext->ParamsFor.Locks.ByteOffset,
            LowIoContext->ParamsFor.Locks.Length);
    }
}

static __inline ULONG unlock_list_count(PLOWIO_LOCK_LIST lock)
{
    ULONG count = 0;
    while (lock) {
        count++;
        lock = lock->Next;
    }
    return count;
}

NTSTATUS nfs41_Unlock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PNFS41_FOBX nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_lock_args(RxContext);

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_UNLOCK, &nfs41_fobx->sec_ctx, 
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;

    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        entry->u.Unlock.count = unlock_list_count(
            LowIoContext->ParamsFor.Locks.LockList);
        RtlCopyMemory(&entry->u.Unlock.locks,
            LowIoContext->ParamsFor.Locks.LockList,
            sizeof(LOWIO_LOCK_LIST));
    } else {
        entry->u.Unlock.count = 1;
        entry->u.Unlock.locks.ByteOffset =
            LowIoContext->ParamsFor.Locks.ByteOffset;
        entry->u.Unlock.locks.Length =
            LowIoContext->ParamsFor.Locks.Length;
    }

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

static NTSTATUS map_symlink_errors(NTSTATUS status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_INVALID_REPARSE_DATA: return STATUS_IO_REPARSE_DATA_INVALID;
    case ERROR_NOT_A_REPARSE_POINT: return STATUS_NOT_A_REPARSE_POINT;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INSUFFICIENT_BUFFER: return STATUS_BUFFER_TOO_SMALL;
    case STATUS_BUFFER_TOO_SMALL:
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    default:
        print_error("failed to map windows error %d to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static void print_reparse_buffer(PREPARSE_DATA_BUFFER Reparse)
{
    UNICODE_STRING name;
    DbgP("ReparseTag:           %08X\n", Reparse->ReparseTag);
    DbgP("ReparseDataLength:    %8u\n", Reparse->ReparseDataLength);
    DbgP("Reserved:             %8u\n", Reparse->Reserved);
    DbgP("SubstituteNameOffset: %8u\n", Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset);
    DbgP("SubstituteNameLength: %8u\n", Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength);
    DbgP("PrintNameOffset:      %8u\n", Reparse->SymbolicLinkReparseBuffer.PrintNameOffset);
    DbgP("PrintNameLength:      %8u\n", Reparse->SymbolicLinkReparseBuffer.PrintNameLength);
    DbgP("Flags:                %08X\n", Reparse->SymbolicLinkReparseBuffer.Flags);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength;
    DbgP("SubstituteName:       %wZ\n", &name);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    DbgP("PrintName:            %wZ\n", &name);
}

static NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    UNICODE_STRING TargetName;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    PNFS41_FOBX Fobx = NFS41GetFileObjectExtension(RxContext->pFobx);
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION VNetRoot = NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    nfs41_updowncall_entry *entry;
    NTSTATUS status;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();
    print_reparse_buffer(Reparse);

    if (Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        status = STATUS_IO_REPARSE_TAG_MISMATCH;
        goto out;
    }

    TargetName.MaximumLength = TargetName.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    TargetName.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx, 
        VNetRoot->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;

    entry->u.Symlink.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = TRUE;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    status = map_symlink_errors(entry->status);
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

static NTSTATUS nfs41_GetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    UNICODE_STRING TargetName;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    PNFS41_FOBX Fobx = NFS41GetFileObjectExtension(RxContext->pFobx);
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PNFS41_V_NET_ROOT_EXTENSION VNetRoot = NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    nfs41_updowncall_entry *entry;
    const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
        SymbolicLinkReparseBuffer.PathBuffer);
    NTSTATUS status;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);

    DbgEn();

    if (!BooleanFlagOn(RxContext->pFcb->Attributes,
        FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_NOT_A_REPARSE_POINT;
        DbgP("FILE_ATTRIBUTE_REPARSE_POINT is not set!\n");
        goto out;
    }

    if (FsCtl->OutputBufferLength < HeaderLen) {
        RxContext->InformationToReturn = HeaderLen;
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    TargetName.Buffer = (PWCH)((PBYTE)FsCtl->pOutputBuffer + HeaderLen);
    TargetName.MaximumLength = (USHORT)min(FsCtl->OutputBufferLength - HeaderLen, 0xFFFF);

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx, 
        VNetRoot->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, &entry);
    if (status)
        goto out;

    entry->u.Symlink.filename = SrvOpen->pAlreadyPrefixedName;
    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = FALSE;

    if (nfs41_UpcallWaitForReply(entry) != STATUS_SUCCESS) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    status = map_symlink_errors(entry->status);
    if (status == STATUS_SUCCESS) {
        /* fill in the output buffer */
        PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pOutputBuffer;
        Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
        Reparse->Reserved = 0;
        Reparse->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        /* PrintName and SubstituteName point to the same string */
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength = TargetName.Length;
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength = TargetName.Length;
        print_reparse_buffer(Reparse);

        RxContext->IoStatusBlock.Information = HeaderLen + TargetName.Length;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = HeaderLen + TargetName.Length;
    }
    RxFreePool(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_FsCtl(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    DbgEn();
    print_debug_header(RxContext);
    DbgP("FileName: %wZ\n", &RxContext->CurrentIrpSp->FileObject->FileName);
    switch (RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode) {
    case FSCTL_SET_REPARSE_POINT:
        DbgP("FSCTL_SET_REPARSE_POINT\n");
        status = nfs41_SetReparsePoint(RxContext);
        break;

    case FSCTL_GET_REPARSE_POINT:
        DbgP("FSCTL_GET_REPARSE_POINT\n");
        status = nfs41_GetReparsePoint(RxContext);
        break;
    default:
        DbgP("FsControlCode: %d\n", RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode);
    }
    DbgEx();
    return status;
}

NTSTATUS nfs41_IoCtl(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_NotifyChangeDirectory(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_CompleteBufferingStateChangeRequest (
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PMRX_SRV_OPEN   SrvOpen,
    IN     PVOID       pContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    DbgEn();
    DbgEx();
    return status;
}

NTSTATUS nfs41_AreFilesAliased(
    PFCB  Fcb1, 
    PFCB  Fcb2)
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    PMRX_SRV_OPEN srv1 = (PMRX_SRV_OPEN)Fcb1->InternalSrvOpen, 
        srv2 = (PMRX_SRV_OPEN)Fcb2->InternalSrvOpen;
    DbgEn();
    DbgP("fcb1 %p fcb2 %p srv1 %p srv2 %p\n", Fcb1, Fcb2, srv1, srv2);
    DbgP("file1 %wZ file2 %wZ\n", srv1->pAlreadyPrefixedName, 
        srv2->pAlreadyPrefixedName); 
    DbgEx();
    return status;
}

NTSTATUS nfs41_GetConnectionId(
    IN OUT PRX_CONTEXT RxContext,    
    IN OUT PRX_CONNECTION_ID UniqueId)
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    //DbgEn();
    //DbgEx();
    return status;
}

NTSTATUS nfs41_FsdDispatch (
    IN PDEVICE_OBJECT dev,
    IN PIRP Irp
    )
{
#ifdef DEBUG_FSDDISPATCH
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
#endif
    NTSTATUS status;

#ifdef DEBUG_FSDDISPATCH
    DbgEn();
    DbgP("CURRENT IRP = %d.%d\n", IrpSp->MajorFunction, IrpSp->MinorFunction);
    if(IrpSp->FileObject)
        DbgP("FileOject %p Filename %wZ\n", IrpSp->FileObject, 
                &IrpSp->FileObject->FileName);
    switch(IrpSp->MajorFunction) {
    case 0:
        DbgP("Create: share access %d\n", IrpSp->Parameters.Create.ShareAccess);
        break;
    case 5:
        DbgP("InfoClass %d\n", IrpSp->Parameters.QueryFile.FileInformationClass);
        break;
    }
#endif

    if (dev != (PDEVICE_OBJECT)nfs41_dev) {
        print_error("*** not ours ***\n");
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT );
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto out;
    }

    status = RxFsdDispatch((PRDBSS_DEVICE_OBJECT)dev,Irp);
    /* AGLO: 08/05/2009 - looks like RxFsdDispatch frees IrpSp */

out:
#ifdef DEBUG_FSDDISPATCH
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_init_ops()
{
    DbgEn();

    ZeroAndInitializeNodeType(&nfs41_ops, RDBSS_NTC_MINIRDR_DISPATCH, 
        sizeof(MINIRDR_DISPATCH));

    nfs41_ops.MRxFlags = (RDBSS_MANAGE_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_V_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_FCB_EXTENSION |
                            RDBSS_MANAGE_SRV_OPEN_EXTENSION |
                            RDBSS_MANAGE_FOBX_EXTENSION);

    nfs41_ops.MRxSrvCallSize  = 0; // srvcall extension is not handled in rdbss
    nfs41_ops.MRxNetRootSize  = sizeof(NFS41_NETROOT_EXTENSION);
    nfs41_ops.MRxVNetRootSize = sizeof(NFS41_V_NET_ROOT_EXTENSION);
    nfs41_ops.MRxFcbSize      = sizeof(NFS41_FCB);
    nfs41_ops.MRxSrvOpenSize  = sizeof(NFS41_SRV_OPEN);
    nfs41_ops.MRxFobxSize     = sizeof(NFS41_FOBX);

    // Mini redirector cancel routine ..
    
    nfs41_ops.MRxCancel = NULL;

    //
    // Mini redirector Start/Stop. Each mini-rdr can be started or stopped
    // while the others continue to operate.
    //

    nfs41_ops.MRxStart                = nfs41_Start;
    nfs41_ops.MRxStop                 = nfs41_Stop;
    nfs41_ops.MRxDevFcbXXXControlFile = nfs41_DevFcbXXXControlFile;

    //
    // Mini redirector name resolution.
    //

    nfs41_ops.MRxCreateSrvCall       = nfs41_CreateSrvCall;
    nfs41_ops.MRxSrvCallWinnerNotify = nfs41_SrvCallWinnerNotify;
    nfs41_ops.MRxCreateVNetRoot      = nfs41_CreateVNetRoot;
    nfs41_ops.MRxExtractNetRootName  = nfs41_ExtractNetRootName;
    nfs41_ops.MRxFinalizeSrvCall     = nfs41_FinalizeSrvCall;
    nfs41_ops.MRxFinalizeNetRoot     = nfs41_FinalizeNetRoot;
    nfs41_ops.MRxFinalizeVNetRoot    = nfs41_FinalizeVNetRoot;

    //
    // File System Object Creation/Deletion.
    //

    nfs41_ops.MRxCreate            = nfs41_Create;
    nfs41_ops.MRxCollapseOpen      = nfs41_CollapseOpen;
    nfs41_ops.MRxShouldTryToCollapseThisOpen = nfs41_ShouldTryToCollapseThisOpen;
    nfs41_ops.MRxExtendForCache    = nfs41_ExtendForCache;
    nfs41_ops.MRxExtendForNonCache = nfs41_ExtendForCache;
    nfs41_ops.MRxZeroExtend        = nfs41_ZeroExtend;
    nfs41_ops.MRxTruncate          = nfs41_Truncate;
    nfs41_ops.MRxCleanupFobx       = nfs41_CleanupFobx;
    nfs41_ops.MRxCloseSrvOpen      = nfs41_CloseSrvOpen;
    nfs41_ops.MRxFlush             = nfs41_Flush;
    nfs41_ops.MRxForceClosed       = nfs41_ForcedClose;
    nfs41_ops.MRxDeallocateForFcb  = nfs41_DeallocateForFcb;
    nfs41_ops.MRxDeallocateForFobx = nfs41_DeallocateForFobx;
    nfs41_ops.MRxIsLockRealizable    = nfs41_IsLockRealizable;
    //
    // File System Objects query/Set
    //

    nfs41_ops.MRxQueryDirectory       = nfs41_QueryDirectory;
    nfs41_ops.MRxQueryVolumeInfo      = nfs41_QueryVolumeInformation;
    nfs41_ops.MRxSetVolumeInfo        = nfs41_SetVolumeInfo;
    nfs41_ops.MRxQueryEaInfo          = nfs41_QueryEaInformation;
    nfs41_ops.MRxSetEaInfo            = nfs41_SetEaInformation;
    nfs41_ops.MRxQuerySdInfo          = nfs41_QuerySecurityInformation;
    nfs41_ops.MRxSetSdInfo            = nfs41_SetSecurityInformation;
    nfs41_ops.MRxQueryQuotaInfo       = nfs41_QueryQuotaInformation;
    nfs41_ops.MRxSetQuotaInfo         = nfs41_SetQuotaInformation;
    nfs41_ops.MRxQueryFileInfo        = nfs41_QueryFileInformation;
    nfs41_ops.MRxSetFileInfo          = nfs41_SetFileInformation;
    nfs41_ops.MRxSetFileInfoAtCleanup = nfs41_SetFileInformationAtCleanup ;
    //
    // Buffering state change
    //

    nfs41_ops.MRxComputeNewBufferingState = nfs41_ComputeNewBufferingState;

    //
    // File System Object I/O
    //

    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_READ]            = nfs41_Read;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_WRITE]           = nfs41_Write;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_SHAREDLOCK]      = nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_EXCLUSIVELOCK]   = nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK]          = nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK_MULTIPLE] = nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_FSCTL]           = nfs41_FsCtl;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_IOCTL]           = nfs41_IoCtl;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_NOTIFY_CHANGE_DIRECTORY] = 
        nfs41_NotifyChangeDirectory;

    //
    // Miscellanous
    //

    nfs41_ops.MRxCompleteBufferingStateChangeRequest = 
        nfs41_CompleteBufferingStateChangeRequest;
    nfs41_ops.MRxIsValidDirectory     = nfs41_IsValidDirectory;
    nfs41_ops.MRxPreparseName         = nfs41_PreparseName;
    
    nfs41_ops.MRxAreFilesAliased = nfs41_AreFilesAliased;
    nfs41_ops.MRxGetConnectionId = nfs41_GetConnectionId;

    DbgR();
    return(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT drv, IN PUNICODE_STRING path)
{
    NTSTATUS status;
    ULONG flags = 0, i;
    UNICODE_STRING dev_name, user_dev_name;
    PNFS41_DEVICE_EXTENSION dev_exts;
    TIME_FIELDS jan_1_1970 = {1970, 1, 1, 0, 0, 0, 0, 0};

    DbgEn();

    status = RxDriverEntry(drv, path);
    if (status != STATUS_SUCCESS) {
        print_error("RxDriverEntry failed: %08lx\n", status);
        goto out;
    }

    RtlInitUnicodeString(&dev_name, NFS41_DEVICE_NAME);
    SetFlag(flags, RX_REGISTERMINI_FLAG_DONT_PROVIDE_MAILSLOTS);

    status = nfs41_init_ops();
    if (status != STATUS_SUCCESS) {
        print_error("nfs41_init_ops failed to initialize dispatch table\n");
        goto out;
    }

    DbgP("calling RxRegisterMinirdr\n");
    status = RxRegisterMinirdr(&nfs41_dev, drv, &nfs41_ops, flags, &dev_name,
                sizeof(NFS41_DEVICE_EXTENSION), 
                FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE);
    if (status != STATUS_SUCCESS) {
        print_error("RxRegisterMinirdr failed: %08lx\n", status);
        goto out;
    }
    nfs41_dev->Flags |= DO_BUFFERED_IO;

    dev_exts = (PNFS41_DEVICE_EXTENSION)
        ((PBYTE)(nfs41_dev) + sizeof(RDBSS_DEVICE_OBJECT));

    RxDefineNode(dev_exts, NFS41_DEVICE_EXTENSION);
    dev_exts->DeviceObject = nfs41_dev;

    RtlInitUnicodeString(&user_dev_name, NFS41_SHADOW_DEVICE_NAME);
    DbgP("calling IoCreateSymbolicLink %wZ %wZ\n", &user_dev_name, &dev_name);
    status = IoCreateSymbolicLink(&user_dev_name, &dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("Device name IoCreateSymbolicLink failed: %08lx\n", status);
        goto out_unregister;
    }

    KeInitializeEvent(&upcallEvent, SynchronizationEvent, FALSE );
    ExInitializeFastMutex(&upcallLock);
    ExInitializeFastMutex(&downcallLock);
    ExInitializeFastMutex(&xidLock);
    ExInitializeFastMutex(&openOwnerLock);
    upcall = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_list), 
                NFS41_MM_POOLTAG);
    if (upcall == NULL) 
        goto out_unregister;
    InitializeListHead(&upcall->head);
    downcall = RxAllocatePoolWithTag(NonPagedPool, sizeof(nfs41_updowncall_list), 
                NFS41_MM_POOLTAG);
    if (downcall == NULL) {
        RxFreePool(upcall);
        goto out_unregister;
    }
    InitializeListHead(&downcall->head);

    drv->DriverUnload = nfs41_driver_unload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv->MajorFunction[i] = (PDRIVER_DISPATCH)nfs41_FsdDispatch;

    RtlTimeFieldsToTime(&jan_1_1970, &unix_time_diff);

out_unregister:
    if (status != STATUS_SUCCESS)
        RxUnregisterMinirdr(nfs41_dev);
out:
    DbgEx();
    return status;
}

VOID nfs41_driver_unload(IN PDRIVER_OBJECT drv)
{
    PRX_CONTEXT RxContext;
    NTSTATUS    status;
    UNICODE_STRING dev_name, pipe_name;

    DbgEn();

    RxContext = RxCreateRxContext(NULL, nfs41_dev, RX_CONTEXT_FLAG_IN_FSP);
    if (RxContext == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto unload;
    }
    status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
    RxDereferenceAndDeleteRxContext(RxContext);

unload:
    RtlInitUnicodeString(&dev_name, NFS41_SHADOW_DEVICE_NAME);
    status = IoDeleteSymbolicLink(&dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete device symbolic link\n");
    }
    RtlInitUnicodeString(&pipe_name, NFS41_SHADOW_PIPE_NAME);
    status = IoDeleteSymbolicLink(&pipe_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete pipe symbolic link\n");
    }
    if (upcall) 
        RxFreePool(upcall);
    if (downcall)
        RxFreePool(downcall);
    RxUnload(drv);

    DbgP("driver unloaded %p\n", drv);
    DbgR();
}
