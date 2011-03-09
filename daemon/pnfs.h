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

#ifndef __PNFS_H__
#define __PNFS_H__

#include "nfs41_types.h"
#include "list.h"


/* preprocessor options */
#ifndef PNFS_DISABLE

# ifndef PNFS_DISABLE_READ
#  define PNFS_ENABLE_READ
# endif
# ifndef PNFS_DISABLE_WRITE
#  define PNFS_ENABLE_WRITE
# endif

# define PNFS_THREADING
# define PNFS_THREAD_BY_SERVER

#endif


/* forward declarations from nfs41.h */
struct __nfs41_client;
struct __nfs41_session;
struct __nfs41_open_state;
struct __nfs41_root;


/* pnfs error values, in order of increasing severity */
enum pnfs_status {
    PNFS_SUCCESS            = 0,
    PNFS_PENDING,
    PNFS_READ_EOF,
    PNFSERR_NOT_SUPPORTED,
    PNFSERR_NOT_CONNECTED,
    PNFSERR_IO,
    PNFSERR_NO_DEVICE,
    PNFSERR_NO_LAYOUT,
    PNFSERR_INVALID_FH_LIST,
    PNFSERR_INVALID_DS_INDEX,
    PNFSERR_RESOURCES,
    PNFSERR_LAYOUT_RECALLED,
    PNFSERR_LAYOUT_CHANGED,
};

enum pnfs_layout_type {
    PNFS_LAYOUTTYPE_FILE    = 1,
    PNFS_LAYOUTTYPE_OBJECT  = 2,
    PNFS_LAYOUTTYPE_BLOCK   = 3
};

enum pnfs_iomode {
    PNFS_IOMODE_READ        = 0x1,
    PNFS_IOMODE_RW          = 0x2,
    PNFS_IOMODE_ANY         = PNFS_IOMODE_READ | PNFS_IOMODE_RW
};

enum pnfs_layout_status {
    /* LAYOUTGET was successful, and the layout has not been returned or
     * otherwise revoked by the server */
    PNFS_LAYOUT_GRANTED     = 0x01,
    /* GETDEVICEINFO was successful, and we have a valid 'device' pointer */
    PNFS_LAYOUT_HAS_DEVICE  = 0x02,
    /* CB_LAYOUTRECALL indicated that the server has recalled this layout,
     * and it should be returned on completion of any pending io */
    PNFS_LAYOUT_RECALLED    = 0x04,
    /* CB_LAYOUTRECALL indicated that the layout is changing, and "the client
     * SHOULD NOT write and commit modified data to the storage devices!" */
    PNFS_LAYOUT_CHANGED     = 0x08,

    /* a LAYOUTGET error indicated that this layout will never be granted */
    PNFS_LAYOUT_UNAVAILABLE = 0x10,
    /* LAYOUTGET returned BADIOMODE, so a RW layout will never be granted */
    PNFS_LAYOUT_NOT_RW      = 0x20,
};

enum pnfs_device_status {
    /* GETDEVICEINFO was successful */
    PNFS_DEVICE_GRANTED     = 0x1,
    /* a bulk recall or lease expiration led to device invalidation */
    PNFS_DEVICE_REVOKED     = 0x2,
};

enum pnfs_return_type {
    PNFS_RETURN_FILE        = 1,
    PNFS_RETURN_FSID        = 2,
    PNFS_RETURN_ALL         = 3
};

#define NFL4_UFLG_MASK                  0x0000003F
#define NFL4_UFLG_DENSE                 0x00000001
#define NFL4_UFLG_COMMIT_THRU_MDS       0x00000002
#define NFL4_UFLG_STRIPE_UNIT_SIZE_MASK 0xFFFFFFC0

#define PNFS_DEVICEID_SIZE              16


/* device */
typedef struct __pnfs_device {
    unsigned char           deviceid[PNFS_DEVICEID_SIZE];
    enum pnfs_layout_type   type;
    enum pnfs_device_status status;
    uint32_t                layout_count; /* layouts using this device */
    CRITICAL_SECTION        lock;
} pnfs_device;

typedef struct __pnfs_stripe_indices {
    uint32_t                count;
    uint32_t                *arr;
} pnfs_stripe_indices;

typedef struct __pnfs_data_server {
    struct __nfs41_client   *client;
    multi_addr4             addrs;
    SRWLOCK                 lock;
} pnfs_data_server;

typedef struct __pnfs_data_server_list {
    uint32_t                count;
    pnfs_data_server        *arr;
} pnfs_data_server_list;

typedef struct __pnfs_file_device {
    pnfs_device             device;
    pnfs_stripe_indices     stripes;
    pnfs_data_server_list   servers;
    struct pnfs_file_device_list *devices; /* -> nfs41_client.devices */
    struct list_entry       entry; /* position in devices */
} pnfs_file_device;


/* layout */
typedef struct __pnfs_layout_state {
    nfs41_fh                meta_fh;
    stateid4                stateid;
    struct list_entry       entry; /* position in nfs41_client.layouts */
    struct __pnfs_file_layout *layout;
    enum pnfs_layout_status status;
    bool_t                  return_on_close;
    LONG                    open_count; /* for return on last close */
    uint32_t                io_count; /* number of pending io operations */
    SRWLOCK                 lock;
} pnfs_layout_state;

typedef struct __pnfs_layout {
    struct list_entry       entry;
    uint64_t                offset;
    uint64_t                length;
    enum pnfs_iomode        iomode;
    enum pnfs_layout_type   type;
} pnfs_layout;

typedef struct __pnfs_file_layout_handles {
    uint32_t                count;
    nfs41_path_fh           *arr;
} pnfs_file_layout_handles;

typedef struct __pnfs_file_layout {
    pnfs_layout             layout;
    pnfs_file_layout_handles filehandles;
    unsigned char           deviceid[PNFS_DEVICEID_SIZE];
    pnfs_file_device        *device;
    uint64_t                pattern_offset;
    uint32_t                first_index;
    uint32_t                util;
} pnfs_file_layout;

typedef struct __pnfs_layout_recall {
    enum pnfs_layout_type   type;
    enum pnfs_iomode        iomode;
    bool_t                  changed;

    enum pnfs_return_type   recall;
    union {
        struct {
            nfs41_fh        fh;
            stateid4        stateid;
        } file;
        nfs41_fsid          fsid;
    } args;
} pnfs_layout_recall;


/* io */
typedef struct __pnfs_io_pattern {
    struct __pnfs_io_thread *threads;
    struct __nfs41_root     *root;
    struct __nfs41_open_state *state;
    pnfs_file_layout        *layout;
    unsigned char           *buffer;
    uint64_t                offset_start;
    uint64_t                offset_end;
    uint32_t                count;
    uint32_t                default_lease;
} pnfs_io_pattern;

typedef struct __pnfs_io_thread {
    pnfs_io_pattern         *pattern;
    uint64_t                offset;
    uint64_t                offset_end;
    uint32_t                id;
    enum stable_how4        stable;
} pnfs_io_thread;

typedef struct __pnfs_io_unit {
    nfs41_path_fh           *file;
    unsigned char           *buffer;
    uint64_t                offset;
    uint64_t                length;
    uint32_t                stripeid;
    uint32_t                serverid;
} pnfs_io_unit;

typedef uint32_t (WINAPI *pnfs_io_thread_fn)(void*);


/* pnfs_layout.c */
struct pnfs_layout_list;
struct cb_layoutrecall_args;

enum pnfs_status pnfs_layout_list_create(
    OUT struct pnfs_layout_list **layouts_out);

void pnfs_layout_list_free(
    IN struct pnfs_layout_list *layouts);

enum pnfs_status pnfs_layout_state_open(
    IN struct pnfs_layout_list *layouts,
    IN struct __nfs41_session *session,
    IN struct __nfs41_open_state *state,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length,
    OUT pnfs_layout_state **layout_out);

void pnfs_layout_state_close(
    IN struct __nfs41_session *session,
    IN struct __nfs41_open_state *state,
    IN bool_t remove);

enum pnfs_status pnfs_file_layout_recall(
    IN struct __nfs41_client *client,
    IN const struct cb_layoutrecall_args *recall);

enum pnfs_status pnfs_layout_io_start(
    IN pnfs_layout_state *state);

void pnfs_layout_io_finished(
    IN pnfs_layout_state *state);


__inline int is_dense(
    IN const pnfs_file_layout *layout)
{
    return (layout->util & NFL4_UFLG_DENSE) != 0;
}
__inline int should_commit_to_mds(
    IN const pnfs_file_layout *layout)
{
    return (layout->util & NFL4_UFLG_COMMIT_THRU_MDS) != 0;
}
__inline uint32_t layout_unit_size(
    IN const pnfs_file_layout *layout)
{
    return layout->util & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK;
}


/* pnfs_device.c */
struct pnfs_file_device_list;

enum pnfs_status pnfs_file_device_list_create(
    OUT struct pnfs_file_device_list **devices_out);

void pnfs_file_device_list_free(
    IN struct pnfs_file_device_list *devices);

void pnfs_file_device_list_invalidate(
    IN struct pnfs_file_device_list *devices);

enum pnfs_status pnfs_file_device_get(
    IN struct __nfs41_session *session,
    IN struct pnfs_file_device_list *devices,
    IN unsigned char *deviceid,
    OUT pnfs_file_device **device_out);

void pnfs_file_device_put(
    IN pnfs_file_device *device);

enum pnfs_status pnfs_data_server_client(
    IN struct __nfs41_root *root,
    IN pnfs_data_server *server,
    IN uint32_t default_lease,
    OUT struct __nfs41_client **client_out);

enum pnfs_status pnfs_file_device_io_unit(
    IN pnfs_io_pattern *pattern,
    IN uint64_t offset,
    OUT pnfs_io_unit *io);


__inline uint64_t stripe_unit_number(
    IN pnfs_file_layout *layout,
    IN uint64_t offset,
    IN uint32_t unit_size)
{
    const uint64_t relative_offset = offset - layout->pattern_offset;
    return relative_offset / unit_size;
}
__inline uint32_t stripe_index(
    IN pnfs_file_layout *layout,
    IN uint64_t sui,
    IN uint32_t stripe_count)
{
    return (uint32_t)((sui + layout->first_index) % stripe_count);
}
__inline uint32_t data_server_index(
    IN pnfs_file_device *device,
    IN uint32_t stripeid)
{
    return device->stripes.arr[stripeid];
}


/* pnfs_io.c */
enum pnfs_status pnfs_read(
    IN struct __nfs41_root *root,
    IN struct __nfs41_session *session,
    IN struct __nfs41_open_state *state,
    IN pnfs_file_layout *layout,
    IN uint64_t offset,
    IN uint64_t length,
    OUT unsigned char *buffer_out,
    OUT ULONG *len_out);

enum pnfs_status pnfs_write(
    IN struct __nfs41_root *root,
    IN struct __nfs41_session *session,
    IN struct __nfs41_open_state *state,
    IN pnfs_file_layout *layout,
    IN uint64_t offset,
    IN uint64_t length,
    IN unsigned char *buffer,
    OUT ULONG *len_out);

#endif /* !__PNFS_H__ */
