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

#ifndef __NFS41_DAEMON_TYPES_H__
#define __NFS41_DAEMON_TYPES_H__

#include "wintirpc.h"
#include "rpc/xdr.h"
#include "nfs41_const.h"

typedef char*       caddr_t;

static const int64_t    NFS4_INT64_MAX      = 0x7fffffffffffffff;
static const uint64_t   NFS4_UINT64_MAX     = 0xffffffffffffffff;
static const int32_t    NFS4_INT32_MAX      = 0x7fffffff;
static const uint32_t   NFS4_UINT32_MAX     = 0xffffffff;

static const uint64_t   NFS4_MAXFILELEN     = 0xffffffffffffffff;
static const uint64_t   NFS4_MAXFILEOFF     = 0xfffffffffffffffe;


/* common nfs types */
typedef struct __nfs41_abs_path {
    char            path[NFS41_MAX_PATH_LEN];
    unsigned short  len;
    SRWLOCK         lock;
} nfs41_abs_path;

typedef struct __nfs41_component {
    const char      *name;
    unsigned short  len;
} nfs41_component;

typedef struct __nfs41_fh {
    unsigned char   fh[NFS4_FHSIZE];
    uint32_t        len;
    uint64_t        fileid;
    struct __nfs41_superblock *superblock;
} nfs41_fh;

typedef struct __nfs41_path_fh {
    nfs41_abs_path  *path;
    nfs41_component name;
    nfs41_fh        fh;
} nfs41_path_fh;

typedef struct __nfs41_fsid {
    uint64_t        major;
    uint64_t        minor;
} nfs41_fsid;

typedef struct __nfs41_readdir_cookie {
    uint64_t        cookie;
    unsigned char   verf[NFS4_VERIFIER_SIZE];
} nfs41_readdir_cookie;

typedef struct __netaddr4 {
    char            netid[NFS41_NETWORK_ID_LEN+1];
    char            uaddr[NFS41_UNIVERSAL_ADDR_LEN+1];
} netaddr4;

typedef struct __multi_addr4 {
    netaddr4        arr[NFS41_ADDRS_PER_SERVER];
    uint32_t        count;
} multi_addr4;

typedef struct __bitmap4 {
    uint32_t        count;
    uint32_t        arr[3];
} bitmap4;

typedef struct __nfstime4 {
    int64_t         seconds;
    uint32_t        nseconds;
} nfstime4;

typedef struct __client_owner4 {
    unsigned char   co_verifier[NFS4_VERIFIER_SIZE];
    uint32_t        co_ownerid_len;
    unsigned char   co_ownerid[NFS4_OPAQUE_LIMIT];
} client_owner4;

typedef struct __server_owner4 {
    uint64_t        so_minor_id;
    uint32_t        so_major_id_len;
    char            so_major_id[NFS4_OPAQUE_LIMIT];
} server_owner4;

typedef struct __state_owner4 {
    uint32_t        owner_len;
    unsigned char   owner[NFS4_OPAQUE_LIMIT];
} state_owner4;

typedef struct __nfs_impl_id4 {
    uint32_t        nii_domain_len;
    unsigned char   *nii_domain;
    uint32_t        nii_name_len;
    unsigned char   *nii_name;
    nfstime4        nii_date;
} nfs_impl_id4;

typedef struct __nfsace4 {
    uint32_t        acetype;
    uint32_t        aceflag;
    uint32_t        acemask;
    unsigned char   who[NFS4_OPAQUE_LIMIT];
} nfsace4;

typedef struct __stateid4 {
    uint32_t        seqid;
    unsigned char   other[NFS4_STATEID_OTHER];
} stateid4;

typedef struct __fattr4 {
    bitmap4         attrmask;
    uint32_t        attr_vals_len;
    unsigned char   attr_vals[NFS4_OPAQUE_LIMIT];
} fattr4;

typedef struct __change_info4 {
    bool_t          atomic;
    uint64_t        before;
    uint64_t        after;
} change_info4;

typedef struct __fs_location_server {
    /* 'address' represents one of a traditional DNS host name,
     * IPv4 address, IPv6 address, or a zero-length string */
    char            address[NFS41_HOSTNAME_LEN+1];
} fs_location_server;

typedef struct __fs_location4 {
    nfs41_abs_path  path; /* path to fs from referred server's root */
    fs_location_server *servers;
    uint32_t        server_count;
} fs_location4;

typedef struct __fs_locations4 {
    nfs41_abs_path  path; /* path to fs from referring server's root */
    fs_location4    *locations;
    uint32_t        location_count;
} fs_locations4;

enum {
    MDSTHRESH_READ = 0,
    MDSTHRESH_WRITE,
    MDSTHRESH_READ_IO,
    MDSTHRESH_WRITE_IO,

    MAX_MDSTHRESH_HINTS
};
typedef struct __threshold_item4 {
    uint32_t        type;
    uint64_t        hints[MAX_MDSTHRESH_HINTS];
} threshold_item4;

#define MAX_MDSTHRESHOLD_ITEMS 1
typedef struct __mdsthreshold4 {
    uint32_t        count;
    threshold_item4 items[MAX_MDSTHRESHOLD_ITEMS];
} mdsthreshold4;

typedef struct __nfs41_file_info {
    nfs41_fsid              fsid;
    mdsthreshold4           mdsthreshold;
    nfstime4                time_access;
    nfstime4                time_create;
    nfstime4                time_modify;
    nfstime4                *time_delta; /* XXX: per-fs */
    bitmap4                 attrmask;
    bitmap4                 *supported_attrs; /* XXX: per-fs */
    uint64_t                maxread; /* XXX: per-fs */
    uint64_t                maxwrite; /* XXX: per-fs */
    uint64_t                change;
    uint64_t                size;
    uint64_t                fileid;
    uint64_t                space_avail; /* XXX: per-fs */
    uint64_t                space_free; /* XXX: per-fs */
    uint64_t                space_total; /* XXX: per-fs */
    uint32_t                type;
    uint32_t                numlinks;
    uint32_t                rdattr_error;
    uint32_t                mode;
    uint32_t                mode_mask;
    fs_locations4           *fs_locations; /* XXX: per-fs */
    uint32_t                lease_time; /* XXX: per-server */
    uint32_t                fs_layout_types; /* pnfs, XXX: per-fs */
    bool_t                  hidden;
    bool_t                  cansettime; /* XXX: per-fs */
    bool_t                  case_insensitive;
    bool_t                  case_preserving;
    bool_t                  symlink_dir;
    bool_t                  symlink_support;
    bool_t                  link_support;
    unsigned char           owner[NFS4_OPAQUE_LIMIT];
    uint32_t                owner_len;
    unsigned char           owner_group[NFS4_OPAQUE_LIMIT];
    uint32_t                owner_group_len;
    uint32_t                aclsupport;
} nfs41_file_info;

#endif /* !__NFS41_DAEMON_TYPES_H__ */
