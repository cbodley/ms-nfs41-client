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
#include <stdio.h>

#include "daemon_debug.h"
#include "nfs41.h"
#include "nfs41_ops.h"
#include "util.h"


#define SBLVL 3 /* dprintf level for superblock logging */


static __inline int compare_fsid(
    IN const nfs41_fsid *lhs,
    IN const nfs41_fsid *rhs)
{
    if (lhs->major > rhs->major) return 1;
    if (lhs->major < rhs->major) return -1;
    if (lhs->minor > rhs->minor) return 1;
    if (lhs->minor < rhs->minor) return -1;
    return 0;
}


/* nfs41_superblock */
static int superblock_create(
    IN const nfs41_fsid *fsid,
    OUT nfs41_superblock **superblock_out)
{
    int status = NO_ERROR;
    nfs41_superblock *superblock;

    dprintf(SBLVL, "creating superblock for fsid(%llu,%llu)\n",
        fsid->major, fsid->minor);

    superblock = calloc(1, sizeof(nfs41_superblock));
    if (superblock == NULL) {
        status = GetLastError();
        eprintf("failed to allocate superblock "
            "for fsid(%llu,%llu)\n", fsid->major, fsid->minor);
        goto out;
    }

    memcpy(&superblock->fsid, fsid, sizeof(nfs41_fsid));
    InitializeSRWLock(&superblock->lock);

    *superblock_out = superblock;
out:
    return status;
}

static int get_superblock_attrs(
    IN nfs41_session *session,
    IN nfs41_superblock *superblock,
    IN nfs41_path_fh *file)
{
    int status;
    bitmap4 attr_request;
    nfs41_file_info info;

    attr_request.arr[0] = FATTR4_WORD0_SUPPORTED_ATTRS |
        FATTR4_WORD0_LINK_SUPPORT | FATTR4_WORD0_SYMLINK_SUPPORT |
        FATTR4_WORD0_ACLSUPPORT | FATTR4_WORD0_CANSETTIME |
        FATTR4_WORD0_CASE_INSENSITIVE | FATTR4_WORD0_CASE_PRESERVING |
        FATTR4_WORD0_MAXREAD | (uint32_t)(FATTR4_WORD0_MAXWRITE);
    attr_request.arr[1] = FATTR4_WORD1_FS_LAYOUT_TYPE |
        FATTR4_WORD1_TIME_DELTA;
    attr_request.count = 2;

    ZeroMemory(&info, sizeof(info));
    info.supported_attrs = &superblock->supported_attrs;
    info.time_delta = &superblock->time_delta;

    status = nfs41_getattr(session, file, &attr_request, &info);
    if (status) {
        eprintf("nfs41_getattr() failed with %s when "
            "fetching attributes for fsid(%llu,%llu)\n",
            nfs_error_string(status),
            superblock->fsid.major, superblock->fsid.minor);
        goto out;
    }

    if (info.maxread)
        superblock->maxread = info.maxread;
    else
        superblock->maxread = session->fore_chan_attrs.ca_maxresponsesize;

    if (info.maxwrite)
        superblock->maxwrite = info.maxwrite;
    else
        superblock->maxwrite = session->fore_chan_attrs.ca_maxrequestsize;

    superblock->layout_types = info.fs_layout_types;
    superblock->aclsupport = info.aclsupport;
    superblock->link_support = info.link_support;
    superblock->symlink_support = info.symlink_support;
    superblock->case_preserving = info.case_preserving;
    superblock->case_insensitive = info.case_insensitive;

    if (bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CANSETTIME))
        superblock->cansettime = info.cansettime;
    else /* cansettime is not supported, try setting them anyway */
        superblock->cansettime = 1;

    /* if time_delta is not supported, default to 1s */
    if (!bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_TIME_DELTA))
        superblock->time_delta.seconds = 1;

    dprintf(SBLVL, "attributes for fsid(%llu,%llu): "
        "maxread=%llu, maxwrite=%llu, layout_types: 0x%X, "
        "cansettime=%u, time_delta={%llu,%u}, aclsupport=%u, "
        "link_support=%u, symlink_support=%u, case_preserving=%u, "
        "case_insensitive=%u\n",
        superblock->fsid.major, superblock->fsid.minor,
        superblock->maxread, superblock->maxwrite,
        superblock->layout_types, superblock->cansettime,
        superblock->time_delta.seconds, superblock->time_delta.nseconds,
        superblock->aclsupport, superblock->link_support,
        superblock->symlink_support, superblock->case_preserving,
        superblock->case_insensitive);
out:
    return status;
}


/* nfs41_superblock_list */
#define superblock_entry(pos) list_container(pos, nfs41_superblock, entry)

static int superblock_compare(
    const struct list_entry *entry,
    const void *value)
{
    const nfs41_superblock *superblock = superblock_entry(entry);
    return compare_fsid(&superblock->fsid, (const nfs41_fsid*)value);
}

static nfs41_superblock* find_superblock(
    IN nfs41_superblock_list *superblocks,
    IN const nfs41_fsid *fsid)
{
    struct list_entry *entry;
    entry = list_search(&superblocks->head, fsid, superblock_compare);
    return entry ? superblock_entry(entry) : NULL;
}

void nfs41_superblock_list_init(
    IN nfs41_superblock_list *superblocks)
{
    list_init(&superblocks->head);
    InitializeSRWLock(&superblocks->lock);
}

void nfs41_superblock_list_free(
    IN nfs41_superblock_list *superblocks)
{
    struct list_entry *entry, *tmp;

    dprintf(SBLVL, "nfs41_superblock_list_free()\n");

    list_for_each_tmp(entry, tmp, &superblocks->head)
        free(superblock_entry(entry));
}


int nfs41_superblock_for_fh(
    IN nfs41_session *session,
    IN const nfs41_fsid *fsid,
    IN const nfs41_fh *parent OPTIONAL,
    OUT nfs41_path_fh *file)
{
    int status = NFS4_OK;
    nfs41_server *server = client_server(session->client);
    nfs41_superblock_list *superblocks = &server->superblocks;
    nfs41_superblock *superblock;

    dprintf(SBLVL, "--> nfs41_superblock_for_fh(fsid(%llu,%llu))\n",
        fsid->major, fsid->minor);

    /* compare with the parent's fsid, and use that if it matches */
    if (parent && parent->superblock &&
        compare_fsid(fsid, &parent->superblock->fsid) == 0) {
        file->fh.superblock = parent->superblock;
        dprintf(SBLVL, "using superblock from parent\n");
        goto out;
    }

    /* using a shared lock, search for an existing superblock */
    AcquireSRWLockShared(&superblocks->lock);
    superblock = find_superblock(superblocks, fsid);
    ReleaseSRWLockShared(&superblocks->lock);

    if (superblock) {
        dprintf(SBLVL, "found existing superblock in server list "
            "[shared lock]\n");
    } else {
        AcquireSRWLockExclusive(&superblocks->lock);
        /* must search again under an exclusive lock, in case another thread
         * created it after our first search */
        superblock = find_superblock(superblocks, fsid);
        if (superblock) {
            dprintf(SBLVL, "found newly created superblock in server list "
                "[exclusive lock]\n");
        } else {
            /* create the superblock */
            status = superblock_create(fsid, &superblock);
            if (status == NO_ERROR) /* add it to the list */
                list_add_tail(&superblocks->head, &superblock->entry);
        }
        ReleaseSRWLockExclusive(&superblocks->lock);
    }

    if (status == NO_ERROR && superblock->supported_attrs.count == 0) {
        /* exclusive lock on the superblock while fetching attributes */
        AcquireSRWLockExclusive(&superblock->lock);
        if (superblock->supported_attrs.count == 0)
            status = get_superblock_attrs(session, superblock, file);
        ReleaseSRWLockExclusive(&superblock->lock);
    }

    file->fh.superblock = superblock;
out:
    dprintf(SBLVL, "<-- nfs41_superblock_for_fh() returning %p, status %d\n",
        file->fh.superblock, status);
    return status;
}

void nfs41_superblock_space_changed(
    IN nfs41_superblock *superblock)
{
    /* invalidate cached volume size attributes */
    AcquireSRWLockExclusive(&superblock->lock);
    superblock->cache_expiration = 0;
    ReleaseSRWLockExclusive(&superblock->lock);
}
