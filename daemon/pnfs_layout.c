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

#include <stdio.h>

#include "nfs41_ops.h"
#include "nfs41_callback.h"
#include "util.h"
#include "daemon_debug.h"


#define FLLVL 2 /* dprintf level for file layout logging */


/* pnfs_layout_list */
struct pnfs_layout_list {
    struct list_entry       head;
    CRITICAL_SECTION        lock;
};

#define state_entry(pos) list_container(pos, pnfs_layout_state, entry)

static enum pnfs_status layout_state_create(
    IN const nfs41_fh *meta_fh,
    OUT pnfs_layout_state **layout_out)
{
    pnfs_layout_state *layout;
    enum pnfs_status status = PNFS_SUCCESS;

    layout = calloc(1, sizeof(pnfs_layout_state));
    if (layout == NULL) {
        status = PNFSERR_RESOURCES;
        goto out;
    }

    fh_copy(&layout->meta_fh, meta_fh);
    InitializeSRWLock(&layout->lock);
    InitializeConditionVariable(&layout->cond);

    *layout_out = layout;
out:
    return status;
}

static void file_layout_free(
    IN pnfs_file_layout *layout)
{
    if (layout->device) pnfs_file_device_put(layout->device);
    free(layout->filehandles.arr);
    free(layout);
}

static void layout_state_free(
    IN pnfs_layout_state *state)
{
    if (state->layout) file_layout_free(state->layout);
    free(state);
}

static int layout_entry_compare(
    IN const struct list_entry *entry,
    IN const void *value)
{
    const pnfs_layout_state *layout = state_entry(entry);
    const nfs41_fh *meta_fh = (const nfs41_fh*)value;
    const nfs41_fh *layout_fh = (const nfs41_fh*)&layout->meta_fh;
    const uint32_t diff = layout_fh->len - meta_fh->len;
    return diff ? diff : memcmp(layout_fh->fh, meta_fh->fh, meta_fh->len);
}

static enum pnfs_status layout_entry_find(
    IN struct pnfs_layout_list *layouts,
    IN const nfs41_fh *meta_fh,
    OUT struct list_entry **entry_out)
{
    *entry_out = list_search(&layouts->head, meta_fh, layout_entry_compare);
    return *entry_out ? PNFS_SUCCESS : PNFSERR_NO_LAYOUT;
}

enum pnfs_status pnfs_layout_list_create(
    OUT struct pnfs_layout_list **layouts_out)
{
    struct pnfs_layout_list *layouts;
    enum pnfs_status status = PNFS_SUCCESS;

    layouts = calloc(1, sizeof(struct pnfs_layout_list));
    if (layouts == NULL) {
        status = PNFSERR_RESOURCES;
        goto out;
    }
    list_init(&layouts->head);
    InitializeCriticalSection(&layouts->lock);
    *layouts_out = layouts;
out:
    return status;
}

void pnfs_layout_list_free(
    IN struct pnfs_layout_list *layouts)
{
    struct list_entry *entry, *tmp;

    EnterCriticalSection(&layouts->lock);

    list_for_each_tmp(entry, tmp, &layouts->head)
        layout_state_free(state_entry(entry));

    LeaveCriticalSection(&layouts->lock);

    free(layouts);
}

static enum pnfs_status layout_state_find_or_create(
    IN struct pnfs_layout_list *layouts,
    IN const nfs41_fh *meta_fh,
    OUT pnfs_layout_state **layout_out)
{
    struct list_entry *entry;
    enum pnfs_status status;

    dprintf(FLLVL, "--> layout_state_find_or_create()\n");

    EnterCriticalSection(&layouts->lock);

    /* search for an existing layout */
    status = layout_entry_find(layouts, meta_fh, &entry);
    if (status) {
        /* create a new layout */
        pnfs_layout_state *layout;
        status = layout_state_create(meta_fh, &layout);
        if (status == PNFS_SUCCESS) {
            /* add it to the list */
            list_add_head(&layouts->head, &layout->entry);
            *layout_out = layout;

            dprintf(FLLVL, "<-- layout_state_find_or_create() "
                "returning new layout %p\n", layout);
        } else {
            dprintf(FLLVL, "<-- layout_state_find_or_create() "
                "returning %s\n", pnfs_error_string(status));
        }
    } else {
        *layout_out = state_entry(entry);

        dprintf(FLLVL, "<-- layout_state_find_or_create() "
            "returning existing layout %p\n", *layout_out);
    }

    LeaveCriticalSection(&layouts->lock);
    return status;
}

static enum pnfs_status layout_state_find_and_delete(
    IN struct pnfs_layout_list *layouts,
    IN const nfs41_fh *meta_fh)
{
    struct list_entry *entry;
    enum pnfs_status status;

    dprintf(FLLVL, "--> layout_state_find_and_delete()\n");

    EnterCriticalSection(&layouts->lock);

    status = layout_entry_find(layouts, meta_fh, &entry);
    if (status == PNFS_SUCCESS) {
        list_remove(entry);
        layout_state_free(state_entry(entry));
    }

    LeaveCriticalSection(&layouts->lock);

    dprintf(FLLVL, "<-- layout_state_find_and_delete() "
        "returning %s\n", pnfs_error_string(status));
    return status;
}


/* pnfs_file_layout */
static enum pnfs_status layout_update_range(
    IN OUT pnfs_layout_state *state,
    IN const struct list_entry *layouts)
{
    struct list_entry *entry, *tmp;
    pnfs_layout *layout;
    enum pnfs_status status = PNFSERR_NO_LAYOUT;

    list_for_each_tmp(entry, tmp, layouts) {
        layout = list_container(entry, pnfs_layout, entry);

        /* don't know what to do with non-file layouts */
        if (layout->type != PNFS_LAYOUTTYPE_FILE)
            continue;

        if (state->layout == NULL) {
            /* store the first file layout returned */
            dprintf(FLLVL, "Saving layout:\n");
            dprint_layout(FLLVL, (pnfs_file_layout*)layout);

            state->layout = (pnfs_file_layout*)layout;
            status = PNFS_SUCCESS;
        } else {
            /* free anything else */
            /* TODO: attempt to merge with existing segments */
            dprintf(FLLVL, "Discarding extra layout:\n");
            dprint_layout(FLLVL, (pnfs_file_layout*)layout);

            file_layout_free((pnfs_file_layout*)layout);
        }
    }
    return status;
}

static enum pnfs_status layout_update_stateid(
    IN OUT pnfs_layout_state *state,
    IN const stateid4 *stateid)
{
    enum pnfs_status status = PNFS_SUCCESS;

    if (state->stateid.seqid == 0) {
        /* save a new layout stateid */
        memcpy(&state->stateid, stateid, sizeof(stateid4));
    } else if (memcmp(&state->stateid.other, stateid->other, 
                        NFS4_STATEID_OTHER) == 0) {
        /* update an existing layout stateid */
        state->stateid.seqid = stateid->seqid;
    } else {
        status = PNFSERR_NO_LAYOUT;
    }
    return status;
}

static enum pnfs_status layout_update(
    IN OUT pnfs_layout_state *state,
    IN const pnfs_layoutget_res_ok *layoutget_res)
{
    enum pnfs_status status;

    /* update the layout ranges held by the client */
    status = layout_update_range(state, &layoutget_res->layouts);
    if (status) {
        eprintf("LAYOUTGET didn't return any file layouts\n");
        goto out;
    }
    /* update the layout stateid */
    status = layout_update_stateid(state, &layoutget_res->stateid);
    if (status) {
        eprintf("LAYOUTGET returned a new stateid when we already had one\n");
        goto out_free;
    }
    /* if a previous LAYOUTGET set return_on_close, don't overwrite it */
    if (!state->return_on_close)
        state->return_on_close = layoutget_res->return_on_close;
out:
    return status;

out_free:
    file_layout_free(state->layout);
    state->layout = NULL;
    goto out;
}

static enum pnfs_status file_layout_fetch(
    IN OUT pnfs_layout_state *state,
    IN nfs41_session *session,
    IN nfs41_path_fh *meta_file,
    IN stateid_arg *stateid,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length)
{
    pnfs_layoutget_res_ok layoutget_res = { 0 };
    enum pnfs_status pnfsstat = PNFS_SUCCESS;
    enum nfsstat4 nfsstat;

    dprintf(FLLVL, "--> file_layout_fetch(%s, seqid=%u)\n",
        pnfs_iomode_string(iomode), state->stateid.seqid);

    list_init(&layoutget_res.layouts);

    /* drop the lock during the rpc call */
    ReleaseSRWLockExclusive(&state->lock);
    nfsstat = pnfs_rpc_layoutget(session, meta_file,
        stateid, iomode, offset, length, &layoutget_res);
    AcquireSRWLockExclusive(&state->lock);

    if (nfsstat) {
        dprintf(FLLVL, "pnfs_rpc_layoutget() failed with %s\n",
            nfs_error_string(nfsstat));
        pnfsstat = PNFSERR_NOT_SUPPORTED;
    }

    switch (nfsstat) {
    case NFS4_OK:
        /* use the LAYOUTGET results to update our view of the layout */
        pnfsstat = layout_update(state, &layoutget_res);
        if (pnfsstat)
            break;

        /* mark granted and clear other flags */
        state->status = PNFS_LAYOUT_GRANTED;
        break;

    case NFS4ERR_BADIOMODE:
        /* don't try RW again */
        if (iomode == PNFS_IOMODE_RW)
            state->status |= PNFS_LAYOUT_NOT_RW;
        break;

    case NFS4ERR_LAYOUTUNAVAILABLE:
    case NFS4ERR_UNKNOWN_LAYOUTTYPE:
    case NFS4ERR_BADLAYOUT:
        /* don't try again at all */
        state->status |= PNFS_LAYOUT_UNAVAILABLE;
        break;
    }

    dprintf(FLLVL, "<-- file_layout_fetch() returning %s\n",
        pnfs_error_string(pnfsstat));
    return pnfsstat;
}

static enum pnfs_status layout_grant_status(
    IN const pnfs_layout_state *layout,
    IN enum pnfs_iomode iomode)
{
    enum pnfs_status status = PNFS_PENDING;

    if (layout->status & PNFS_LAYOUT_RECALLED) {
        /* don't use a recalled layout */
        status = PNFSERR_LAYOUT_RECALLED;
    } else if (layout->status & PNFS_LAYOUT_GRANTED) {
        /* the layout is granted; use it if it's compatible */
        status = PNFS_SUCCESS;
    } else if ((layout->status & PNFS_LAYOUT_UNAVAILABLE) ||
        (iomode == PNFS_IOMODE_RW && layout->status & PNFS_LAYOUT_NOT_RW)) {
        /* an error from LAYOUTGET indicated that the server
         * won't ever grant this layout, so stop trying */
        status = PNFSERR_NOT_SUPPORTED;
    }
    return status;
}

static enum pnfs_status file_layout_cache(
    IN OUT pnfs_layout_state *state,
    IN nfs41_session *session,
    IN nfs41_path_fh *meta_file,
    IN stateid_arg *stateid,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length)
{
    enum pnfs_status status;

    /* use a shared lock to see if it's already been granted */
    AcquireSRWLockShared(&state->lock);
    status = layout_grant_status(state, iomode);
    ReleaseSRWLockShared(&state->lock);

    if (status == PNFS_PENDING) {
        /* use an exclusive lock while attempting to get a new layout */
        AcquireSRWLockExclusive(&state->lock);

        /* wait for any pending LAYOUTGETs/LAYOUTRETURNs */
        while (state->pending)
            SleepConditionVariableSRW(&state->cond, &state->lock, INFINITE, 0);
        state->pending = TRUE;

        status = layout_grant_status(state, iomode);
        if (status == PNFS_PENDING) {
            /* if there's an existing layout stateid, use it */
            if (state->stateid.seqid) {
                memcpy(&stateid->stateid, &state->stateid, sizeof(stateid4));
                stateid->type = STATEID_LAYOUT;
            }

            if ((state->status & PNFS_LAYOUT_NOT_RW) == 0) {
                /* try to get a RW layout first */
                status = file_layout_fetch(state, session,
                    meta_file, stateid, PNFS_IOMODE_RW, offset, length);
            }

            if (status && iomode == PNFS_IOMODE_READ) {
                /* fall back on READ if necessary */
                status = file_layout_fetch(state, session,
                    meta_file, stateid, iomode, offset, length);
            }
        }

        state->pending = FALSE;
        WakeConditionVariable(&state->cond);
        ReleaseSRWLockExclusive(&state->lock);
    }
    return status;
}

static enum pnfs_status layout_compatible(
    IN OUT pnfs_layout_state *state,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length)
{
    pnfs_layout *layout;
    enum pnfs_status status = PNFS_SUCCESS;

    AcquireSRWLockShared(&state->lock);

    if (state->layout == NULL) {
        status = PNFSERR_NOT_SUPPORTED;
        goto out_unlock;
    }
    layout = &state->layout->layout;
    if (iomode == PNFS_IOMODE_RW && layout->iomode == PNFS_IOMODE_READ) {
        status = PNFSERR_NOT_SUPPORTED;
        goto out_unlock;
    }
    if (offset < layout->offset ||
        offset + length > layout->offset + layout->length) {
        status = PNFSERR_NOT_SUPPORTED;
        goto out_unlock;
    }
out_unlock:
    ReleaseSRWLockShared(&state->lock);
    return status;
}

static enum pnfs_status file_device_status(
    IN const pnfs_layout_state *state)
{
    enum pnfs_status status = PNFS_PENDING;

    if (state->layout == NULL) {
        status = PNFSERR_NO_LAYOUT;
    } else if (state->status & PNFS_LAYOUT_RECALLED) {
        /* don't fetch deviceinfo for a recalled layout */
        status = PNFSERR_LAYOUT_RECALLED;
    } else if (state->status & PNFS_LAYOUT_HAS_DEVICE) {
        /* deviceinfo already cached */
        status = PNFS_SUCCESS;
    }
    return status;
}

static enum pnfs_status file_layout_device(
    IN OUT pnfs_layout_state *state,
    IN nfs41_session *session)
{
    enum pnfs_status status = PNFS_PENDING;

    /* use a shared lock to see if we already have a device */
    AcquireSRWLockShared(&state->lock);
    status = file_device_status(state);
    ReleaseSRWLockShared(&state->lock);

    if (status == PNFS_PENDING) {
        /* use an exclusive lock to look up device info */
        AcquireSRWLockExclusive(&state->lock);

        /* wait for any pending LAYOUTGETs/LAYOUTRETURNs */
        while (state->pending)
            SleepConditionVariableSRW(&state->cond, &state->lock, INFINITE, 0);
        state->pending = TRUE;

        status = file_device_status(state);
        if (status == PNFS_PENDING) {
            unsigned char deviceid[PNFS_DEVICEID_SIZE];
            pnfs_file_device *device;

            memcpy(deviceid, state->layout->deviceid, PNFS_DEVICEID_SIZE);

            /* drop the lock during the rpc call */
            ReleaseSRWLockExclusive(&state->lock);
            status = pnfs_file_device_get(session,
                session->client->devices, deviceid, &device);
            AcquireSRWLockExclusive(&state->lock);

            if (status == PNFS_SUCCESS) {
                state->layout->device = device;
                state->status |= PNFS_LAYOUT_HAS_DEVICE;
            }
        }

        state->pending = FALSE;
        WakeConditionVariable(&state->cond);
        ReleaseSRWLockExclusive(&state->lock);
    }
    return status;
}

static enum pnfs_status file_layout_get(
    IN OUT pnfs_layout_state *state,
    IN nfs41_session *session,
    IN nfs41_path_fh *meta_file,
    IN stateid_arg *stateid,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length)
{
    enum pnfs_status status;

    /* request a range for the entire file */
    status = file_layout_cache(state, session, meta_file,
        stateid, iomode, 0, NFS4_UINT64_MAX);
    if (status) {
        dprintf(FLLVL, "file_layout_cache() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }

    /* fail if we don't get everything we asked for */
    status = layout_compatible(state, iomode, offset, length);
    if (status) {
        dprintf(FLLVL, "file_layout_compatible() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }

    /* make sure we have a device for the layout */
    status = file_layout_device(state, session);
    if (status) {
        dprintf(FLLVL, "file_layout_device() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }
out:
    return status;
}

static enum pnfs_status layout_return_status(
    IN const pnfs_layout_state *state)
{
    return (state->status & PNFS_LAYOUT_GRANTED) == 0
        ? PNFS_SUCCESS : PNFS_PENDING;
}

static enum pnfs_status file_layout_return(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN pnfs_layout_state *state)
{
    enum pnfs_status status;
    enum nfsstat4 nfsstat;

    dprintf(FLLVL, "--> file_layout_return()\n");

    /* under shared lock, determine whether we need to return the layout */
    AcquireSRWLockShared(&state->lock);
    status = layout_return_status(state);
    ReleaseSRWLockShared(&state->lock);

    if (status == PNFS_PENDING) {
        /* under exclusive lock, return the layout and reset status flags */
        AcquireSRWLockExclusive(&state->lock);

        /* wait for any pending LAYOUTGETs/LAYOUTRETURNs */
        while (state->pending)
            SleepConditionVariableSRW(&state->cond, &state->lock, INFINITE, 0);
        state->pending = TRUE;

        status = layout_return_status(state);
        if (status == PNFS_PENDING) {
            pnfs_layoutreturn_res layoutreturn_res = { 0 };
            stateid4 stateid;
            memcpy(&stateid, &state->stateid, sizeof(stateid));
            
            /* drop the lock during the rpc call */
            ReleaseSRWLockExclusive(&state->lock);
            nfsstat = pnfs_rpc_layoutreturn(session, file,
                PNFS_LAYOUTTYPE_FILE, PNFS_IOMODE_ANY, 0,
                NFS4_UINT64_MAX, &stateid, &layoutreturn_res);
            AcquireSRWLockExclusive(&state->lock);

            if (nfsstat) {
                eprintf("pnfs_rpc_layoutreturn() failed with %s\n",
                    nfs_error_string(nfsstat));
                status = PNFSERR_NO_LAYOUT;
            } else {
                status = PNFS_SUCCESS;

                /* update the layout range held by the client */
                file_layout_free(state->layout);
                state->layout = NULL;

                if (layoutreturn_res.stateid_present) {
                    /* update the layout seqid */
                    /* XXX: this shouldn't happen when we send a LAYOUTRETURN
                     * with IOMODE_ANY for the entire range */
                    memcpy(&state->stateid, &layoutreturn_res.stateid,
                        sizeof(stateid4));
                } else {
                    /* 12.5.3. Layout Stateid: Once a client has no more
                     * layouts on a file, the layout stateid is no longer
                     * valid and MUST NOT be used. */
                    ZeroMemory(&state->stateid, sizeof(stateid4));
                }

                /* reset the granted flag */
                state->status &= ~PNFS_LAYOUT_GRANTED;
            }
        }

        state->pending = FALSE;
        WakeConditionVariable(&state->cond);
        ReleaseSRWLockExclusive(&state->lock);
    }

    dprintf(FLLVL, "<-- file_layout_return() returning %s\n",
        pnfs_error_string(status));
    return status;
}


/* nfs41_open_state */
static enum pnfs_status client_supports_pnfs(
    IN nfs41_client *client)
{
    enum pnfs_status status;
    AcquireSRWLockShared(&client->exid_lock);
    status = client->roles & EXCHGID4_FLAG_USE_PNFS_MDS
        ? PNFS_SUCCESS : PNFSERR_NOT_SUPPORTED;
    ReleaseSRWLockShared(&client->exid_lock);
    return status;
}

static enum pnfs_status fs_supports_layout(
    IN const nfs41_superblock *superblock,
    IN enum pnfs_layout_type type)
{
    const uint32_t flag = 1 << (type - 1);
    return (superblock->layout_types & flag) == 0
        ? PNFSERR_NOT_SUPPORTED : PNFS_SUCCESS;
}

static enum pnfs_status open_state_layout_cached(
    IN nfs41_open_state *state,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length,
    OUT pnfs_layout_state **layout_out)
{
    enum pnfs_status status = PNFSERR_NO_LAYOUT;

    if (state->layout) {
        status = PNFS_SUCCESS;
        *layout_out = state->layout;

        dprintf(FLLVL, "pnfs_open_state_layout() found "
            "cached layout %p\n", *layout_out);
    }
    return status;
}

enum pnfs_status pnfs_layout_state_open(
    IN struct pnfs_layout_list *layouts,
    IN nfs41_session *session,
    IN nfs41_open_state *state,
    IN enum pnfs_iomode iomode,
    IN uint64_t offset,
    IN uint64_t length,
    OUT pnfs_layout_state **layout_out)
{
    stateid_arg stateid;
    pnfs_layout_state *layout;
    enum pnfs_status status;

    dprintf(FLLVL, "--> pnfs_layout_state_open()\n");

    status = client_supports_pnfs(session->client);
    if (status)
        goto out;
    status = fs_supports_layout(state->file.fh.superblock, PNFS_LAYOUTTYPE_FILE);
    if (status)
        goto out;

    /* under shared lock, check open state for cached layouts */
    AcquireSRWLockShared(&state->lock);
    status = open_state_layout_cached(state, iomode, offset, length, &layout);
    ReleaseSRWLockShared(&state->lock);

    if (status) {
        /* under exclusive lock, find or create a layout for this file */
        AcquireSRWLockExclusive(&state->lock);

        status = open_state_layout_cached(state, iomode, offset, length, &layout);
        if (status) {
            status = layout_state_find_or_create(layouts, &state->file.fh, &layout);
            if (status == PNFS_SUCCESS) {
                LONG open_count = InterlockedIncrement(&layout->open_count);
                state->layout = layout;

                dprintf(FLLVL, "pnfs_layout_state_open() caching layout %p "
                    "(%u opens)\n", state->layout, open_count);
            }
        }

        ReleaseSRWLockExclusive(&state->lock);

        if (status)
            goto out;
    }

    nfs41_lock_stateid_arg(state, &stateid);

    /* make sure the layout can satisfy this request */
    status = file_layout_get(layout, session, &state->file,
        &stateid, iomode, offset, length);
    if (status) {
        dprintf(FLLVL, "file_layout_get() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }

    *layout_out = layout;
out:
    dprintf(FLLVL, "<-- pnfs_layout_state_open() returning %s\n",
        pnfs_error_string(status));
    return status;
}

void pnfs_layout_state_close(
    IN nfs41_session *session,
    IN nfs41_open_state *state,
    IN bool_t remove)
{
    pnfs_layout_state *layout;
    bool_t return_layout;
    enum pnfs_status status;

    AcquireSRWLockExclusive(&state->lock);
    layout = state->layout;
    state->layout = NULL;
    ReleaseSRWLockExclusive(&state->lock);

    if (layout) {
        LONG open_count = InterlockedDecrement(&layout->open_count);

        AcquireSRWLockShared(&layout->lock);
        /* only return on close if it's the last close */
        return_layout = layout->return_on_close && (open_count <= 0);
        ReleaseSRWLockShared(&layout->lock);

        if (return_layout) {
            status = file_layout_return(session, &state->file, layout);
            if (status)
                eprintf("file_layout_return() failed with %s\n",
                    pnfs_error_string(status));
        }
    }

    if (remove && session->client->layouts) {
        /* free the layout when the file is removed */
        layout_state_find_and_delete(session->client->layouts, &state->file.fh);
    }
}


/* pnfs_layout_recall */

/* expects the caller to have an exclusive lock */
static enum pnfs_status layout_recall_return(
    IN pnfs_layout_state *state)
{
    dprintf(FLLVL, "layout_recall_return() 'forgetting' layout\n");

    if (state->layout) {
        /* release our reference on the device */
        if (state->layout->device) {
            pnfs_file_device_put(state->layout->device);
            state->layout->device = NULL;
        }

        /* update the layout range held by the client */
        file_layout_free(state->layout);
        state->layout = NULL;
    }

    /* since we're forgetful, we don't actually return the layout;
     * just zero the stateid since it won't be valid anymore */
    ZeroMemory(&state->stateid, sizeof(state->stateid));
    state->status = 0;

    return PNFS_SUCCESS;
}

static enum pnfs_status file_layout_recall(
    IN pnfs_layout_state *state,
    IN const struct cb_layoutrecall_args *recall)
{
    const stateid4 *stateid_arg = &recall->recall.args.file.stateid;
    enum pnfs_status status = PNFS_SUCCESS;

    /* under an exclusive lock, flag the layout as recalled */
    AcquireSRWLockExclusive(&state->lock);

    if ((state->status & PNFS_LAYOUT_GRANTED) == 0) {
        /* return NOMATCHINGLAYOUT if it wasn't actually granted */
        status = PNFSERR_NO_LAYOUT;
    } else if (recall->recall.type == PNFS_RETURN_FILE
        && stateid_arg->seqid > state->stateid.seqid + 1) {
        /* the server has processed an outstanding LAYOUTGET or LAYOUTRETURN;
         * we must return ERR_DELAY until we get the response and update our
         * view of the layout */
        status = PNFS_PENDING;
    } else if (state->io_count) {
        /* flag the layout as recalled so it can be returned after io */
        state->status |= PNFS_LAYOUT_RECALLED;
        if (recall->changed)
            state->status |= PNFS_LAYOUT_CHANGED;

        /* if we got a stateid, update the layout's seqid */
        if (recall->recall.type == PNFS_RETURN_FILE)
            state->stateid.seqid = stateid_arg->seqid;
    } else {
        /* if there is no pending io, return the layout now */
        status = layout_recall_return(state);
    }

    ReleaseSRWLockExclusive(&state->lock);
    return status;
}

static enum pnfs_status file_layout_recall_file(
    IN nfs41_client *client,
    IN const struct cb_layoutrecall_args *recall)
{
    struct list_entry *entry;
    enum pnfs_status status;

    dprintf(FLLVL, "--> file_layout_recall_file()\n");

    EnterCriticalSection(&client->layouts->lock);

    status = layout_entry_find(client->layouts, &recall->recall.args.file.fh, &entry);
    if (status == PNFS_SUCCESS)
        status = file_layout_recall(state_entry(entry), recall);

    LeaveCriticalSection(&client->layouts->lock);

    dprintf(FLLVL, "<-- file_layout_recall_file() returning %s\n",
        pnfs_error_string(status));
    return status;
}

static bool_t fsid_matches(
    IN const nfs41_fsid *lhs,
    IN const nfs41_fsid *rhs)
{
    return lhs->major == rhs->major
        && lhs->minor == rhs->minor;
}

static enum pnfs_status file_layout_recall_fsid(
    IN nfs41_client *client,
    IN const struct cb_layoutrecall_args *recall)
{
    struct list_entry *entry;
    pnfs_layout_state *state;
    nfs41_fh *fh;
    enum pnfs_status status = PNFSERR_NO_LAYOUT;

    dprintf(FLLVL, "--> file_layout_recall_fsid(%llu, %llu)\n",
        recall->recall.args.fsid.major, recall->recall.args.fsid.minor);

    EnterCriticalSection(&client->layouts->lock);

    list_for_each(entry, &client->layouts->head) {
        state = state_entry(entry);
        /* no locks needed to read layout.meta_fh or superblock.fsid,
         * because they are only written once on creation */
        fh = &state->meta_fh;
        if (fsid_matches(&recall->recall.args.fsid, &fh->superblock->fsid))
            status = file_layout_recall(state, recall);
    }

    LeaveCriticalSection(&client->layouts->lock);

    /* bulk recalls require invalidation of cached device info */
    pnfs_file_device_list_invalidate(client->devices);

    dprintf(FLLVL, "<-- file_layout_recall_fsid() returning %s\n",
        pnfs_error_string(status));
    return status;
}

static enum pnfs_status file_layout_recall_all(
    IN nfs41_client *client,
    IN const struct cb_layoutrecall_args *recall)
{
    struct list_entry *entry;
    enum pnfs_status status = PNFSERR_NO_LAYOUT;

    dprintf(FLLVL, "--> file_layout_recall_all()\n");

    EnterCriticalSection(&client->layouts->lock);

    list_for_each(entry, &client->layouts->head)
        status = file_layout_recall(state_entry(entry), recall);

    LeaveCriticalSection(&client->layouts->lock);

    /* bulk recalls require invalidation of cached device info */
    pnfs_file_device_list_invalidate(client->devices);

    dprintf(FLLVL, "<-- file_layout_recall_all() returning %s\n",
        pnfs_error_string(status));
    return status;
}

enum pnfs_status pnfs_file_layout_recall(
    IN nfs41_client *client,
    IN const struct cb_layoutrecall_args *recall)
{
    enum pnfs_status status = PNFS_SUCCESS;

    dprintf(FLLVL, "--> pnfs_file_layout_recall(%u, %s, %u)\n",
        recall->recall.type, pnfs_iomode_string(recall->iomode),
        recall->changed);

    if (recall->type != PNFS_LAYOUTTYPE_FILE) {
        dprintf(FLLVL, "invalid layout type %u (%s)!\n",
            recall->type, pnfs_layout_type_string(recall->type));
        status = PNFSERR_NOT_SUPPORTED;
        goto out;
    }

    switch (recall->recall.type) {
    case PNFS_RETURN_FILE:
        status = file_layout_recall_file(client, recall);
        break;
    case PNFS_RETURN_FSID:
        status = file_layout_recall_fsid(client, recall);
        break;
    case PNFS_RETURN_ALL:
        status = file_layout_recall_all(client, recall);
        break;

    default:
        dprintf(FLLVL, "invalid return type %u!\n", recall->recall);
        status = PNFSERR_NOT_SUPPORTED;
        goto out;
    }
out:
    dprintf(FLLVL, "<-- pnfs_file_layout_recall() returning %s\n",
        pnfs_error_string(status));
    return status;
}


enum pnfs_status pnfs_layout_io_start(
    IN pnfs_layout_state *state)
{
    enum pnfs_status status = PNFS_SUCCESS;

    AcquireSRWLockExclusive(&state->lock);

    if ((state->status & PNFS_LAYOUT_RECALLED) != 0) {
        /* don't start any more io if the layout has been recalled */
        status = PNFSERR_LAYOUT_RECALLED;
        dprintf(FLLVL, "pnfs_layout_io_start() failed, layout was recalled\n");
    } else if (layout_unit_size(state->layout) == 0) { /* prevent div/0 */
        status = PNFSERR_NO_LAYOUT;
    } else if (state->layout->device->stripes.count == 0) {
        status = PNFSERR_NO_LAYOUT;
    } else if (state->layout->device->servers.count == 0) {
        status = PNFSERR_NO_LAYOUT;
    } else {
        /* take a reference on the layout, so that it won't be recalled
         * until all io is finished */
        state->io_count++;
        dprintf(FLLVL, "pnfs_layout_io_start(): count -> %u\n",
            state->io_count);
    }

    ReleaseSRWLockExclusive(&state->lock);
    return status;
}

void pnfs_layout_io_finished(
    IN pnfs_layout_state *state)
{
    AcquireSRWLockExclusive(&state->lock);

    /* return the reference to signify that an io request is finished */
    state->io_count--;
    dprintf(FLLVL, "pnfs_layout_io_finished() count -> %u\n",
        state->io_count);

    if (state->io_count > 0) /* more io pending */
        goto out_unlock;

    /* once all io is finished, check for layout recalls */
    if (state->status & PNFS_LAYOUT_RECALLED)
        layout_recall_return(state);

out_unlock:
    ReleaseSRWLockExclusive(&state->lock);
}
