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
#include "nfs41_ops.h"
#include "upcall.h"
#include "util.h"


#define LKLVL 2 /* dprintf level for lock logging */


void nfs41_lock_stateid_arg(
    IN nfs41_open_state *state,
    OUT stateid_arg *arg)
{
    AcquireSRWLockShared(&state->lock);
    if (state->locks.stateid.seqid) {
        /* use lock stateid where available */
        memcpy(&arg->stateid, &state->locks.stateid, sizeof(stateid4));
        arg->type = STATEID_LOCK;
        arg->open = state;
    } else {
        /* fall back on open stateid */
        nfs41_open_stateid_arg(state, arg);
    }
    ReleaseSRWLockShared(&state->lock);
}

/* expects the caller to hold an exclusive lock on nfs41_open_state.lock */
static void update_lock_state(
    OUT nfs41_open_state *state,
    IN const stateid4 *stateid)
{
    if (state->locks.stateid.seqid == 0) {
        /* if it's a new lock stateid, copy it in */
        memcpy(&state->locks.stateid, stateid, sizeof(stateid4));
    } else if (stateid->seqid > state->locks.stateid.seqid) {
        /* update the seqid if it's more recent */
        state->locks.stateid.seqid = stateid->seqid;
    }
}

static int open_lock_add(
    IN nfs41_open_state *state,
    IN const stateid4 *stateid,
    IN uint64_t offset,
    IN uint64_t length,
    IN uint32_t type)
{
    nfs41_lock_state *lock;
    int status = NO_ERROR;

    AcquireSRWLockExclusive(&state->lock);
    update_lock_state(state, stateid);

    lock = malloc(sizeof(nfs41_lock_state));
    if (lock == NULL) {
        status = GetLastError();
        goto out;
    }
    lock->offset = offset;
    lock->length = length;
    lock->type = type;

    list_add_tail(&state->locks.list, &lock->open_entry);
out:
    ReleaseSRWLockExclusive(&state->lock);
    return status;
}

static void open_lock_remove(
    IN nfs41_open_state *state,
    IN const stateid4 *stateid,
    IN uint64_t offset,
    IN uint64_t length)
{
    struct list_entry *entry;
    nfs41_lock_state *lock;

    AcquireSRWLockExclusive(&state->lock);
    update_lock_state(state, stateid);

    list_for_each(entry, &state->locks.list) {
        lock = list_container(entry, nfs41_lock_state, open_entry);
        if (lock->offset == offset && lock->length == length) {
            list_remove(entry);
            free(lock);
            break;
        }
    }
    ReleaseSRWLockExclusive(&state->lock);
}


/* NFS41_LOCK */
static int parse_lock(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    lock_upcall_args *args = &upcall->args.lock;

    status = safe_read(&buffer, &length, &args->offset, sizeof(LONGLONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->length, sizeof(LONGLONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->exclusive, sizeof(BOOLEAN));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->blocking, sizeof(BOOLEAN));
    if (status) goto out;

    dprintf(1, "parsing NFS41_LOCK: offset=0x%llx length=0x%llx exclusive=%u "
            "blocking=%u\n", args->offset, args->length, args->exclusive, 
            args->blocking);
out:
    return status;
}

static __inline uint32_t get_lock_type(BOOLEAN exclusive, BOOLEAN blocking)
{
    return blocking == 0
        ? ( exclusive == 0 ? READ_LT : WRITE_LT )
        : ( exclusive == 0 ? READW_LT : WRITEW_LT );
}

static int handle_lock(nfs41_upcall *upcall)
{
    stateid_arg stateid;
    lock_upcall_args *args = &upcall->args.lock;
    nfs41_open_state *state = upcall->state_ref;
    const uint32_t type = get_lock_type(args->exclusive, args->blocking);
    int status;

    nfs41_lock_stateid_arg(state, &stateid);

    status = nfs41_lock(state->session, &state->file, &state->owner,
        type, args->offset, args->length, FALSE, TRUE, &stateid);
    if (status) {
        dprintf(LKLVL, "nfs41_lock failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    /* ignore errors from open_lock_add(); they just mean we
     * won't be able to recover the lock after reboot */
    open_lock_add(state, &stateid.stateid, args->offset, args->length, type);
out:
    return status;
}

static void cancel_lock(IN nfs41_upcall *upcall)
{
    stateid_arg stateid;
    lock_upcall_args *args = &upcall->args.lock;
    nfs41_open_state *state = upcall->state_ref;
    int status = NO_ERROR;

    dprintf(1, "--> cancel_lock()\n");

    if (upcall->status)
        goto out;

    nfs41_lock_stateid_arg(state, &stateid);

    status = nfs41_unlock(state->session, &state->file,
        args->offset, args->length, &stateid);
    if (status) {
        dprintf(LKLVL, "cancel_lock: nfs41_unlock() failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    open_lock_remove(state, &stateid.stateid, args->offset, args->length);
out:
    dprintf(1, "<-- cancel_lock() returning %d\n", status);
}


/* NFS41_UNLOCK */
static int parse_unlock(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    unlock_upcall_args *args = &upcall->args.unlock;

    status = safe_read(&buffer, &length, &args->count, sizeof(ULONG));
    if (status) goto out;

    args->buf = buffer;
    args->buf_len = length;

    dprintf(1, "parsing NFS41_UNLOCK: count=%u\n", args->count);
out:
    return status;
}

static int handle_unlock(nfs41_upcall *upcall)
{
    stateid_arg stateid;
    unlock_upcall_args *args = &upcall->args.unlock;
    nfs41_open_state *state = upcall->state_ref;
    uint32_t i, nsuccess = 0;
    unsigned char *buf = args->buf;
    uint32_t buf_len = args->buf_len;
    uint64_t offset;
    uint64_t length;
    int status = NO_ERROR;

    nfs41_lock_stateid_arg(state, &stateid);
    if (stateid.type != STATEID_LOCK) {
        eprintf("attempt to unlock a file with no lock state\n");
        status = ERROR_NOT_LOCKED;
        goto out;
    }

    for (i = 0; i < args->count; i++) {
        if (safe_read(&buf, &buf_len, &offset, sizeof(LONGLONG))) break;
        if (safe_read(&buf, &buf_len, &length, sizeof(LONGLONG))) break;

        status = nfs41_unlock(state->session,
            &state->file, offset, length, &stateid);
        if (status == NFS4_OK) {
            open_lock_remove(state, &stateid.stateid, offset, length);
            nsuccess++;
        } else {
            dprintf(LKLVL, "nfs41_unlock failed with %s\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        }
    }

    if (nsuccess) {
        update_lock_state(state, &stateid.stateid);
        status = NO_ERROR;
    }
out:
    return status;
}


const nfs41_upcall_op nfs41_op_lock = {
    parse_lock,
    handle_lock,
    NULL,
    cancel_lock
};
const nfs41_upcall_op nfs41_op_unlock = {
    parse_unlock,
    handle_unlock
};
