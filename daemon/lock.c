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


stateid4* nfs41_lock_stateid_copy(
    IN nfs41_lock_state *lock_state,
    IN OUT stateid4 *dest)
{
    stateid4 *result;
    AcquireSRWLockShared(&lock_state->lock);
    if (lock_state->initialized) {
        memcpy(dest, &lock_state->stateid, sizeof(stateid4));
        result = dest;
        dprintf(LKLVL, "nfs41_lock_stateid_copy: copying existing stateid "
            "with seqid=%u\n", result->seqid);
    } else {
        result = NULL;
        dprintf(LKLVL, "nfs41_lock_stateid_copy: no existing lock state\n");
    }
    ReleaseSRWLockShared(&lock_state->lock);
    return result;
}

static void update_last_lock_state(
    OUT nfs41_lock_state *lock_state,
    IN stateid4 *stateid)
{
    /* update the lock state if the seqid is more recent */
    AcquireSRWLockShared(&lock_state->lock);
    if (stateid->seqid > lock_state->stateid.seqid) {
        ReleaseSRWLockShared(&lock_state->lock);

        AcquireSRWLockExclusive(&lock_state->lock);
        if (stateid->seqid > lock_state->stateid.seqid) {
            if (lock_state->initialized) {
                /* if the lock state already existed, update the seqid only;
                 * assume that stateid->other remains unchanged */
                dprintf(LKLVL, "update_last_lock_state: setting seqid=%u "
                    "(was %u)\n", stateid->seqid, lock_state->stateid.seqid);
                lock_state->stateid.seqid = stateid->seqid;
            } else {
                /* copy the entire stateid and mark as initialized */
                dprintf(LKLVL, "update_last_lock_state: stateid "
                    "initialized with seqid=%u\n", stateid->seqid);
                memcpy(&lock_state->stateid, stateid, sizeof(stateid4));
                lock_state->initialized = 1;
            }
        }
        ReleaseSRWLockExclusive(&lock_state->lock);
    } else {
        dprintf(LKLVL, "update_last_lock_state: discarding seqid=%u "
            "(already %u)\n", stateid->seqid, lock_state->stateid.seqid);
        ReleaseSRWLockShared(&lock_state->lock);
    }
}


/* NFS41_LOCK */
static int parse_lock(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    lock_upcall_args *args = &upcall->args.lock;

    status = safe_read(&buffer, &length, &args->state, sizeof(HANDLE));
    if (status) goto out;
    upcall_open_state_ref(upcall, args->state);
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->offset, sizeof(LONGLONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->length, sizeof(LONGLONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->exclusive, sizeof(BOOLEAN));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->blocking, sizeof(BOOLEAN));
    if (status) goto out;

    dprintf(1, "parsing NFS41_LOCK: state=%p root=%p offset=0x%llx "
        "length=0x%llx exclusive=%u blocking=%u\n",
        args->state, args->root, args->offset, args->length,
        args->exclusive, args->blocking);
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
    int status;
    lock_upcall_args *args = &upcall->args.lock;
    nfs41_open_state *state = args->state;
    const uint32_t type = get_lock_type(args->exclusive, args->blocking);
    stateid4 stateid, *prev_stateid;

    prev_stateid = nfs41_lock_stateid_copy(&state->last_lock, &stateid);

    status = nfs41_lock(state->session, state, prev_stateid,
        type, args->offset, args->length, &stateid);
    if (status) {
        dprintf(LKLVL, "nfs41_lock failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    update_last_lock_state(&state->last_lock, &stateid);
out:
    return status;
}

static void cancel_lock(IN nfs41_upcall *upcall)
{
    int status = NO_ERROR;
    lock_upcall_args *args = &upcall->args.lock;
    nfs41_open_state *state = args->state;
    stateid4 stateid, *prev_stateid;

    dprintf(1, "--> cancel_lock()\n");

    if (upcall->status)
        goto out;

    prev_stateid = nfs41_lock_stateid_copy(&state->last_lock, &stateid);

    status = nfs41_unlock(state->session, state,
        prev_stateid, args->offset, args->length);
    if (status) {
        dprintf(LKLVL, "cancel_lock: nfs41_unlock() failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    update_last_lock_state(&state->last_lock, &stateid);
out:
    dprintf(1, "<-- cancel_lock() returning %d\n", status);
}


/* NFS41_UNLOCK */
static int parse_unlock(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    unlock_upcall_args *args = &upcall->args.unlock;

    status = safe_read(&buffer, &length, &args->state, sizeof(HANDLE));
    if (status) goto out;
    upcall_open_state_ref(upcall, args->state);
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->count, sizeof(ULONG));
    if (status) goto out;

    args->buf = buffer;
    args->buf_len = length;

    dprintf(1, "parsing NFS41_UNLOCK: state=%p root=%p count=%u\n",
        args->state, args->root, args->count);
out:
    return status;
}

static int handle_unlock(nfs41_upcall *upcall)
{
    int status;
    unlock_upcall_args *args = &upcall->args.unlock;
    nfs41_open_state *state = args->state;
    stateid4 stateid;
    uint32_t i, nsuccess = 0;
    unsigned char *buf = args->buf;
    uint32_t buf_len = args->buf_len;
    uint64_t offset;
    uint64_t length;

    if (nfs41_lock_stateid_copy(&state->last_lock, &stateid) == NULL) {
        eprintf("attempt to unlock a file with no lock state\n");
        status = ERROR_NOT_LOCKED;
        goto out;
    }

    status = NO_ERROR;
    for (i = 0; i < args->count; i++) {
        if (safe_read(&buf, &buf_len, &offset, sizeof(LONGLONG))) break;
        if (safe_read(&buf, &buf_len, &length, sizeof(LONGLONG))) break;

        status = nfs41_unlock(state->session, state, &stateid, offset, length);
        if (status == NFS4_OK) {
            nsuccess++;
        } else {
            dprintf(LKLVL, "nfs41_unlock failed with %s\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        }
    }

    if (nsuccess) {
        update_last_lock_state(&state->last_lock, &stateid);
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
