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

#include <Windows.h>
#include <process.h>
#include <stdio.h>

#include "nfs41_ops.h"
#include "nfs41_callback.h"
#include "util.h"
#include "daemon_debug.h"


/* session slot mechanism */
static int init_slot_table(nfs41_slot_table *table) 
{
    int i, status = 0;

    //initialize slot table lock
    table->lock = CreateMutex(NULL, FALSE, "session_table_lock");
    if (table->lock == NULL) {
        status = GetLastError();
        eprintf("init_slot_table: CreateMutex failed %d\n", status);
        goto out;
    }
    //initialize condition variable for slots
    table->cond = CreateEvent(NULL, TRUE, FALSE, "session_table_cond");
    if (table->cond == NULL) {
        status = GetLastError();
        eprintf("init_slot_table: CreateEvent failed %d\n", status);
        goto out_mutex;
    }

    table->max_slots = NFS41_MAX_NUM_SLOTS;
    for(i = 0; i < NFS41_MAX_NUM_SLOTS; i++) {
        table->seq_nums[i] = 1;
        table->used_slots[i] = 0;
    }
    table->highest_used = 0;
out:
    return status;
out_mutex:
    CloseHandle(table->lock);
    goto out;
}

static int reinit_slot_table(nfs41_slot_table *table) 
{
    int i, status = 0;

    status = WaitForSingleObject(table->lock, INFINITE);
    if (status != WAIT_OBJECT_0) {
        dprintf(1, "reinit_slot_table: WaitForSingleObject failed\n");
        print_condwait_status(1, status);
        status = ERROR_LOCK_VIOLATION;
        goto out;
    }

    table->max_slots = NFS41_MAX_NUM_SLOTS;
    for(i = 0; i < NFS41_MAX_NUM_SLOTS; i++) {
        table->seq_nums[i] = 1;
        table->used_slots[i] = 0;
    }
    table->highest_used = 0;
    SetEvent(table->cond);
    ReleaseMutex(table->lock);
out:
    return status;
}

static void free_slot_table(nfs41_slot_table *table)
{
    CloseHandle(table->lock);
    CloseHandle(table->cond);
}

int nfs41_session_bump_seq(
    IN nfs41_session *session,
    IN uint32_t slotid)
{
    int status;

    AcquireSRWLockShared(&session->client->session_lock);
    status = WaitForSingleObject(session->table.lock, INFINITE);
    if (status != WAIT_OBJECT_0) {
        dprintf(1, "nfs41_session_bump_seq: WaitForSingleObject failed\n");
        print_condwait_status(1, status);
        status = ERROR_LOCK_VIOLATION;
        goto out;
    }
    session->table.seq_nums[slotid]++;
    ReleaseMutex(session->table.lock);
out:
    ReleaseSRWLockShared(&session->client->session_lock);
    return status;
}

int nfs41_session_free_slot(
    IN nfs41_session *session,
    IN uint32_t slotid)
{
    int status, i;

    AcquireSRWLockShared(&session->client->session_lock);
    status = WaitForSingleObject(session->table.lock, INFINITE);
    if (status != WAIT_OBJECT_0) {
        dprintf(1, "nfs41_session_free_slot: WaitForSingleObject failed\n");
        print_condwait_status(1, status);
        status = ERROR_LOCK_VIOLATION;
        goto out;
    }
    session->table.used_slots[slotid] = 0;
    if (slotid == session->table.highest_used) {
        session->table.highest_used = 0;
        for (i = slotid; i > 0; i--) {
            if (session->table.used_slots[i]) {
                session->table.highest_used = i;
                break;
            }
        }
    }
    dprintf(3, "freeing slot#=%d highest=%d\n", slotid, session->table.highest_used);
    SetEvent(session->table.cond);
    ReleaseMutex(session->table.lock);
out:
    ReleaseSRWLockShared(&session->client->session_lock);
    return status;
}

int nfs41_session_get_slot(
    IN nfs41_session *session, 
    OUT uint32_t *slot, 
    OUT uint32_t *seq, 
    OUT uint32_t *highest)
{
    uint32_t status = NO_ERROR;
    uint32_t i;

    AcquireSRWLockShared(&session->client->session_lock);
look_for_slot:
    status = WaitForSingleObject(session->table.lock, INFINITE);
    if (status != WAIT_OBJECT_0) {
        eprintf("nfs41_session_get_slot: WaitForSingleObject failed with %d\n", 
            status);
        print_condwait_status(1, status);
        status = ERROR_LOCK_VIOLATION;
        goto out;
    }
    dprintf(3, "looking for a free slot in the slot table\n");
    *highest = session->table.highest_used;
    for (i = 0; i < session->table.max_slots; i++) {
        if (!session->table.used_slots[i]) {
            session->table.used_slots[i] = 1; // mark slot used
            *slot = i; // return slot number
            *seq = session->table.seq_nums[i]; // return sequence number for the slot
            //update highest_slot_used if needed
            if (i > session->table.highest_used) 
                *highest = session->table.highest_used = i; 
            break;
        }
    }
    if (i == session->table.max_slots) {
        dprintf(1, "all (%d) slots are used. waiting for a free slot\n", 
            session->table.max_slots);
        ReleaseMutex(session->table.lock);
        status = WaitForSingleObject(session->table.cond, INFINITE);
        if (status == WAIT_OBJECT_0) {
            dprintf(1, "received a signal to look for a free slot\n");
            ResetEvent(session->table.cond);
            goto look_for_slot;
        } else {
            eprintf("nfs41_session_get_slot: WaitForSingleObject failed "
                "with %d\n", status);
            print_condwait_status(1, status);
            status = ERROR_LOCK_VIOLATION;
            goto out;
        }
    }        
    ReleaseMutex(session->table.lock);
    dprintf(2, "session %p: using slot#=%d with seq#=%d highest=%d\n", session, *slot, *seq, *highest);
out:
    ReleaseSRWLockShared(&session->client->session_lock);
    return status;
}

int nfs41_session_sequence(
    nfs41_sequence_args *args,
    nfs41_session *session,
    bool_t cachethis)
{
    uint32_t status = NO_ERROR;

    status = nfs41_session_get_slot(session, &args->sa_slotid, 
        &args->sa_sequenceid, &args->sa_highest_slotid);
    if (status)
        goto out;
    args->sa_sessionid = session->session_id;
    args->sa_cachethis = cachethis;
out:
    return status;
}


/* session renewal */
static unsigned int WINAPI renew_session(void *args) 
{
    int status = NO_ERROR;
    nfs41_session *session = (nfs41_session *)args;
    /* sleep for 2/3 of lease_time */
    const uint32_t sleep_time = (2 * session->lease_time*1000)/3;

    dprintf(1, "Creating renew_session thread: %p\n", session->renew_thread);
    while(1) {
        dprintf(1, "Going to sleep for %dmsecs\n", sleep_time);
        Sleep(sleep_time);
        status = nfs41_send_sequence(session);
        if (status)
            dprintf(1, "renewal thread: nfs41_send_sequence failed %d\n", status);
    }
    return status;
}

/* session creation */
static int session_alloc(
    IN nfs41_client *client,
    OUT nfs41_session **session_out)
{
    int status;
    nfs41_session *session;

    session = calloc(1, sizeof(nfs41_session));
    if (session == NULL) {
        status = GetLastError();
        goto out;
    }
    session->client = client;
    session->renew_thread = INVALID_HANDLE_VALUE;
    session->isValidState = FALSE;

    status = init_slot_table(&session->table);
    if (status)
        goto out_err_session;

    //initialize session lock
    InitializeSRWLock(&client->session_lock);

    /* initialize the back channel */
    nfs41_callback_session_init(session);

    *session_out = session;
out:
    return status;
out_err_session:
    free(session);
    goto out;
}

int nfs41_session_create(
    IN nfs41_client *client,
    IN nfs41_session **session_out)
{
    nfs41_session *session;
    int status;

    status = session_alloc(client, &session);
    if (status) {
        eprintf("session_alloc() failed with %d\n", status);
        goto out;
    }

    AcquireSRWLockShared(&client->exid_lock);
#ifdef NO_CB_4_KRB5P
    if ((client->roles & (EXCHGID4_FLAG_USE_PNFS_MDS |
        EXCHGID4_FLAG_USE_NON_PNFS)) && client->rpc->needcb)
#else
    if (client->roles & (EXCHGID4_FLAG_USE_PNFS_MDS |
        EXCHGID4_FLAG_USE_NON_PNFS))
#endif
        session->flags |= CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
    session->flags |= CREATE_SESSION4_FLAG_PERSIST;
    ReleaseSRWLockShared(&client->exid_lock);

    status = nfs41_create_session(client, session, TRUE);
    if (status) {
        eprintf("nfs41_create_session failed %d\n", status);
        status = ERROR_BAD_NET_RESP;
        goto out_err;
    }

    AcquireSRWLockExclusive(&session->client->session_lock);
    client->session = session;
    session->isValidState = TRUE;
    ReleaseSRWLockExclusive(&session->client->session_lock);
    *session_out = session;
out:
    return status;

out_err:
    nfs41_session_free(session);
    goto out;
}

/* session renewal */
int nfs41_session_renew(
    IN nfs41_session *session)
{
    int status;

    AcquireSRWLockExclusive(&session->client->session_lock);
    session->cb_session.cb_seqnum = 0;
    status = reinit_slot_table(&session->table);
    if (status)
        goto out_unlock;

    status = nfs41_create_session(session->client, session, FALSE);
    if (status) {
        eprintf("nfs41_create_session failed %d\n", status);
        goto out_unlock;
    }
out_unlock:
    ReleaseSRWLockExclusive(&session->client->session_lock);
    return status;
}

int nfs41_session_set_lease(
    IN nfs41_session *session,
    IN uint32_t lease_time)
{
    int status = NO_ERROR;
    uint32_t thread_id;

    if (valid_handle(session->renew_thread)) {
        eprintf("nfs41_session_set_lease(): session "
            "renewal thread already started!\n");
        goto out;
    }

    if (lease_time == 0) {
        eprintf("nfs41_session_set_lease(): invalid lease_time=0\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    session->lease_time = lease_time;
    session->renew_thread = (HANDLE)_beginthreadex(NULL,
        0, renew_session, session, 0, &thread_id);
    if (!valid_handle(session->renew_thread)) {
        status = GetLastError();
        eprintf("_beginthreadex failed %d\n", status);
        goto out;
    }
out:
    return status;
}

void nfs41_session_free(
    IN nfs41_session *session)
{
    AcquireSRWLockExclusive(&session->client->session_lock);
    if (valid_handle(session->renew_thread)) {
        dprintf(1, "nfs41_session_free: terminating session renewal thread\n");
        if (!TerminateThread(session->renew_thread, NO_ERROR))
            eprintf("failed to terminate renewal thread %p\n",
                session->renew_thread);
    }

    if (session->isValidState) {
        session->client->rpc->is_valid_session = FALSE;
        nfs41_destroy_session(session);
    }
    free_slot_table(&session->table);
    ReleaseSRWLockExclusive(&session->client->session_lock);
    free(session);
}
