/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#include <stdio.h>
#include <process.h>

#include "nfs41_ops.h"
#include "util.h"
#include "daemon_debug.h"


#define IOLVL 2 /* dprintf level for pnfs io logging */


typedef struct __pnfs_io_pattern {
    struct __pnfs_io_thread *threads;
    nfs41_root              *root;
    nfs41_path_fh           *meta_file;
    const stateid_arg       *stateid;
    pnfs_layout_state       *state;
    unsigned char           *buffer;
    uint64_t                offset_start;
    uint64_t                offset_end;
    uint32_t                count;
    uint32_t                default_lease;
} pnfs_io_pattern;

typedef struct __pnfs_io_thread {
    pnfs_io_pattern         *pattern;
    pnfs_file_layout        *layout;
    nfs41_path_fh           *file;
    uint64_t                offset;
    uint32_t                id;
    enum stable_how4        stable;
} pnfs_io_thread;

typedef struct __pnfs_io_unit {
    unsigned char           *buffer;
    uint64_t                offset;
    uint64_t                length;
    uint32_t                stripeid;
    uint32_t                serverid;
} pnfs_io_unit;

typedef uint32_t (WINAPI *pnfs_io_thread_fn)(void*);


/* 13.4.2. Interpreting the File Layout Using Sparse Packing
 * http://tools.ietf.org/html/rfc5661#section-13.4.2 */

static enum pnfs_status get_sparse_fh(
    IN pnfs_file_layout *layout,
    IN nfs41_path_fh *meta_file,
    IN uint32_t stripeid,
    OUT nfs41_path_fh **file_out)
{
    const uint32_t filehandle_count = layout->filehandles.count;
    const uint32_t server_count = layout->device->servers.count;
    enum pnfs_status status = PNFS_SUCCESS;

    if (filehandle_count == server_count) {
        const uint32_t serverid = data_server_index(layout->device, stripeid);
        *file_out = &layout->filehandles.arr[serverid];
    } else if (filehandle_count == 1) {
        *file_out = &layout->filehandles.arr[0];
    } else if (filehandle_count == 0) {
        *file_out = meta_file;
    } else {
        eprintf("invalid sparse layout! has %u file handles "
            "and %u servers\n", filehandle_count, server_count);
        status = PNFSERR_INVALID_FH_LIST;
    }
    return status;
}

/* 13.4.3. Interpreting the File Layout Using Dense Packing
* http://tools.ietf.org/html/rfc5661#section-13.4.3 */

static enum pnfs_status get_dense_fh(
    IN pnfs_file_layout *layout,
    IN uint32_t stripeid,
    OUT nfs41_path_fh **file_out)
{
    const uint32_t filehandle_count = layout->filehandles.count;
    const uint32_t stripe_count = layout->device->stripes.count;
    enum pnfs_status status = PNFS_SUCCESS;

    if (filehandle_count == stripe_count) {
        *file_out = &layout->filehandles.arr[stripeid];
    } else {
        eprintf("invalid dense layout! has %u file handles "
            "and %u stripes\n", filehandle_count, stripe_count);
        status = PNFSERR_INVALID_FH_LIST;
    }
    return status;
}

static enum pnfs_status thread_init(
    IN pnfs_io_pattern *pattern,
    IN pnfs_io_thread *thread,
    IN pnfs_file_layout *layout,
    IN uint32_t stripeid)
{
    thread->pattern = pattern;
    thread->layout = layout;
    thread->stable = FILE_SYNC4;
    thread->offset = pattern->offset_start;
    thread->id = stripeid;

    return is_dense(layout) ? get_dense_fh(layout, stripeid, &thread->file)
        : get_sparse_fh(layout, pattern->meta_file, stripeid, &thread->file);
}

static enum pnfs_status pattern_init(
    IN pnfs_io_pattern *pattern,
    IN nfs41_root *root,
    IN nfs41_path_fh *meta_file,
    IN const stateid_arg *stateid,
    IN pnfs_layout_state *state,
    IN unsigned char *buffer,
    IN uint64_t offset,
    IN uint64_t length,
    IN uint32_t default_lease)
{
    uint32_t i;
    enum pnfs_status status;

    pattern->count = state->layout->device->stripes.count;
    pattern->threads = calloc(pattern->count, sizeof(pnfs_io_thread));
    if (pattern->threads == NULL) {
        status = PNFSERR_RESOURCES;
        goto out;
    }

    pattern->root = root;
    pattern->meta_file = meta_file;
    pattern->stateid = stateid;
    pattern->state = state;
    pattern->buffer = buffer;
    pattern->offset_start = offset;
    pattern->offset_end = offset + length;
    pattern->default_lease = default_lease;

    for (i = 0; i < pattern->count; i++) {
        status = thread_init(pattern, &pattern->threads[i], state->layout, i);
        if (status)
            goto out_err_free;
    }

    /* take a reference on the layout so we don't return it during io */
    status = pnfs_layout_io_start(state);
    if (status)
        goto out_err_free;
out:
    return status;

out_err_free:
    free(pattern->threads);
    pattern->threads = NULL;
    goto out;
}

static void pattern_free(
    IN pnfs_io_pattern *pattern)
{
    /* inform the layout that our io is finished */
    pnfs_layout_io_finished(pattern->state);
    free(pattern->threads);
}

static __inline uint64_t positive_remainder(
    IN uint64_t dividend,
    IN uint32_t divisor)
{
    const uint64_t remainder = dividend % divisor;
    return remainder < divisor ? remainder : remainder + divisor;
}

/* return the next unit of the given stripeid */
static enum pnfs_status stripe_next_unit(
    IN const pnfs_file_layout *layout,
    IN uint32_t stripeid,
    IN uint64_t *position,
    IN uint64_t offset_end,
    OUT pnfs_io_unit *io)
{
    const uint32_t unit_size = layout_unit_size(layout);
    const uint32_t stripe_count = layout->device->stripes.count;
    uint64_t sui = stripe_unit_number(layout, *position, unit_size);

    /* advance to the desired stripeid */
    sui += abs(stripeid - stripe_index(layout, sui, stripe_count));

    io->offset = stripe_unit_offset(layout, sui, unit_size);
    if (io->offset < *position) /* don't start before position */
        io->offset = *position;
    else
        *position = io->offset;

    io->length = stripe_unit_offset(layout, sui + 1, unit_size);
    if (io->length > offset_end) /* don't end past offset_end */
        io->length = offset_end;

    if (io->offset >= io->length) /* nothing to do, return success */
        return PNFS_SUCCESS;

    io->length -= io->offset;

    if (is_dense(layout)) {
        const uint64_t rel_offset = io->offset - layout->pattern_offset;
        const uint64_t remainder = positive_remainder(rel_offset, unit_size);
        const uint32_t stride = unit_size * stripe_count;

        io->offset = (rel_offset / stride) * unit_size + remainder;
    }
    return PNFS_PENDING;
}

static enum pnfs_status thread_next_unit(
    IN pnfs_io_thread *thread,
    OUT pnfs_io_unit *io)
{
    pnfs_io_pattern *pattern = thread->pattern;
    pnfs_layout_state *state = pattern->state;
    enum pnfs_status status = PNFS_SUCCESS;

    AcquireSRWLockShared(&state->lock);

    /* stop io if the layout is recalled */
    if (state->status & PNFS_LAYOUT_CHANGED) {
        status = PNFSERR_LAYOUT_CHANGED;
        goto out_unlock;
    }
    if (state->status & PNFS_LAYOUT_RECALLED) {
        status = PNFSERR_LAYOUT_RECALLED;
        goto out_unlock;
    }

    status = stripe_next_unit(thread->layout, thread->id,
        &thread->offset, pattern->offset_end, io);
    if (status == PNFS_PENDING)
        io->buffer = pattern->buffer + thread->offset - pattern->offset_start;

out_unlock:
    ReleaseSRWLockShared(&state->lock);
    return status;
}

static enum pnfs_status thread_data_server(
    IN pnfs_io_thread *thread,
    OUT pnfs_data_server **server_out)
{
    pnfs_file_device *device = thread->layout->device;
    const uint32_t serverid = data_server_index(device, thread->id);

    if (serverid >= device->servers.count)
        return PNFSERR_INVALID_DS_INDEX;

    *server_out = &device->servers.arr[serverid];
    return PNFS_SUCCESS;
}

static enum pnfs_status pattern_fork(
    IN pnfs_io_pattern *pattern,
    IN pnfs_io_thread_fn thread_fn)
{
    pnfs_io_unit io;
#ifdef PNFS_THREADING
    HANDLE *threads;
    uint32_t num_threads;
#endif
    uint32_t i;
    DWORD status;
    enum pnfs_status pnfsstat = PNFS_SUCCESS;

    if (pattern->count == 0)
        goto out;

#ifdef PNFS_THREADING
    /* create a thread for each unit that has actual io */
    threads = calloc(pattern->count, sizeof(HANDLE));
    if (threads == NULL) {
        pnfsstat = PNFSERR_RESOURCES;
        goto out;
    }

    num_threads = 0;
    for (i = 0; i < pattern->count; i++) {
        if (thread_next_unit(&pattern->threads[i], &io) == PNFS_PENDING) {
            threads[num_threads++] = (HANDLE)_beginthreadex(NULL, 0,
                thread_fn, &pattern->threads[i], 0, NULL);
        }
    }

    if (num_threads) { /* wait on all threads to finish */
        status = WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);
        if (status == WAIT_OBJECT_0)
            status = NO_ERROR;

        for (i = 0; i < num_threads; i++) {
            /* keep track of the most severe error returned by a thread */
            if (GetExitCodeThread(threads[i], &status))
                pnfsstat = max(pnfsstat, (enum pnfs_status)status);

            CloseHandle(threads[i]);
        }
    }

    free(threads);
#else
    /* process each server that has actual io */
    for (i = 0; i < pattern->count; i++) {
        if (thread_next_unit(&pattern->threads[i], &io) == PNFS_PENDING) {
            /* keep track of the most severe error returned by a thread */
            status = thread_fn(&pattern->threads[i]);
            pnfsstat = max(pnfsstat, (enum pnfs_status)status);
        }
    }
#endif
out:
    return pnfsstat;
}

static uint64_t pattern_bytes_transferred(
    IN pnfs_io_pattern *pattern,
    OUT OPTIONAL enum stable_how4 *stable)
{
    uint64_t lowest_offset = pattern->offset_end;
    uint32_t i;

    if (stable) *stable = FILE_SYNC4;

    for (i = 0; i < pattern->count; i++) {
        lowest_offset = min(lowest_offset, pattern->threads[i].offset);
        if (stable) *stable = min(*stable, pattern->threads[i].stable);
    }
    return lowest_offset - pattern->offset_start;
}


static enum pnfs_status map_ds_error(
    IN enum nfsstat4 nfsstat,
    IN pnfs_layout_state *state)
{
    switch (nfsstat) {
    case NO_ERROR:
        return PNFS_SUCCESS;

    /* 13.11 Layout Revocation and Fencing
     * http://tools.ietf.org/html/rfc5661#section-13.11
     * if we've been fenced, we'll either get ERR_STALE when we PUTFH
     * something in layout.filehandles, or ERR_PNFS_NO_LAYOUT when
     * attempting to READ or WRITE */
    case NFS4ERR_STALE:
    case NFS4ERR_PNFS_NO_LAYOUT:
        dprintf(IOLVL, "data server fencing detected!\n");

        AcquireSRWLockExclusive(&state->lock);
        /* flag the layout for return once io is finished */
        state->status |= PNFS_LAYOUT_RECALLED | PNFS_LAYOUT_CHANGED;
        /* reset GRANTED so we know not to try LAYOUTRETURN */
        state->status &= ~PNFS_LAYOUT_GRANTED;
        ReleaseSRWLockExclusive(&state->lock);

        /* return CHANGED to prevent any further use of the layout */
        return PNFSERR_LAYOUT_CHANGED;

    default:
        return PNFSERR_IO;
    }
}

static uint32_t WINAPI file_layout_read_thread(void *args)
{
    pnfs_io_unit io;
    stateid_arg stateid;
    pnfs_io_thread *thread = (pnfs_io_thread*)args;
    pnfs_io_pattern *pattern = thread->pattern;
    pnfs_data_server *server;
    nfs41_client *client;
    uint32_t maxreadsize, bytes_read, total_read;
    enum pnfs_status status;
    enum nfsstat4 nfsstat;
    bool_t eof;

    dprintf(IOLVL, "--> file_layout_read_thread(%u)\n", thread->id);

    /* get the data server for this thread */
    status = thread_data_server(thread, &server);
    if (status) {
        eprintf("thread_data_server() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }
    /* find or establish a client for this data server */
    status = pnfs_data_server_client(pattern->root,
        server, pattern->default_lease, &client);
    if (status) {
        eprintf("pnfs_data_server_client() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }

    memcpy(&stateid, pattern->stateid, sizeof(stateid));
    stateid.stateid.seqid = 0;

    total_read = 0;
    while ((status = thread_next_unit(thread, &io)) == PNFS_PENDING) {
        maxreadsize = max_read_size(client->session, &thread->file->fh);
        if (io.length > maxreadsize)
            io.length = maxreadsize;

        nfsstat = nfs41_read(client->session, thread->file, &stateid,
            io.offset, (uint32_t)io.length, io.buffer, &bytes_read, &eof);
        if (nfsstat) {
            eprintf("nfs41_read() failed with %s\n",
                nfs_error_string(nfsstat));
            status = map_ds_error(nfsstat, pattern->state);
            break;
        }

        total_read += bytes_read;
        thread->offset += bytes_read;

        if (eof) {
            dprintf(IOLVL, "read thread %u reached eof: offset %llu\n",
                thread->id, thread->offset);
            status = total_read ? PNFS_SUCCESS : PNFS_READ_EOF;
            break;
        }
    }
out:
    dprintf(IOLVL, "<-- file_layout_read_thread(%u) returning %s\n",
        thread->id, pnfs_error_string(status));
    return status;
}

static uint32_t WINAPI file_layout_write_thread(void *args)
{
    pnfs_io_unit io;
    stateid_arg stateid;
    nfs41_write_verf verf;
    pnfs_io_thread *thread = (pnfs_io_thread*)args;
    pnfs_io_pattern *pattern = thread->pattern;
    pnfs_data_server *server;
    nfs41_client *client;
    const uint64_t offset_start = thread->offset;
    uint64_t commit_min, commit_max;
    uint32_t maxwritesize, bytes_written, total_written;
    enum pnfs_status status;
    enum nfsstat4 nfsstat;

    dprintf(IOLVL, "--> file_layout_write_thread(%u)\n", thread->id);

    /* get the data server for this thread */
    status = thread_data_server(thread, &server);
    if (status) {
        eprintf("thread_data_server() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }
    /* find or establish a client for this data server */
    status = pnfs_data_server_client(pattern->root,
        server, pattern->default_lease, &client);
    if (status) {
        eprintf("pnfs_data_server_client() failed with %s\n",
            pnfs_error_string(status));
        goto out;
    }

    memcpy(&stateid, pattern->stateid, sizeof(stateid));
    stateid.stateid.seqid = 0;

    maxwritesize = max_write_size(client->session, &thread->file->fh);

retry_write:
    thread->offset = offset_start;
    thread->stable = FILE_SYNC4;
    commit_min = NFS4_UINT64_MAX;
    commit_max = 0;
    total_written = 0;

    while ((status = thread_next_unit(thread, &io)) == PNFS_PENDING) {
        if (io.length > maxwritesize)
            io.length = maxwritesize;

        nfsstat = nfs41_write(client->session, thread->file, &stateid, io.buffer,
            (uint32_t)io.length, io.offset, UNSTABLE4, &bytes_written, 
            &verf, NULL);
        if (nfsstat) {
            eprintf("nfs41_write() failed with %s\n",
                nfs_error_string(nfsstat));
            status = map_ds_error(nfsstat, pattern->state);
            break;
        }
        if (!verify_write(&verf, &thread->stable))
            goto retry_write;

        total_written += bytes_written;
        thread->offset += bytes_written;

        /* track the range for commit */
        if (commit_min > io.offset)
            commit_min = io.offset;
        if (commit_max < io.offset + io.length)
            commit_max = io.offset + io.length;
    }

    /* nothing to commit */
    if (commit_max <= commit_min)
        goto out;
    /* layout changed; redo all io against metadata server */
    if (status == PNFSERR_LAYOUT_CHANGED)
        goto out;
    /* the data is already in stable storage */
    if (thread->stable != UNSTABLE4)
        goto out;
    /* the metadata server expects us to commit there instead */
    if (should_commit_to_mds(thread->layout))
        goto out;

    dprintf(1, "sending COMMIT to data server for offset=%lld len=%lld\n",
        commit_min, commit_max - commit_min);
    nfsstat = nfs41_commit(client->session, thread->file,
        commit_min, (uint32_t)(commit_max - commit_min), 0, &verf, NULL);

    if (nfsstat)
        status = map_ds_error(nfsstat, pattern->state);
    else if (!verify_commit(&verf)) {
        /* resend the writes unless the layout was recalled */
        if (status != PNFSERR_LAYOUT_RECALLED)
            goto retry_write;
        status = PNFSERR_IO;
    } else {
        /* on successful commit, leave pnfs_status unchanged; if the
         * layout was recalled, we still want to return the error */
        thread->stable = DATA_SYNC4;
    }
out:
    dprintf(IOLVL, "<-- file_layout_write_thread(%u) returning %s\n",
        thread->id, pnfs_error_string(status));
    return status;
}


enum pnfs_status pnfs_read(
    IN nfs41_root *root,
    IN nfs41_open_state *state,
    IN stateid_arg *stateid,
    IN pnfs_layout_state *layout,
    IN uint64_t offset,
    IN uint64_t length,
    OUT unsigned char *buffer_out,
    OUT ULONG *len_out)
{
    pnfs_io_pattern pattern;
    enum pnfs_status status;

    dprintf(IOLVL, "--> pnfs_read(%llu, %llu)\n", offset, length);

    *len_out = 0;

    AcquireSRWLockExclusive(&layout->lock);

    /* get layouts/devices for the entire range; PNFS_PENDING means we
     * dropped the lock to send an rpc, so repeat until it succeeds */
    do {
        status = pnfs_layout_state_prepare(layout, state->session,
            &state->file, stateid, PNFS_IOMODE_READ, offset, length);
    } while (status == PNFS_PENDING);

    if (status == PNFS_SUCCESS) {
        /* interpret the layout and set up threads for io */
        status = pattern_init(&pattern, root, &state->file, stateid, layout,
            buffer_out, offset, length, state->session->lease_time);
        if (status)
            eprintf("pattern_init() failed with %s\n",
                pnfs_error_string(status));
    }

    ReleaseSRWLockExclusive(&layout->lock);

    if (status)
        goto out;

    status = pattern_fork(&pattern, file_layout_read_thread);
    if (status != PNFS_SUCCESS && status != PNFS_READ_EOF)
        goto out_free_pattern;

    *len_out = (ULONG)pattern_bytes_transferred(&pattern, NULL);

out_free_pattern:
    pattern_free(&pattern);
out:
    dprintf(IOLVL, "<-- pnfs_read() returning %s\n",
        pnfs_error_string(status));
    return status;
}

static enum pnfs_status layout_commit(
    IN nfs41_open_state *state,
    IN pnfs_layout_state *layout,
    IN uint64_t offset,
    IN uint64_t length,
    OUT nfs41_file_info *info)
{
    stateid4 layout_stateid;
    uint64_t last_offset = offset + length - 1;
    uint64_t *new_last_offset = NULL;
    enum nfsstat4 nfsstat;
    enum pnfs_status status = PNFS_SUCCESS;

    AcquireSRWLockExclusive(&state->lock);
    /* if this is past the current eof, update the open state's
     * last offset, and pass a pointer to LAYOUTCOMMIT */
    if (state->pnfs_last_offset < last_offset ||
        (state->pnfs_last_offset == 0 && last_offset == 0)) {
        state->pnfs_last_offset = last_offset;
        new_last_offset = &last_offset;
    }
    ReleaseSRWLockExclusive(&state->lock);

    AcquireSRWLockShared(&layout->lock);
    memcpy(&layout_stateid, &layout->stateid, sizeof(layout_stateid));
    ReleaseSRWLockShared(&layout->lock);

    dprintf(1, "LAYOUTCOMMIT for offset=%lld len=%lld new_last_offset=%u\n",
        offset, length, new_last_offset ? 1 : 0);
    nfsstat = pnfs_rpc_layoutcommit(state->session, &state->file,
        &layout_stateid, offset, length, new_last_offset, NULL, info);
    if (nfsstat) {
        dprintf(IOLVL, "pnfs_rpc_layoutcommit() failed with %s\n",
            nfs_error_string(nfsstat));
        status = PNFSERR_IO;
    }
    return status;
}

enum pnfs_status pnfs_write(
    IN nfs41_root *root,
    IN nfs41_open_state *state,
    IN stateid_arg *stateid,
    IN pnfs_layout_state *layout,
    IN uint64_t offset,
    IN uint64_t length,
    IN unsigned char *buffer,
    OUT ULONG *len_out,
    OUT nfs41_file_info *info)
{
    pnfs_io_pattern pattern;
    enum stable_how4 stable;
    enum pnfs_status status;
    enum nfsstat4 nfsstat;

    dprintf(IOLVL, "--> pnfs_write(%llu, %llu)\n", offset, length);

    *len_out = 0;

    AcquireSRWLockExclusive(&layout->lock);

    /* get layouts/devices for the entire range; PNFS_PENDING means we
     * dropped the lock to send an rpc, so repeat until it succeeds */
    do {
        status = pnfs_layout_state_prepare(layout, state->session,
            &state->file, stateid, PNFS_IOMODE_RW, offset, length);
    } while (status == PNFS_PENDING);

    if (status == PNFS_SUCCESS) {
        /* interpret the layout and set up threads for io */
        status = pattern_init(&pattern, root, &state->file, stateid, layout,
            buffer, offset, length, state->session->lease_time);
        if (status)
            eprintf("pattern_init() failed with %s\n",
                pnfs_error_string(status));
    }

    ReleaseSRWLockExclusive(&layout->lock);

    if (status)
        goto out;

    status = pattern_fork(&pattern, file_layout_write_thread);
    /* on layout recall, we still attempt to commit what we wrote */
    if (status != PNFS_SUCCESS && status != PNFSERR_LAYOUT_RECALLED)
        goto out_free_pattern;

    *len_out = (ULONG)pattern_bytes_transferred(&pattern, &stable);
    if (*len_out == 0)
        goto out_free_pattern;

    if (stable == UNSTABLE4) {
        nfs41_write_verf ignored;

        /* not all data was committed, so commit to metadata server */
        dprintf(1, "sending COMMIT to meta server for offset=%lld len=%lld\n",
            offset, *len_out);
        nfsstat = nfs41_commit(state->session, &state->file,
            offset, *len_out, 1, &ignored, info);
        if (nfsstat) {
            dprintf(IOLVL, "nfs41_commit() failed with %s\n",
                nfs_error_string(nfsstat));
            status = PNFSERR_IO;
        }
    } else if (stable == DATA_SYNC4) {
        /* send LAYOUTCOMMIT to sync the metadata */
        status = layout_commit(state, layout, offset, *len_out, info);
    } else {
        /* send a GETATTR to update the cached size */
        bitmap4 attr_request;
        nfs41_superblock_getattr_mask(state->file.fh.superblock, &attr_request);
        nfs41_getattr(state->session, &state->file, &attr_request, info);
    }
out_free_pattern:
    pattern_free(&pattern);
out:
    dprintf(IOLVL, "<-- pnfs_write() returning %s\n",
        pnfs_error_string(status));
    return status;
}