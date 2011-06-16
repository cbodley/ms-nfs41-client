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
#include <strsafe.h>
#include <stdio.h>
#include <time.h>

#include "nfs41_ops.h"
#include "from_kernel.h"
#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"


/* windows volume queries want size in 'units', so we have to
 * convert the nfs space_* attributes from bytes to units */
#define SECTORS_PER_UNIT    8
#define BYTES_PER_SECTOR    512
#define BYTES_PER_UNIT      (SECTORS_PER_UNIT * BYTES_PER_SECTOR)

#define TO_UNITS(bytes) (bytes / BYTES_PER_UNIT)

#define VOLUME_CACHE_EXPIRATION 20


/* NFS41_VOLUME_QUERY */
static int parse_volume(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;

    status = safe_read(&buffer, &length, &args->query, sizeof(FS_INFORMATION_CLASS));
    if (status) goto out;

    dprintf(1, "parsing NFS41_VOLUME_QUERY: query=%d\n", args->query);
out:
    return status;
}

static int get_volume_size_info(
    IN nfs41_open_state *state,
    IN const char *query,
    OUT OPTIONAL PLONGLONG total_out,
    OUT OPTIONAL PLONGLONG user_out,
    OUT OPTIONAL PLONGLONG avail_out)
{
    nfs41_file_info info = { 0 };
    nfs41_superblock *superblock = state->file.fh.superblock;
    int status = ERROR_NOT_FOUND;

    AcquireSRWLockShared(&superblock->lock);
    /* check superblock for cached attributes */
    if (time(NULL) <= superblock->cache_expiration) {
        info.space_total = superblock->space_total;
        info.space_avail = superblock->space_avail;
        info.space_free = superblock->space_free;
        status = NO_ERROR;

        dprintf(2, "%s cached: %llu user, %llu free of %llu total\n",
            query, info.space_avail, info.space_free, info.space_total);
    }
    ReleaseSRWLockShared(&superblock->lock);

    if (status) {
        bitmap4 attr_request = { 2, { 0, FATTR4_WORD1_SPACE_AVAIL |
            FATTR4_WORD1_SPACE_FREE | FATTR4_WORD1_SPACE_TOTAL } };

        /* query the space_ attributes of the filesystem */
        status = nfs41_getattr(state->session, &state->file,
            &attr_request, &info);
        if (status) {
            eprintf("nfs41_getattr() failed with %s\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
            goto out;
        }

        AcquireSRWLockExclusive(&superblock->lock);
        superblock->space_total = info.space_total;
        superblock->space_avail = info.space_avail;
        superblock->space_free = info.space_free;
        superblock->cache_expiration = time(NULL) + VOLUME_CACHE_EXPIRATION;
        ReleaseSRWLockExclusive(&superblock->lock);

        dprintf(2, "%s: %llu user, %llu free of %llu total\n",
            query, info.space_avail, info.space_free, info.space_total);
    }

    if (total_out) *total_out = TO_UNITS(info.space_total);
    if (user_out) *user_out = TO_UNITS(info.space_avail);
    if (avail_out) *avail_out = TO_UNITS(info.space_free);
out:
    return status;
}

static int handle_volume_attributes(
    IN volume_upcall_args *args,
    IN nfs41_open_state *state)
{
    PFILE_FS_ATTRIBUTE_INFORMATION attr = &args->info.attribute;
    const nfs41_superblock *superblock = state->file.fh.superblock;
    int status = NO_ERROR;

    attr->FileSystemAttributes = FILE_SUPPORTS_REMOTE_STORAGE;
    if (superblock->link_support)
        attr->FileSystemAttributes |= FILE_SUPPORTS_HARD_LINKS;
    if (superblock->symlink_support)
        attr->FileSystemAttributes |= FILE_SUPPORTS_REPARSE_POINTS;
    if (superblock->case_preserving)
        attr->FileSystemAttributes |= FILE_CASE_PRESERVED_NAMES;
    if (!superblock->case_insensitive)
        attr->FileSystemAttributes |= FILE_CASE_SENSITIVE_SEARCH;
    if (superblock->aclsupport)
        attr->FileSystemAttributes |= FILE_PERSISTENT_ACLS;

    attr->MaximumComponentNameLength = NFS41_MAX_COMPONENT_LEN;

    /* let the driver fill in FileSystemName/Len */

    args->len = sizeof(args->info.attribute);

    dprintf(2, "FileFsAttributeInformation: case_preserving %u, "
        "case_insensitive %u, max component %u\n",
        superblock->case_preserving, superblock->case_insensitive,
        attr->MaximumComponentNameLength);

    return status;
}

static int handle_volume(nfs41_upcall *upcall)
{
    volume_upcall_args *args = &upcall->args.volume;
    int status;

    switch (args->query) {
    case FileFsSizeInformation:
        args->len = sizeof(args->info.size);
        args->info.size.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.size.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(upcall->state_ref,
            "FileFsSizeInformation",
            &args->info.size.TotalAllocationUnits.QuadPart,
            &args->info.size.AvailableAllocationUnits.QuadPart,
            NULL);
        break;

    case FileFsFullSizeInformation:
        args->len = sizeof(args->info.fullsize);
        args->info.fullsize.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.fullsize.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(upcall->state_ref,
            "FileFsFullSizeInformation",
            &args->info.fullsize.TotalAllocationUnits.QuadPart,
            &args->info.fullsize.CallerAvailableAllocationUnits.QuadPart,
            &args->info.fullsize.ActualAvailableAllocationUnits.QuadPart);
        break;

    case FileFsAttributeInformation:
        status = handle_volume_attributes(args, upcall->state_ref);
        break;

    default:
        eprintf("unhandled fs query class %d\n", args->query);
        status = ERROR_INVALID_PARAMETER;
        break;
    }
    return status;
}

static int marshall_volume(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;

    status = safe_write(&buffer, length, &args->len, sizeof(args->len));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->info, args->len);
out:
    return status;
}


const nfs41_upcall_op nfs41_op_volume = {
    parse_volume,
    handle_volume,
    marshall_volume
};
