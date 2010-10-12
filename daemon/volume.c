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


int parse_volume(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;
    status = safe_read(&buffer, &length, &args->root, sizeof(HANDLE));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->query, sizeof(FS_INFORMATION_CLASS));
out:
    if (status)
        eprintf("parsing NFS41_VOLUME_QUERY failed with %d\n",
            status);
    else
        dprintf(1, "parsing NFS41_VOLUME_QUERY: root=0x%p, query=%d\n",
            args->root, args->query);
    return status;
}

static int get_volume_size_info(
    IN nfs41_session *session,
    IN const char *query,
    OUT OPTIONAL PLONGLONG total_out,
    OUT OPTIONAL PLONGLONG user_out,
    OUT OPTIONAL PLONGLONG avail_out)
{
    nfs41_file_info info = { 0 };
    bitmap4 attr_request = { 2, { 0, FATTR4_WORD1_SPACE_AVAIL |
        FATTR4_WORD1_SPACE_FREE | FATTR4_WORD1_SPACE_TOTAL } };
    int status;

    /* query the space_ attributes of the root filesystem */
    status = nfs41_getattr(session, NULL, &attr_request, &info);
    if (status) {
        eprintf("nfs41_getattr() failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    dprintf(2, "%s: %llu user, %llu free of %llu total\n", query,
        info.space_avail, info.space_free, info.space_total);

    if (total_out) *total_out = TO_UNITS(info.space_total);
    if (user_out) *user_out = TO_UNITS(info.space_avail);
    if (avail_out) *avail_out = TO_UNITS(info.space_free);
out:
    return status;
}

static int handle_volume_attributes(
    IN nfs41_session *session,
    IN volume_upcall_args *args)
{
    /* query the case_ attributes of the root filesystem */
    nfs41_file_info info = { 0 };
    bitmap4 attr_request = { 1, { FATTR4_WORD0_CASE_INSENSITIVE |
        FATTR4_WORD0_CASE_PRESERVING } };
    PFILE_FS_ATTRIBUTE_INFORMATION attr = &args->info.attribute;
    int status = NO_ERROR;

    status = nfs41_getattr(session, NULL, &attr_request, &info);
    if (status) {
        eprintf("nfs41_getattr() failed with %s\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    attr->FileSystemAttributes = FILE_SUPPORTS_REMOTE_STORAGE |
        FILE_SUPPORTS_REPARSE_POINTS;
    if (info.case_preserving)
        attr->FileSystemAttributes |= FILE_CASE_PRESERVED_NAMES;
    if (!info.case_insensitive)
        attr->FileSystemAttributes |= FILE_CASE_SENSITIVE_SEARCH;

    attr->MaximumComponentNameLength = NFS41_MAX_COMPONENT_LEN;

    /* let the driver fill in FileSystemName/Len */

    args->len = sizeof(args->info.attribute);

    dprintf(2, "FileFsAttributeInformation: case_preserving %u, "
        "case_insensitive %u, max component %u\n",
        info.case_preserving, info.case_insensitive,
        attr->MaximumComponentNameLength);
out:
    return status;
}

int handle_volume(nfs41_upcall *upcall)
{
    volume_upcall_args *args = &upcall->args.volume;
    nfs41_session *session = nfs41_root_session(args->root);
    int status;

    switch (args->query) {
    case FileFsSizeInformation:
        args->len = sizeof(args->info.size);
        args->info.size.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.size.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(session, "FileFsSizeInformation",
            &args->info.size.TotalAllocationUnits.QuadPart,
            &args->info.size.AvailableAllocationUnits.QuadPart,
            NULL);
        break;

    case FileFsFullSizeInformation:
        args->len = sizeof(args->info.fullsize);
        args->info.fullsize.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.fullsize.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(session, "FileFsFullSizeInformation",
            &args->info.fullsize.TotalAllocationUnits.QuadPart,
            &args->info.fullsize.CallerAvailableAllocationUnits.QuadPart,
            &args->info.fullsize.ActualAvailableAllocationUnits.QuadPart);
        break;

    case FileFsAttributeInformation:
        status = handle_volume_attributes(session, args);
        break;

    default:
        eprintf("unhandled fs query class %d\n", args->query);
        status = ERROR_INVALID_PARAMETER;
        break;
    }
    return status;
}

int marshall_volume(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;

    status = safe_write(&buffer, length, &args->len, sizeof(args->len));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->info, args->len);
out:
    return status;
}
