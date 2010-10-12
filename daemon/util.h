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

#ifndef __NFS41_DAEMON_UTIL_H__
#define __NFS41_DAEMON_UTIL_H__

#include "nfs41_types.h"


struct __nfs41_session;
struct __nfs41_write_verf;
enum stable_how4;

int safe_read(unsigned char **pos, uint32_t *remaining, void *dest, uint32_t dest_len);
int safe_write(unsigned char **pos, uint32_t *remaining, void *dest, uint32_t dest_len);
int get_name(unsigned char **pos, uint32_t *remaining, char *out_name);
int get_abs_path(unsigned char **pos, uint32_t *remaining, nfs41_abs_path *path);
int wchar2asci(WCHAR *src, char **dest, int dest_len);

const char* strip_path(
    IN const char *path,
    OUT uint32_t *len_out OPTIONAL);

uint32_t max_read_size(
    IN const struct __nfs41_session *session,
    IN const nfs41_fh *fh);
uint32_t max_write_size(
    IN const struct __nfs41_session *session,
    IN const nfs41_fh *fh);

bool_t verify_write(
    IN struct __nfs41_write_verf *verf,
    IN OUT enum stable_how4 *stable);

/* bitmap4 */
static __inline bool_t bitmap_isset(
    IN const bitmap4 *mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    return mask->count > word && mask->arr[word] & flag;
}
static __inline void bitmap_set(
    IN bitmap4 *mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    if (mask->count > word)
        mask->arr[word] |= flag;
    else {
        mask->count = word + 1;
        mask->arr[word] = flag;
    }
}
static __inline void bitmap_unset(
    IN bitmap4 *mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    if (mask->count > word) {
        mask->arr[word] &= ~flag;
        while (mask->count && mask->arr[mask->count-1] == 0)
            mask->count--;
    }
}

ULONG nfs_file_info_to_attributes(
    IN const nfs41_file_info *info);
void nfs_to_basic_info(
    IN const nfs41_file_info *info,
    OUT PFILE_BASIC_INFO basic_out);
void nfs_to_standard_info(
    IN const nfs41_file_info *info,
    OUT PFILE_STANDARD_INFO std_out);

void file_time_to_nfs_time(
    IN const PLARGE_INTEGER file_time,
    OUT nfstime4 *nfs_time);
void nfs_time_to_file_time(
    IN const nfstime4 *nfs_time,
    OUT PLARGE_INTEGER file_time);
void get_file_time(
    OUT PLARGE_INTEGER file_time);
void get_nfs_time(
    OUT nfstime4 *nfs_time);

int create_silly_rename(
    IN nfs41_abs_path *path,
    IN const nfs41_fh *fh,
    OUT nfs41_component *silly);

void map_access_2_allowdeny(
    IN ULONG access_mask,
    IN ULONG access_mode,
    OUT uint32_t *allow, 
    OUT uint32_t *deny);

bool_t multi_addr_find(
    IN const multi_addr4 *addrs,
    IN const netaddr4 *addr,
    OUT OPTIONAL uint32_t *index_out);

/* nfs_to_windows_error
 *   Returns a windows ERROR_ code corresponding to the given NFS4ERR_ status.
 * If the status is outside the range of valid NFS4ERR_ values, it is returned
 * unchanged.  Otherwise, if the status does not match a value in the mapping,
 * a debug warning is generated and the default_error value is returned.
 */
int nfs_to_windows_error(int status, int default_error);


__inline uint32_t align8(uint32_t offset) {
    return 8 + ((offset - 1) & ~7);
}
__inline uint32_t align4(uint32_t offset) {
    return 4 + ((offset - 1) & ~3);
}

/* path parsing */
__inline int is_delimiter(char c) {
    return c == '\\' || c == '/' || c == '\0';
}
__inline const char* next_delimiter(const char *pos, const char *end) {
    while (pos < end && !is_delimiter(*pos))
        pos++;
    return pos;
}
__inline const char* prev_delimiter(const char *pos, const char *start) {
    while (pos > start && !is_delimiter(*pos))
        pos--;
    return pos;
}
__inline const char* next_non_delimiter(const char *pos, const char *end) {
    while (pos < end && is_delimiter(*pos))
        pos++;
    return pos;
}
__inline const char* prev_non_delimiter(const char *pos, const char *start) {
    while (pos > start && is_delimiter(*pos))
        pos--;
    return pos;
}

bool_t next_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component);

bool_t last_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component);

bool_t is_last_component(
    IN const char *path,
    IN const char *path_end);

void abs_path_copy(
    OUT nfs41_abs_path *dst,
    IN const nfs41_abs_path *src);

void path_fh_init(
    OUT nfs41_path_fh *file,
    IN nfs41_abs_path *path);

void fh_copy(
    OUT nfs41_fh *dst,
    IN const nfs41_fh *src);

void path_fh_copy(
    OUT nfs41_path_fh *dst,
    IN const nfs41_path_fh *src);

__inline int valid_handle(HANDLE handle) {
    return handle != INVALID_HANDLE_VALUE && handle != 0;
}

#endif /* !__NFS41_DAEMON_UTIL_H__ */
