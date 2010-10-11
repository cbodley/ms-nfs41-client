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

#ifndef __NFS41_DAEMON_NAME_CACHE_H__
#define __NFS41_DAEMON_NAME_CACHE_H__

#include "nfs41.h"


static __inline struct nfs41_name_cache* client_name_cache(
    IN nfs41_client *client)
{
    return client_server(client)->name_cache;
}

static __inline struct nfs41_name_cache* session_name_cache(
    IN nfs41_session *session)
{
    return client_name_cache(session->client);
}


/* attribute cache */
int nfs41_attr_cache_lookup(
    IN struct nfs41_name_cache *cache,
    IN uint64_t fileid,
    OUT nfs41_file_info *info_out);

int nfs41_attr_cache_update(
    IN struct nfs41_name_cache *cache,
    IN uint64_t fileid,
    IN const nfs41_file_info *info);


/* name cache */
int nfs41_name_cache_create(
    OUT struct nfs41_name_cache **cache_out);

int nfs41_name_cache_free(
    IN OUT struct nfs41_name_cache **cache_out);

int nfs41_name_cache_lookup(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const char *path_end,
    OUT OPTIONAL const char **remaining_path_out,
    OUT OPTIONAL nfs41_fh *parent_out,
    OUT OPTIONAL nfs41_fh *target_out,
    OUT OPTIONAL nfs41_file_info *info_out,
    OUT OPTIONAL bool_t *is_negative);

int nfs41_name_cache_insert(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const nfs41_component *name,
    IN const nfs41_fh *fh,
    IN const nfs41_file_info *info,
    IN OPTIONAL const change_info4 *cinfo);

int nfs41_name_cache_remove(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const nfs41_component *name,
    IN const change_info4 *cinfo);

int nfs41_name_cache_rename(
    IN struct nfs41_name_cache *cache,
    IN const char *src_path,
    IN const nfs41_component *src_name,
    IN const change_info4 *src_cinfo,
    IN const char *dst_path,
    IN const nfs41_component *dst_name,
    IN const change_info4 *dst_cinfo);

int nfs41_name_cache_remove_stale(
    IN struct nfs41_name_cache *cache,
    IN nfs41_session *session,
    IN nfs41_abs_path *path);

#endif /* !__NFS41_DAEMON_NAME_CACHE_H__ */
