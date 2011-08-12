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

#ifndef __NFS41_DAEMON_COMPOUND_H__
#define __NFS41_DAEMON_COMPOUND_H__

#include "nfs41.h"


/* COMPOUND */
typedef struct __nfs_argop4 {
    uint32_t                op;
    void                    *arg;
} nfs_argop4;

typedef struct __nfs41_compound_args {
    uint32_t                tag_len;
    unsigned char           tag[NFS4_OPAQUE_LIMIT];
    uint32_t                minorversion;
    uint32_t                argarray_count;
    nfs_argop4              *argarray; /* <> */
} nfs41_compound_args;

typedef struct __nfs_resop4 {
    uint32_t                op;
    void                    *res;
} nfs_resop4;

typedef struct __nfs41_compound_res {
    uint32_t                status;
    uint32_t                tag_len;
    unsigned char           tag[NFS4_OPAQUE_LIMIT];
    uint32_t                resarray_count;
    nfs_resop4              *resarray; /* <> */
} nfs41_compound_res;

typedef struct __nfs41_compound {
    nfs41_compound_args     args;
    nfs41_compound_res      res;
} nfs41_compound;


int compound_error(int status);

void compound_init(
    nfs41_compound *compound,
    nfs_argop4 *argops,
    nfs_resop4 *resops,
    const char *tag);

void compound_add_op(
    nfs41_compound *compound,
    uint32_t opnum,
    void *arg,
    void *res);

int compound_encode_send_decode(
    nfs41_session *session,
    nfs41_compound *compound,
    bool_t try_recovery);

#endif /* __NFS41_DAEMON_COMPOUND_H__ */
