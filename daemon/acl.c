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
#include <sddl.h>

#include "nfs41.h"
#include "nfs41_ops.h"
#include "daemon_debug.h"
#include "util.h"
#include "upcall.h"
#include "nfs41_xdr.h"

static int parse_getacl(unsigned char *buffer, uint32_t length, 
                        nfs41_upcall *upcall)
{
    int status;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;

    dprintf(1, "parsing NFS41_ACL_QUERY: info_class=%d\n", args->query);
out:
    return status;
}

static int create_unknownsid(WELL_KNOWN_SID_TYPE type, PSID *sid, 
                             DWORD *sid_len)
{
    int status;
    *sid_len = 0;
    *sid = NULL;

    status = CreateWellKnownSid(type, NULL, *sid, sid_len);
    dprintf(1, "create_unknownsid: CreateWellKnownSid type %d returned %d "
            "GetLastError %d sid len %d needed\n", type, status, 
            GetLastError(), *sid_len); 
    if (status) 
        return ERROR_INTERNAL_ERROR;
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) 
        return status;
    *sid = malloc(*sid_len);
    if (*sid == NULL) 
        return ERROR_INSUFFICIENT_BUFFER;
    status = CreateWellKnownSid(type, NULL, *sid, sid_len);
    if (status) 
        return ERROR_SUCCESS;
    free(*sid);
    status = GetLastError();
    eprintf("create_unknownsid: CreateWellKnownSid failed with %d\n", status);
    return status;
}

static void convert_nfs4name_2_user_domain(LPSTR nfs4name, 
                                           LPSTR *domain)
{
    LPSTR p = nfs4name;
    for(; p[0] != '\0'; p++) {
        if (p[0] == '@') { 
            p[0] = '\0';
            *domain = &p[1];
            break;
        }
    }
}

static int map_name_2_sid(DWORD *sid_len, PSID *sid, LPCSTR name)
{
    int status = ERROR_INTERNAL_ERROR;
    SID_NAME_USE sid_type;
    LPSTR tmp_buf = NULL;
    DWORD tmp = 0;

    status = LookupAccountName(NULL, name, NULL, sid_len, NULL, &tmp, &sid_type);
    dprintf(1, "map_name_2_sid: LookupAccountName for %s returned %d "
            "GetLastError %d name len %d domain len %d\n", name, status, 
            GetLastError(), *sid_len, tmp); 
    if (status)
        return ERROR_INTERNAL_ERROR;

    status = GetLastError();
    switch(status) {
    case ERROR_INSUFFICIENT_BUFFER:
        *sid = malloc(*sid_len);
        if (*sid == NULL) {
            status = GetLastError();
            goto out;
        }
        tmp_buf = (LPSTR) malloc(tmp);
        if (tmp_buf == NULL)
            goto out_free_sid;
        status = LookupAccountName(NULL, name, *sid, sid_len, tmp_buf, 
                                    &tmp, &sid_type);
        free(tmp_buf);
        if (!status) {
            eprintf("map_name_2_sid: LookupAccountName for %s failed "
                    "with %d\n", name, GetLastError());
            goto out_free_sid;
        } else {
            LPSTR ssid = NULL;
            if (IsValidSid(*sid))
                if (ConvertSidToStringSidA(*sid, &ssid))
                    dprintf(1, "map_name_2_sid: sid_type = %d SID %s\n", 
                            sid_type, ssid);
                else
                    dprintf(1, "map_name_2_sid: ConvertSidToStringSidA failed "
                            "with %d\n", GetLastError());
            else
                dprintf(1, "map_name_2_sid: Invalid Sid ?\n");
            if (ssid) LocalFree(ssid);
        }
        status = ERROR_SUCCESS;
        break;
    case ERROR_NONE_MAPPED:
        status = create_unknownsid(WinNullSid, sid, sid_len);
        if (status)
            goto out_free_sid;
    }
out:
    return status;
out_free_sid:
    status = GetLastError();
    free(*sid);
    goto out;
}

static void free_sids(PSID *sids, int count)
{
    int i;
    for(i = 0; i < count; i++)
        free(sids[i]);
    free(sids);
}

static int check_4_special_identifiers(char *who, PSID *sid, DWORD *sid_len, 
                                       BOOLEAN *flag)
{
    int status = ERROR_SUCCESS;
    WELL_KNOWN_SID_TYPE type = 0;
    *flag = TRUE;
    if (!strncmp(who, ACE4_OWNER, strlen(ACE4_OWNER)-1))
        type = WinCreatorOwnerSid;
    else if (!strncmp(who, ACE4_GROUP, strlen(ACE4_GROUP)-1))
        type = WinCreatorGroupSid;
    else if (!strncmp(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)-1))
        type = WinWorldSid;
    else if (!strncmp(who, ACE4_NOBODY, strlen(ACE4_NOBODY)))
        type = WinNullSid;
    else 
        *flag = FALSE;
    if (*flag) 
        status = create_unknownsid(type, sid, sid_len);
    return status;
}

static int convert_nfs4acl_2_dacl(nfsacl41 *acl, int file_type, 
                                  PACL *dacl_out, PSID **sids_out)
{
    int status = ERROR_NOT_SUPPORTED, size = 0;
    uint32_t i;
    DWORD sid_len;
    PSID *sids;
    PACL dacl;
    LPSTR domain = NULL;
    BOOLEAN flag;

    sids = malloc(acl->count * sizeof(PSID));
    if (sids == NULL) {
        status = GetLastError();
        goto out;
    }
    for (i = 0; i < acl->count; i++) {
        convert_nfs4name_2_user_domain(acl->aces[i].who, &domain);
        dprintf(1, "handle_getacl: for user=%s domain=%s\n", 
                acl->aces[i].who, domain?domain:"<null>");
        status = check_4_special_identifiers(acl->aces[i].who, &sids[i], 
                                             &sid_len, &flag);
        if (status) {
            free_sids(sids, i);
            goto out;
        }
        if (!flag) {
            status = map_name_2_sid(&sid_len, &sids[i], acl->aces[i].who);
            if (status) {
                free_sids(sids, i);
                goto out;
            }
        } 
        size += sid_len - sizeof(DWORD);
    }
    size += sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE)*acl->count);
    size = (size + sizeof(DWORD) - 1) & 0xfffffffc; //align size on word boundry
    dacl = malloc(size);
    if (dacl == NULL)
        goto out_free_sids;
    
    if (InitializeAcl(dacl, size, ACL_REVISION)) {
        ACCESS_MASK mask;
        for (i = 0; i < acl->count; i++) {
            // nfs4 acemask should be exactly the same as file access mask
            mask = acl->aces[i].acemask;
            dprintf(1, "access mask %x\n", mask);
            if (acl->aces[i].acetype == ACE4_ACCESS_ALLOWED_ACE_TYPE) {
                status = AddAccessAllowedAce(dacl, ACL_REVISION, mask, sids[i]);
                if (!status) {
                    eprintf("convert_nfs4acl_2_dacl: AddAccessAllowedAce failed "
                            "with %d\n", status);
                    goto out_free_dacl;
                }
                else status = ERROR_SUCCESS;
            } else if (acl->aces[i].acetype == ACE4_ACCESS_DENIED_ACE_TYPE) {
                status = AddAccessDeniedAce(dacl, ACL_REVISION, mask, sids[i]);
                if (!status) {
                    eprintf("convert_nfs4acl_2_dacl: AddAccessDeniedAce failed "
                            "with %d\n", status);
                    goto out_free_dacl;
                }
                else status = ERROR_SUCCESS;
            } else {
                eprintf("convert_nfs4acl_2_dacl: unknown acetype %d\n", 
                        acl->aces[i].acetype);
                status = ERROR_INTERNAL_ERROR;
                free(dacl);
                free_sids(sids, acl->count);
                goto out;
            }
        }
    } else {
        eprintf("convert_nfs4acl_2_dacl: InitializeAcl failed with %d\n", status);
        goto out_free_dacl;
    }
    *sids_out = sids;
    *dacl_out = dacl;
out:
    return status;
out_free_dacl:
    free(dacl);
out_free_sids:
    free_sids(sids, acl->count);
    status = GetLastError();
    goto out;
}

static int handle_getacl(nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    getacl_upcall_args *args = &upcall->args.getacl;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_file_info info;
    bitmap4 attr_request;
    LPSTR domain = NULL;
    SECURITY_DESCRIPTOR sec_desc;
    PACL dacl = NULL;
    PSID *sids = NULL;
    PSID osid = NULL, gsid = NULL;
    DWORD sid_len;

    // need to cache owner/group information XX
    ZeroMemory(&info, sizeof(info));
    init_getattr_request(&attr_request);
    if (args->query & DACL_SECURITY_INFORMATION) {
        info.acl = calloc(1, sizeof(nfsacl41));
        if (info.acl == NULL) {
            status = GetLastError();
            goto out;
        }
        attr_request.arr[0] |= FATTR4_WORD0_ACL;
    }
    status = nfs41_getattr(state->session, &state->file, &attr_request, &info);
    if (status) {
        eprintf("handle_getacl: nfs41_cached_getattr() failed with %d\n", 
                status);
        goto out;
    }

    status = InitializeSecurityDescriptor(&sec_desc, 
                                          SECURITY_DESCRIPTOR_REVISION);
    if (!status) {
        status = GetLastError();
        eprintf("handle_getacl: InitializeSecurityDescriptor failed with %d\n", 
                status);
        goto out;
    }
     /* can't (re)use the same sid variable for both owner and group sids 
      * because security descriptor is created in absolute-form and it just
      * stores pointers to the sids. thus each owner and group needs its own
      * memory. free them after creating self-relative security descriptor. 
      */
    if (args->query & OWNER_SECURITY_INFORMATION) {
        // parse user@domain. currently ignoring domain part XX
        convert_nfs4name_2_user_domain(info.owner, &domain);
        dprintf(1, "handle_getacl: OWNER_SECURITY_INFORMATION: for user=%s "
                "domain=%s\n", info.owner, domain?domain:"<null>");
        sid_len = 0;
        status = map_name_2_sid(&sid_len, &osid, info.owner);
        if (status)
            goto out;
        status = SetSecurityDescriptorOwner(&sec_desc, osid, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorOwner failed with "
                    "%d\n", status);
            goto out;
        }
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        convert_nfs4name_2_user_domain(info.owner_group, &domain);
        dprintf(1, "handle_getacl: GROUP_SECURITY_INFORMATION: for %s "
                "domain=%s\n", info.owner_group, domain?domain:"<null>");
        sid_len = 0;
        status = map_name_2_sid(&sid_len, &gsid, info.owner_group);
        if (status)
            goto out;
        status = SetSecurityDescriptorGroup(&sec_desc, gsid, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorGroup failed with "
                    "%d\n", status);
            goto out;
        }
    }
    if (args->query & DACL_SECURITY_INFORMATION) {
        dprintf(1, "handle_getacl: DACL_SECURITY_INFORMATION\n");
        status = convert_nfs4acl_2_dacl(info.acl, state->type, &dacl, &sids);
        if (status)
            goto out;
        status = SetSecurityDescriptorDacl(&sec_desc, TRUE, dacl, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorDacl failed with "
                    "%d\n", status);
            goto out;
        }
    }

    args->sec_desc_len = 0;
    status = MakeSelfRelativeSD(&sec_desc, args->sec_desc, &args->sec_desc_len);
    if (status) {
        status = ERROR_INTERNAL_ERROR;
        goto out;
    }
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        eprintf("handle_getacl: MakeSelfRelativeSD failes with %d\n", status);
        goto out;
    }
    args->sec_desc = malloc(args->sec_desc_len);
    if (args->sec_desc == NULL) {
        status = GetLastError();
        goto out;
    }
    status = MakeSelfRelativeSD(&sec_desc, args->sec_desc, &args->sec_desc_len);
    if (!status) {
        status = GetLastError();
        eprintf("handle_getacl: MakeSelfRelativeSD failes with %d\n", status);
        free(args->sec_desc);
        goto out;
    } else status = ERROR_SUCCESS;

out:
    if (args->query & OWNER_SECURITY_INFORMATION) {
        if (osid) free(osid);
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        if (gsid) free(gsid);
    }
    if (args->query & DACL_SECURITY_INFORMATION) {
        if (sids) free_sids(sids, info.acl->count);
        free(dacl);
        nfsacl41_free(info.acl);
        free(info.acl);
    }
    return status;
}

static int marshall_getacl(unsigned char *buffer, uint32_t *length, 
                           nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_write(&buffer, length, &args->sec_desc_len, sizeof(DWORD));
    if (status) goto out;
    status = safe_write(&buffer, length, args->sec_desc, args->sec_desc_len);
    free(args->sec_desc);
    if (status) goto out;
out:
    return status;
}

const nfs41_upcall_op nfs41_op_getacl = {
    parse_getacl,
    handle_getacl,
    marshall_getacl
};

static int parse_setacl(unsigned char *buffer, uint32_t length, 
                        nfs41_upcall *upcall)
{
    int status;
    setacl_upcall_args *args = &upcall->args.setacl;
    ULONG sec_desc_len;

    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;
    status = safe_read(&buffer, &length, &sec_desc_len, sizeof(ULONG));
    if (status) goto out;
    args->sec_desc = malloc(sec_desc_len);
    if (args->sec_desc == NULL) {
        status = GetLastError();
        goto out;
    }
    status = safe_read(&buffer, &length, args->sec_desc, sec_desc_len);
    if (status) goto out_free;
    status = IsValidSecurityDescriptor(args->sec_desc);
    if (!status) {
        eprintf("parse_setacl: received invalid security descriptor\n");
        status = ERROR_INVALID_PARAMETER;
        goto out_free;
    } else status = 0;

    dprintf(1, "parsing NFS41_ACL_SET: info_class=%d sec_desc_len=%d\n", 
            args->query, sec_desc_len);
out:
    return status;
out_free:
    free(args->sec_desc);
    goto out;
}

static int is_well_known_sid(PSID sid, char *who) 
{
    int status, i;
    for (i = 0; i < 78; i++) {
        status = IsWellKnownSid(sid, (WELL_KNOWN_SID_TYPE)i);
        if (!status) continue;
        else {
            dprintf(1, "WELL_KNOWN_SID_TYPE %d\n", i);
            switch((WELL_KNOWN_SID_TYPE)i) {
            case WinCreatorOwnerSid:
                memcpy(who, ACE4_OWNER, strlen(ACE4_OWNER)+1); 
                return TRUE;
            case WinNullSid:
                memcpy(who, ACE4_NOBODY, strlen(ACE4_NOBODY)+1); 
                return TRUE;
            case WinAnonymousSid:
                memcpy(who, ACE4_ANONYMOUS, strlen(ACE4_ANONYMOUS)+1); 
                return TRUE;
            case WinWorldSid:
                memcpy(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1); 
                return TRUE;
            case WinCreatorGroupSid:
            case WinBuiltinUsersSid:
                memcpy(who, ACE4_GROUP, strlen(ACE4_GROUP)+1); 
                return TRUE;
            case WinAuthenticatedUserSid:
                memcpy(who, ACE4_AUTHENTICATED, strlen(ACE4_AUTHENTICATED)+1); 
                return TRUE;
            case WinDialupSid:
                memcpy(who, ACE4_DIALUP, strlen(ACE4_DIALUP)+1); 
                return TRUE;
            case WinNetworkSid:
                memcpy(who, ACE4_NETWORK, strlen(ACE4_NETWORK)+1); 
                return TRUE;
            case WinBatchSid:
                memcpy(who, ACE4_BATCH, strlen(ACE4_BATCH)+1); 
                return TRUE;
            case WinInteractiveSid:
                memcpy(who, ACE4_INTERACTIVE, strlen(ACE4_INTERACTIVE)+1); 
                return TRUE;
            case WinNetworkServiceSid:
            case WinLocalServiceSid:
            case WinServiceSid:
                memcpy(who, ACE4_SERVICE, strlen(ACE4_SERVICE)+1); 
                return TRUE;
            default: return FALSE;
            }
        }
    }
    return FALSE;
}

static void map_aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags)
{
    if (win_aceflags & OBJECT_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_FILE_INHERIT_ACE;
    if (win_aceflags & CONTAINER_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_FILE_INHERIT_ACE;
    if (win_aceflags & NO_PROPAGATE_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_NO_PROPAGATE_INHERIT_ACE;
    if (win_aceflags & INHERIT_ONLY_ACE)
        *nfs4_aceflags |= ACE4_INHERIT_ONLY_ACE;
    if (win_aceflags & INHERITED_ACE)
        *nfs4_aceflags |= ACE4_INHERITED_ACE;
    dprintf(1, "ACE FLAGS: %x nfs4 aceflags %x\n", 
            win_aceflags, *nfs4_aceflags);
}

static void map_acemask(ACCESS_MASK mask, int file_type, uint32_t *nfs4_mask)
{
    dprintf(1, "ACE MASK: %x\n", mask);
    print_windows_access_mask(0, mask);
    /* check if any GENERIC bits set */
    if (mask & 0xf000000) {
        if (mask & GENERIC_ALL) {
            if (file_type == NF4DIR)
                *nfs4_mask |= ACE4_ALL_DIR;
            else
                *nfs4_mask |= ACE4_ALL_FILE;
        } else {
            if (mask & GENERIC_READ)
                *nfs4_mask |= ACE4_GENERIC_READ;
            if (mask & GENERIC_WRITE)
                *nfs4_mask |= ACE4_GENERIC_WRITE;
            if (mask & GENERIC_EXECUTE)
                *nfs4_mask |= ACE4_GENERIC_EXECUTE;
        }
    }
    else /* ignoring generic and reserved bits */
        *nfs4_mask = mask & 0x00ffffff;
    print_nfs_access_mask(0, *nfs4_mask);
}

static int map_nfs4ace_who(PSID sid, PSID owner_sid, PSID group_sid, char *who_out, char *domain)
{
    int status = ERROR_INTERNAL_ERROR;
    DWORD size = 0, tmp_size = 0;
    SID_NAME_USE sid_type;
    LPSTR tmp_buf = NULL, who = NULL;

    status = IsValidSid(sid);
    if (!status) {
        eprintf("map_dacl_2_nfs4acl: invalid sid\n");
        status = GetLastError();
        goto out;
    }
    /* for ace mapping, we want to map owner's sid into "owner@" 
     * but for set_owner attribute we want to map owner into a user name
     * same applies to group
     */
    status = 0;
    if (owner_sid) {
        if (EqualSid(sid, owner_sid)) {
            dprintf(1, "map_nfs4ace_who: this is owner's sid\n");
            memcpy(who_out, ACE4_OWNER, strlen(ACE4_OWNER)+1); 
            return ERROR_SUCCESS;
        }
    }
    if (group_sid) {
        if (EqualSid(sid, group_sid)) {
            dprintf(1, "map_nfs4ace_who: this is group's sid\n");
            memcpy(who_out, ACE4_GROUP, strlen(ACE4_GROUP)+1); 
            return ERROR_SUCCESS;
        }
    }
    status = is_well_known_sid(sid, who_out);
    if (status) {
        if (!strncmp(who_out, ACE4_NOBODY, strlen(ACE4_NOBODY))) {
            size = (DWORD)strlen(ACE4_NOBODY);
            goto add_domain;
        }
        else
            return ERROR_SUCCESS;
    }

    status = LookupAccountSid(NULL, sid, who, &size, tmp_buf, 
        &tmp_size, &sid_type);
    dprintf(1, "map_nfs4ace_who: LookupAccountSid returned %d GetLastError "
            "%d name len %d domain len %d\n", status, GetLastError(), 
            size, tmp_size); 
    if (status)
        return ERROR_INTERNAL_ERROR;
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER)
        return ERROR_INTERNAL_ERROR;
    who = malloc(size);
    if (who == NULL) {
        status = GetLastError();
        goto out;
    }
    tmp_buf = malloc(tmp_size);
    if (tmp_buf == NULL)
        goto out_free_who;
    status = LookupAccountSid(NULL, sid, who, &size, tmp_buf, 
                                &tmp_size, &sid_type);
    free(tmp_buf);
    if (!status) {
        eprintf("map_nfs4ace_who: LookupAccountSid failed with %d\n", 
                GetLastError());
        goto out_free_who;
    }
    memcpy(who_out, who, size);
add_domain:
    memcpy(who_out+size, "@", sizeof(char));
    memcpy(who_out+size+1, domain, strlen(domain)+1);
    dprintf(1, "map_nfs4ace_who: who=%s\n", who_out);
    if (who) free(who);
    status = ERROR_SUCCESS;
out:
    return status;
out_free_who:
    free(who);
    status = GetLastError();
    goto out;
}
static int map_dacl_2_nfs4acl(PACL acl, PSID sid, PSID gsid, nfsacl41 *nfs4_acl, 
                                int file_type, char *domain)
{
    int status;
    if (acl == NULL) {
        dprintf(1, "this is a NULL dacl: all access to an object\n");
        nfs4_acl->count = 1;
        nfs4_acl->aces = calloc(1, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        memcpy(nfs4_acl->aces->who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1);
        nfs4_acl->aces->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
        if (file_type == NF4DIR)
            nfs4_acl->aces->acemask = ACE4_ALL_DIR;
        else
            nfs4_acl->aces->acemask = ACE4_ALL_FILE;
        nfs4_acl->aces->aceflag = 0;
    } else {
        int i;
        PACE_HEADER ace;
        PBYTE tmp_pointer;

        dprintf(1, "NON-NULL dacl with %d ACEs\n", acl->AceCount);
        print_hexbuf_no_asci(3, (unsigned char *)"ACL\n", 
                            (unsigned char *)acl, acl->AclSize);
        nfs4_acl->count = acl->AceCount;
        nfs4_acl->aces = calloc(nfs4_acl->count, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        for (i = 0; i < acl->AceCount; i++) {
            status = GetAce(acl, i, &ace);
            if (!status) {
                status = GetLastError();
                eprintf("map_dacl_2_nfs4acl: GetAce failed with %d\n", status);
                goto out_free;
            }
            tmp_pointer = (PBYTE)ace;
            print_hexbuf_no_asci(3, (unsigned char *)"ACE\n", 
                                    (unsigned char *)ace, ace->AceSize); 
            dprintf(1, "ACE TYPE: %x\n", ace->AceType);
            if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
            else if (ace->AceType == ACCESS_DENIED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_DENIED_ACE_TYPE;
            else {
                eprintf("map_dacl_2_nfs4acl: unsupported ACE type %d\n",
                    ace->AceType);
                status = ERROR_NOT_SUPPORTED;
                goto out_free;
            }

            map_aceflags(ace->AceFlags, &nfs4_acl->aces[i].aceflag);            
            map_acemask(*(PACCESS_MASK)(ace + 1), file_type, 
                        &nfs4_acl->aces[i].acemask);

            tmp_pointer += sizeof(ACCESS_MASK) + sizeof(ACE_HEADER);
            status = map_nfs4ace_who(tmp_pointer, sid, gsid, nfs4_acl->aces[i].who, 
                                     domain);
            if (status)
                goto out_free;
        }
    }
    status = ERROR_SUCCESS;
out:
    return status;
out_free:
    free(nfs4_acl->aces);
    goto out;
}

static int handle_setacl(nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    setacl_upcall_args *args = &upcall->args.setacl;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_file_info info;
    stateid_arg stateid;
    nfsacl41 nfs4_acl = { 0 };
    PSID sid = NULL, gsid = NULL;
    BOOL sid_default, gsid_default;

    ZeroMemory(&info, sizeof(info));

    if (args->query & OWNER_SECURITY_INFORMATION) {
        dprintf(1, "handle_setacl: OWNER_SECURITY_INFORMATION\n");
        status = GetSecurityDescriptorOwner(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = map_nfs4ace_who(sid, NULL, NULL, info.owner,
                                 state->session->client->domain_name);
        if (status)
            goto out;
        else {
            info.owner_len = (uint32_t)strlen(info.owner);
            info.attrmask.arr[1] |= FATTR4_WORD1_OWNER;
            info.attrmask.count = 2;
        }
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        dprintf(1, "handle_setacl: GROUP_SECURITY_INFORMATION\n");
        status = GetSecurityDescriptorGroup(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = map_nfs4ace_who(sid, NULL, NULL, info.owner_group,
                                 state->session->client->domain_name);
        if (status)
            goto out;
        else {
            info.owner_group_len = (uint32_t)strlen(info.owner_group);
            info.attrmask.arr[1] |= FATTR4_WORD1_OWNER_GROUP;
            info.attrmask.count = 2;
        }
    }
    if (args->query & DACL_SECURITY_INFORMATION) {
        BOOL dacl_present, dacl_default;
        PACL acl;
        dprintf(1, "handle_setacl: DACL_SECURITY_INFORMATION\n");
        status = GetSecurityDescriptorDacl(args->sec_desc, &dacl_present,
                                            &acl, &dacl_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorDacl failed with %d\n", status);
            goto out;
        }
        status = GetSecurityDescriptorOwner(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = GetSecurityDescriptorGroup(args->sec_desc, &gsid, &gsid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = map_dacl_2_nfs4acl(acl, sid, gsid, &nfs4_acl, state->type, 
                                    state->session->client->domain_name);
        if (status)
            goto out;
        else {
            info.acl = &nfs4_acl;
            info.attrmask.arr[0] |= FATTR4_WORD0_ACL;
            if (!info.attrmask.count)
                info.attrmask.count = 1;
        }
    }

    nfs41_lock_stateid_arg(state, &stateid);
    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        dprintf(1, "handle_setacl: nfs41_setattr() failed with error %s.\n",
                nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
    }
    if (args->query & DACL_SECURITY_INFORMATION)
        free(nfs4_acl.aces);
out:
    free(args->sec_desc);
    return status;
}

const nfs41_upcall_op nfs41_op_setacl = {
    parse_setacl,
    handle_setacl,
};