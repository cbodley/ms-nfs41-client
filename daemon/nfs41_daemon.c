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
#include <process.h>
#include <tchar.h>
#include <stdio.h>

#include <devioctl.h>
#include <lmcons.h> /* UNLEN for GetUserName() */

#include "nfs41_driver.h" /* for NFS41_USER_DEVICE_NAME_A */
#include "nfs41_np.h" /* for NFS41NP_SHARED_MEMORY */

#include "idmap.h"
#include "daemon_debug.h"
#include "upcall.h"
#include "util.h"

#define MAX_NUM_THREADS 128
DWORD NFS41D_VERSION = 0;

#ifndef STANDALONE_NFSD //make sure to define it in "sources" not here
#include "service.h"
HANDLE  stop_event = NULL;
#endif
typedef struct _nfs41_process_thread {
    HANDLE handle;
    uint32_t tid;
} nfs41_process_thread;

static int map_user_to_ids(nfs41_idmapper *idmapper, uid_t *uid, gid_t *gid)
{
    char username[UNLEN + 1];
    DWORD len = UNLEN + 1;
    int status = NO_ERROR;

    if (!GetUserNameA(username, &len)) {
        status = GetLastError();
        eprintf("GetUserName() failed with %d\n", status);
        goto out;
    }
    dprintf(1, "map_user_to_ids: mapping user %s\n", username);

    if (nfs41_idmap_name_to_ids(idmapper, username, uid, gid)) {
        /* instead of failing for auth_sys, fall back to 'nobody' uid/gid */
        *uid = 666;
        *gid = 777;
    }
out:
    return status;
}

static unsigned int WINAPI thread_main(void *args) 
{
    nfs41_idmapper *idmapper = (nfs41_idmapper*)args;
    DWORD status = 0;
    HANDLE pipe;
    // buffer used to process upcall, assumed to be fixed size. 
    // if we ever need to handle non-cached IO, need to make it dynamic
    unsigned char outbuf[UPCALL_BUF_SIZE]; 
    // buffer used to send downcall content, need to dynamically allocated 
    // as we don't know the length of the buffer (ie. size of directory listing
    unsigned char *inbuf = NULL;
    DWORD inbuf_len, outbuf_len;
    nfs41_upcall upcall;

    pipe = CreateFile(NFS41_USER_DEVICE_NAME_A, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        eprintf("Unable to open upcall pipe %d\n", GetLastError());
        return GetLastError();
    }

    while(1) {
        status = DeviceIoControl(pipe, IOCTL_NFS41_READ, NULL, 0,
            outbuf, UPCALL_BUF_SIZE, (LPDWORD)&outbuf_len, NULL);
        if (!status) {
            eprintf("IOCTL_NFS41_READ failed %d\n", GetLastError());
            continue;
        }

        status = upcall_parse(outbuf, (uint32_t)outbuf_len, &upcall);
        if (status) {
            upcall.status = status;
            goto write_downcall;
        }

        /* map username to uid/gid */
        status = map_user_to_ids(idmapper, &upcall.uid, &upcall.gid);
        if (status) {
            upcall.status = status;
            goto write_downcall;
        }

        if (upcall.opcode == NFS41_SHUTDOWN) {
            printf("Shutting down..\n");
            exit(0);
        }

        status = upcall_handle(&upcall);

write_downcall:
        dprintf(1, "writing downcall: xid=%d opcode=%s status=%d "
            "get_last_error=%d\n", upcall.xid, opcode2string(upcall.opcode),
            upcall.status, upcall.last_error);

        if (upcall.opcode == NFS41_DIR_QUERY)
            inbuf_len = UPCALL_BUF_SIZE + upcall.args.readdir.query_reply_len;
        else
            inbuf_len = UPCALL_BUF_SIZE;

        inbuf = malloc(inbuf_len);
        upcall_marshall(&upcall, inbuf, (uint32_t)inbuf_len, (uint32_t*)&outbuf_len);

        dprintf(2, "making a downcall: outbuf_len %ld\n\n", outbuf_len);
        status = DeviceIoControl(pipe, IOCTL_NFS41_WRITE,
            inbuf, inbuf_len, NULL, 0, (LPDWORD)&outbuf_len, NULL);
        free(inbuf);
        if (!status) {
            eprintf("IOCTL_NFS41_WRITE failed with %d xid=%d opcode=%s\n", 
                GetLastError(), upcall.xid, opcode2string(upcall.opcode));
            upcall_cancel(&upcall);
        }
        if (upcall.status != NFSD_VERSION_MISMATCH)
            upcall_cleanup(&upcall);
    }
    CloseHandle(pipe);

    return GetLastError();
}

#ifndef STANDALONE_NFSD
VOID ServiceStop()
{
   if (stop_event)
      SetEvent(stop_event);
}
#endif

typedef struct _nfsd_args {
    bool_t ldap_enable;
    int debug_level;
} nfsd_args;

static void PrintUsage()
{
    fprintf(stderr, "Usage: nfsd.exe -d <debug_level> --noldap\n");
}
static bool_t parse_cmdlineargs(int argc, TCHAR *argv[], nfsd_args *out)
{
    int i;

    /* set defaults. */
    out->debug_level = 2;
    out->ldap_enable = TRUE;

    /* parse command line */
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == TEXT('-')) {
            if (_tcscmp(argv[i], TEXT("-h")) == 0) { /* help */
                PrintUsage();
                return FALSE;
            }
            else if (_tcscmp(argv[i], TEXT("-d")) == 0) { /* debug level */
                ++i;
                if (i >= argc) {
                    fprintf(stderr, "Missing debug level value\n");
                    PrintUsage();
                    return FALSE;
                } 
                out->debug_level = _ttoi(argv[i]);
            }
            else if (_tcscmp(argv[i], TEXT("--noldap")) == 0) { /* no LDAP */
                out->ldap_enable = FALSE;
            }
            else
                fprintf(stderr, "Unrecognized option '%s', disregarding.\n", argv[i]);
        }
    }
    fprintf(stdout, "parse_cmdlineargs: debug_level %d ldap is %d\n", 
        out->debug_level, out->ldap_enable);
    return TRUE;
}

#ifdef STANDALONE_NFSD
void __cdecl _tmain(int argc, TCHAR *argv[])
#else
VOID ServiceStart(DWORD argc, LPTSTR *argv)
#endif
{
    DWORD status = 0, len;
    // handle to our drivers
    HANDLE pipe;
    nfs41_process_thread tids[MAX_NUM_THREADS];
    nfs41_idmapper *idmapper = NULL;
    int i;
    nfsd_args cmd_args;

    if (!parse_cmdlineargs(argc, argv, &cmd_args)) 
        exit(0);
    set_debug_level(cmd_args.debug_level);
    open_log_files();

#ifdef _DEBUG
    /* dump memory leaks to stderr on exit; this requires the debug heap,
    /* available only when built in debug mode under visual studio -cbodley */
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    dprintf(1, "debug mode. dumping memory leaks to stderr on exit.\n");
#endif

    nfs41_server_list_init();

    if (cmd_args.ldap_enable) {
        status = nfs41_idmap_create(&idmapper);
        if (status) {
            eprintf("id mapping initialization failed with %d\n", status);
            goto out_logs;
        }
    }

    NFS41D_VERSION = GetTickCount();
    dprintf(1, "NFS41 Daemon starting: version %d\n", NFS41D_VERSION);

    pipe = CreateFile(NFS41_USER_DEVICE_NAME_A, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        eprintf("Unable to open upcall pipe %d\n", GetLastError());
        goto out_idmap;
    }

    dprintf(1, "starting nfs41 mini redirector\n");
    status = DeviceIoControl(pipe, IOCTL_NFS41_START,
        &NFS41D_VERSION, sizeof(DWORD), NULL, 0, (LPDWORD)&len, NULL);
    if (!status) {
        eprintf("IOCTL_NFS41_START failed with %d\n", 
                GetLastError());
        goto out_pipe;
    }

#ifndef STANDALONE_NFSD
    stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (stop_event == NULL)
      goto out_pipe;
#endif

    for (i = 0; i < MAX_NUM_THREADS; i++) {
        tids[i].handle = (HANDLE)_beginthreadex(NULL, 0, thread_main, 
                idmapper, 0, &tids[i].tid);
        if (tids[i].handle == INVALID_HANDLE_VALUE) {
            status = GetLastError();
            eprintf("_beginthreadex failed %d\n", status);
            goto out_pipe;
        }
    }
#ifndef STANDALONE_NFSD
    // report the status to the service control manager.
    if (!ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0))
        goto out_pipe;
    WaitForSingleObject(stop_event, INFINITE);
#else
    //This can be changed to waiting on an array of handles and using waitformultipleobjects
    dprintf(1, "Parent waiting for children threads\n");
    for (i = 0; i < MAX_NUM_THREADS; i++)
        WaitForSingleObject(tids[i].handle, INFINITE );
#endif
    dprintf(1, "Parent woke up!!!!\n");

out_pipe:
    CloseHandle(pipe);
out_idmap:
    if (idmapper) nfs41_idmap_free(idmapper);
out_logs:
#ifndef STANDALONE_NFSD
    close_log_files();
#endif
    return;
}
