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

#include "nfs41_driver.h" /* for NFS41_USER_DEVICE_NAME_A */
#include "nfs41_np.h" /* for NFS41NP_SHARED_MEMORY */

#include "daemon_debug.h"
#include "upcall.h"
#include "util.h"


#define MAX_NUM_THREADS 128
BOOLEAN CREATED_SESSION = FALSE;

typedef struct _nfs41_process_thread {
    HANDLE handle;
    uint32_t tid;
} nfs41_process_thread;

static unsigned int WINAPI thread_main(void *args) 
{
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
        if (status)
            goto write_downcall;

#if 1   //AGLO: this is just a placeholder for a real solution. I know this variable needs a lock in a
        //normal case. However, this does not prevent us from receiving an upcall for an old mount
        //that was not reestablished. It will only work for erroring requests until the 1st mount upcall.
        if (!CREATED_SESSION && (upcall.opcode != NFS41_MOUNT && upcall.opcode != NFS41_SHUTDOWN)) {
            eprintf("nfs41_daemon restarted and does not have a valid session established\n");
            upcall.status = 116;
            goto write_downcall;
        }
#endif

        if (upcall.opcode == NFS41_SHUTDOWN) {
            printf("Shutting down..\n");
            exit(0);
        }

        status = upcall_handle(&upcall);

#if 1 //AGLO: place holder for a real solution
        if (upcall.opcode == NFS41_MOUNT && upcall.status == NO_ERROR)
            CREATED_SESSION = 1;
#endif

write_downcall:
        dprintf(1, "writing downcall: xid=%d opcode=%s status=%d "
            "get_last_error=%d\n", upcall.xid, opcode2string(upcall.opcode),
            upcall.status, upcall.last_error);

        if (upcall.opcode == NFS41_DIR_QUERY)
            inbuf_len = UPCALL_BUF_SIZE + upcall.args.readdir.query_reply_len;
        else
            inbuf_len = UPCALL_BUF_SIZE;

        inbuf = malloc(inbuf_len);
        status = upcall_marshall(&upcall, inbuf, (uint32_t)inbuf_len, (uint32_t*)&outbuf_len);

        dprintf(2, "making a downcall: outbuf_len %ld\n", outbuf_len);
        status = DeviceIoControl(pipe, IOCTL_NFS41_WRITE,
            inbuf, inbuf_len, NULL, 0, (LPDWORD)&outbuf_len, NULL);
        free(inbuf);
        if (!status) {
            eprintf("IOCTL_NFS41_WRITE failed with %d xid=%d opcode=%s\n", 
                GetLastError(), upcall.xid, opcode2string(upcall.opcode));
            status = upcall_cancel(&upcall);
            continue;
        }
        dprintf(3, "downcall returned %d\n", status);
        printf("\n");
    }
    CloseHandle(pipe);

    return GetLastError();
}

void __cdecl _tmain(int argc, TCHAR *argv[])
{
    DWORD status = 0, len;
    // handle to our drivers
    HANDLE pipe;
    nfs41_process_thread tids[MAX_NUM_THREADS];
    int i;

    if (argc > 2) {
        const char *process = strip_path(argv[0], NULL);
        printf("Usage: %s [#debug level]\n", process);
    } else if (argc == 2) {
        set_debug_level(_ttoi(argv[1]));
    }

#ifdef _DEBUG
    /* dump memory leaks to stderr on exit; this requires the debug heap,
    /* available only when built in debug mode under visual studio -cbodley */
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    dprintf(1, "debug mode. dumping memory leaks to stderr on exit.\n");
#endif

    nfs41_server_list_init();

    pipe = CreateFile(NFS41_USER_DEVICE_NAME_A, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        eprintf("Unable to open upcall pipe %d\n", GetLastError());
        return;
    }

    dprintf(1, "starting nfs41 mini redirector\n");
    status = DeviceIoControl(pipe, IOCTL_NFS41_START,
        NULL, 0, NULL, 0, (LPDWORD)&len, NULL);
    if (!status) {
        eprintf("IOCTL_NFS41_START failed with %d\n", 
                GetLastError());
        goto quit;
    }

    for (i = 0; i < MAX_NUM_THREADS; i++) {
        tids[i].handle = (HANDLE)_beginthreadex(NULL, 0, thread_main, 
                NULL, 0, &tids[i].tid);
        if (tids[i].handle == INVALID_HANDLE_VALUE) {
            status = GetLastError();
            eprintf("_beginthreadex failed %d\n", status);
            goto quit;
        }
    }
    //This can be changed to waiting on an array of handles and using waitformultipleobjects
    dprintf(1, "Parent waiting for children threads\n");
    for (i = 0; i < MAX_NUM_THREADS; i++)
        WaitForSingleObject(tids[i].handle, INFINITE );
    dprintf(1, "Parent woke up!!!!\n");

quit:
    CloseHandle(pipe);
    return;
}
