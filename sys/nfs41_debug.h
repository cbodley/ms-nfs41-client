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

#ifndef _NFS41_DEBUG_
#define _NFS41_DEBUG_

#define _DRIVER_NAME_ "NFS4.1 Driver"

ULONG __cdecl DbgP(IN PCCH fmt, ...);
VOID print_srv_call(int on, IN PMRX_SRV_CALL p);
VOID print_net_root(int on, IN PMRX_NET_ROOT p);
VOID print_v_net_root(int on, IN PMRX_V_NET_ROOT p);
VOID print_fcb(int on, IN PMRX_FCB p);
VOID print_srv_open(int on, IN PMRX_SRV_OPEN p);
VOID print_fobx(int on, IN PMRX_FOBX p);
VOID print_irp_flags(int on, PIRP irp);
VOID print_irps_flags(int on, PIO_STACK_LOCATION irps);
void print_nt_create_params(int on, NT_CREATE_PARAMETERS params);
unsigned char *print_file_information_class(int InfoClass);
unsigned char *print_fs_information_class(int InfoClass);
void print_hexbuf(int on, unsigned char *title, unsigned char *buf, int len);
void print_ioctl(int on, int op);
void print_fs_ioctl(int on, int op);
void print_driver_state(int state);
void print_file_object(int on, PFILE_OBJECT file);
void print_basic_info(int on, PFILE_BASIC_INFORMATION info);
void print_std_info(int on, PFILE_STANDARD_INFORMATION info);
void print_ea_info(int on, PFILE_FULL_EA_INFORMATION info);
void print_get_ea(int on, PFILE_GET_EA_INFORMATION info);
void print_caching_level(int on, ULONG flag);
const char *opcode2string(int opcode);
void print_open_error(int on, int status);
void print_wait_status(int on, const char *str, NTSTATUS status, 
                       const char *opcode, PVOID entry, int xid);

#define DbgEn() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "--> [%s] [%d] %s\n", _DRIVER_NAME_, IoGetCurrentProcess(), \
        __FUNCTION__); try {
        
#define DbgEx() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "<-- [%s] [%d] %s status = %08lx\n", _DRIVER_NAME_, IoGetCurrentProcess(), \
        __FUNCTION__, status); \
        } except (EXCEPTION_EXECUTE_HANDLER) { \
            status = GetExceptionCode() ; \
            DbgP("Exception encountered with value = Ox%x\n", status); \
        }
#define DbgR() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "<-- [%s] [%d] %s\n", _DRIVER_NAME_, IoGetCurrentProcess(), __FUNCTION__); \
        } except (EXCEPTION_EXECUTE_HANDLER) { \
            NTSTATUS status; \
            status = GetExceptionCode() ; \
            DbgP("Exception encountered with value = Ox%x\n", status); \
        }

/* These are for ToasterDebugPrint */

#define     DBG_ERROR       0x00000001
#define     DBG_WARN        0x00000002
#define     DBG_TRACE       0x00000004
#define     DBG_INFO        0x00000008
#define     DBG_DISP_IN     0x00000010 /* Marks entry into dispatch functions */
#define     DBG_DISP_OUT    0x00000020 /* Marks exit from dispatch functions */

/* I want to do:
 * #define dprintk(flags, args...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_MASK | flags, ## args)
 * but the ... is gcc specific, can't seem to do it here.
 */
#define PNFS_TRACE_TAG      "PNFSMRX: "
#define PNFS_FLTR_ID        DPFLTR_IHVDRIVER_ID

#define DbgEnter()      DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | DBG_DISP_IN, "%s*** %s ***\n", \
                                PNFS_TRACE_TAG, __FUNCTION__);
#define DbgExit(status) DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | DBG_DISP_OUT, "%s<-- %s <-- 0x%08lx\n", \
                                PNFS_TRACE_TAG, __FUNCTION__, status);
ULONG
dprintk(
    IN PCHAR func,
    IN ULONG flags,
    IN PCHAR format,
    ...);
#endif