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
/*++

Copyright (c) 1997 - 1999  Microsoft Corporation

Module Name:

    srfunc.h

Abstract:

--*/

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>

#include "nfs41_driver.h"

typedef struct {
    LPTSTR pszKey;
    DWORD  dwType;
    DWORD  dwLength;
    PVOID  pvValue;
} REGENTRY, *PREGENTRY;

void
ReadRegistryKeyValues(
    HKEY hKey,
    DWORD Count,
    PREGENTRY pValues);

void
WriteRegistryKeyValues(
    HKEY hKey,
    DWORD Count,
    PREGENTRY pValues);


//
// routines for manipulating registry key values
//

BOOL GetRegsz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD *pdwLength);

BOOL GetRegesz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD * pdwLength);

BOOL GetRegmsz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD * pdwLength);

BOOL GetRegdw(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD * pdwLength);


//
// routines for manipulating registry keys
//

BOOL OpenKey(
    __in LPTSTR pszKey,
    __out PHKEY phKey);

BOOL CreateKey(__in LPTSTR pszKey, __out PHKEY phKey);
BOOL AddValue(__in HKEY hKey, __in LPTSTR pszKey, __in DWORD dwType, __in DWORD dwLength, __in PVOID pvValue);

BOOL      RdrSetupProviderOrder( void );
BOOL      RdrRemoveProviderFromOrder( void );

ULONG_PTR RdrGetProviderOrderString( __out LPTSTR *OrderString );
BOOL      RdrSetProviderOrderString( __in LPTSTR OrderString );


typedef BOOL (*ACTIONVECTOR) ( void );

#define RDRSERVICE          TEXT("nfs41_driver")
#define PROVIDER_NAME       RDRSERVICE

#define PROVIDER_ORDER_KEY  TEXT("System\\CurrentControlSet\\Control\\NetworkProvider\\Order")

