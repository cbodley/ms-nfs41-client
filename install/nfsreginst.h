/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
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

