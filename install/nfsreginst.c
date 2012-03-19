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

Module Name:

    nfsreginst.c

--*/

#include "nfsreginst.h"



REGENTRY ProviderOrderKeyValues[] =
{
    { TEXT("ProviderOrder"), REG_SZ, 0,   0 }
};

BOOL RdrSetupProviderOrder( void )
{
    LPTSTR pOrderString = NULL;
    ULONG_PTR len;
    BOOL success = TRUE;
    LPTSTR pNewOrderString;

    while( RdrRemoveProviderFromOrder() ) {};

    len = RdrGetProviderOrderString( &pOrderString ) * sizeof(TCHAR);
    if ( len > 0 && pOrderString )
    {
        len += sizeof( PROVIDER_NAME ) + (2 * sizeof(TCHAR)); // add 2 for comma delimeter and null
        pNewOrderString = malloc( len );
        if ( pNewOrderString )
        {
            StringCbCopy( pNewOrderString, len, PROVIDER_NAME );
            StringCbCat( pNewOrderString, len, TEXT(",") );
            StringCbCat( pNewOrderString, len, pOrderString );
            success = RdrSetProviderOrderString( pNewOrderString );
            free( pNewOrderString );
        }
    }
    else
    {
        success = RdrSetProviderOrderString( PROVIDER_NAME );
    }
    if ( pOrderString )
    {
        free( pOrderString );
    }

    return success;
}


ULONG_PTR RdrGetProviderOrderString( __out LPTSTR *OrderString )
{
    HKEY hOrderKey;
    ULONG_PTR len = 0;

    if ( OpenKey( PROVIDER_ORDER_KEY, &hOrderKey ) )
    {
        ReadRegistryKeyValues( hOrderKey,
                               sizeof(ProviderOrderKeyValues) / sizeof(REGENTRY),
                               ProviderOrderKeyValues);

        RegCloseKey(hOrderKey);
        len = ProviderOrderKeyValues[0].dwLength / sizeof( TCHAR ) - 1;
        *OrderString = (LPTSTR) ProviderOrderKeyValues[0].pvValue;
    }

    return len;
}


BOOL RdrSetProviderOrderString( __in LPTSTR OrderString )
{
    HKEY hOrderKey;
    BOOL rc = FALSE;

    if ( CreateKey( PROVIDER_ORDER_KEY, &hOrderKey ) )
    {
        ProviderOrderKeyValues[0].dwLength = ( lstrlen( OrderString ) + 1 ) * sizeof( TCHAR );
        ProviderOrderKeyValues[0].pvValue = OrderString;
        WriteRegistryKeyValues( hOrderKey,
                                sizeof(ProviderOrderKeyValues) / sizeof(REGENTRY),
                                ProviderOrderKeyValues);
        RegCloseKey(hOrderKey);

        rc = TRUE;
    }

    return rc;
}


BOOL RdrRemoveProviderFromOrder( void )
{
    LPTSTR pCompare, OrderString, pOrig, Provider = PROVIDER_NAME;
    BOOL match = FALSE;
    ULONG_PTR len = 0;

    len = RdrGetProviderOrderString( &pOrig );
    OrderString = pOrig;
    if ( OrderString && Provider && *Provider )
    {
        pCompare = Provider;

        while ( *OrderString )
        {
            if ( toupper(*OrderString) != toupper(*pCompare++) )
            {
                pCompare = Provider;
                while ( ( *OrderString != TEXT(',') ) && ( *OrderString != TEXT('\0') ) )
                {
                    OrderString++;
                }
            }
            if ( *OrderString != TEXT('\0') ) OrderString++;
            if ( *pCompare == TEXT('\0') )
            {
                if ( ( *OrderString == TEXT(',') ) || ( *OrderString == TEXT('\0') ) )
                {
                    LPTSTR pNewString;
                    pNewString = malloc( len ); //Yes, this is a little larger than necessary
                    //No, I don't care that much
                    StringCchCopy(pNewString, len, pOrig);
                    //if ((DWORD_PTR)OrderString - (DWORD_PTR)pOrig - (DWORD_PTR)pCompare + (DWORD_PTR)Provider == 0 ) OrderString += 1;
                    if ( *OrderString == TEXT(',') )
                    {
                    StringCchCopy(pNewString + (DWORD_PTR)OrderString - (DWORD_PTR)pOrig - (DWORD_PTR)pCompare + (DWORD_PTR)Provider, len, OrderString + 1);
                    }
                    else
                    {
                        StringCchCopy(pNewString + (DWORD_PTR)OrderString - (DWORD_PTR)pOrig - (DWORD_PTR)pCompare + (DWORD_PTR)Provider - 1, len, OrderString);
                    }
                    match = RdrSetProviderOrderString( pNewString );
                    free(pNewString);
                    break;
                }
                else    // hmm, it's a substring of another provider name
                {
                    while ( ( *OrderString != TEXT(',') ) && ( *OrderString != TEXT('\0') ) )
                    {
                        OrderString++;
                    }
                    pCompare = Provider;
                }
            }

        }
    }
    free( pOrig );

    return match;
}

void
ReadRegistryKeyValues(
    HKEY       hCurrentKey,
    DWORD      NumberOfValues,
    PREGENTRY pValues)
/*++

Routine Description:

    This routine reads a bunch of values associated with a given key.

Arguments:

    hCurrentKey - the key

    NumberOfValues - the number of values

    pValues - the array of values

Return Value:

   None

--*/
{
    //
    // Iterate through table reading the values along the way
    //

    DWORD  i;

    for (i = 0; i < NumberOfValues; i++)
    {
        DWORD dwType;
        LPTSTR pszKey;

        dwType  = pValues[i].dwType;
        pszKey  = pValues[i].pszKey;

        switch (dwType)
        {
        case REG_SZ:
            GetRegsz(hCurrentKey, pszKey, &pValues[i].pvValue,
                     &pValues[i].dwLength);
            break;

        case REG_DWORD:
            GetRegdw(hCurrentKey, pszKey,  &pValues[i].pvValue,
                     &pValues[i].dwLength);
            break;

        case REG_EXPAND_SZ:
            GetRegesz(hCurrentKey, pszKey, &pValues[i].pvValue,
                      &pValues[i].dwLength);
            break;

        case REG_MULTI_SZ:
            GetRegmsz(hCurrentKey, pszKey, &pValues[i].pvValue,
                      &pValues[i].dwLength);
            break;

        case REG_BINARY:
            break;

        default:
            break;

        }
    }
}

//
// Get a REG_SZ value and stick it in the table entry, along with the
// length
//

BOOL GetRegsz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD *pdwLength)
{
    BYTE  achValue[1024];

    DWORD dwLength;
    LONG  Status;
    DWORD dwType   = REG_SZ;
    PBYTE pszValue = NULL;



    if ( (NULL == pszKey) || (NULL == ppvValue) ||
         (NULL == hKey)   || (NULL == pdwLength))
    {
        return FALSE;
    }

#ifdef _DEBUG
    FillMemory(achValue, sizeof(achValue), 0xcd);
#endif

    dwLength = sizeof(achValue);


    Status = RegGetValue( hKey,
                               NULL,
                               pszKey,
                               0x0000002, //RRF_RD_REG_SZ
                               &dwType,
                               (PVOID) &achValue[0],
                               &dwLength);

    if ((ERROR_SUCCESS != Status) || (REG_SZ != dwType) )
    {
        return FALSE;
    }

    pszValue = malloc(dwLength);

    if (NULL == pszValue)
    {
        return FALSE;
    }


    CopyMemory(pszValue, achValue, dwLength);

    *ppvValue  = pszValue;
    *pdwLength = dwLength;

    return TRUE;
}

//
// Get the value of a REG_EXPAND_SZ and its length
//

BOOL GetRegesz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD * pdwLength)
{
    BYTE  achValue[1024];

    DWORD dwLength;
    LONG  Status;
    DWORD dwType   = REG_EXPAND_SZ;
    PBYTE pszValue = NULL;


    if ( (NULL == pszKey) || (NULL == ppvValue) ||
         (NULL == hKey)   || (NULL == pdwLength))
    {
        return FALSE;
    }

#ifdef _DEBUG
    FillMemory(achValue, sizeof(achValue), 0xcd);
#endif

    dwLength = sizeof(achValue);

    Status = RegQueryValueEx( hKey,
                               pszKey,
                               NULL,
                               &dwType,
                               (PUCHAR) &achValue[0],
                               &dwLength);

    if ((ERROR_SUCCESS != Status) || (REG_EXPAND_SZ != dwType))
    {
        return FALSE;
    }

    pszValue = malloc(dwLength);

    if (NULL == pszValue)
    {
        return FALSE;
    }

    CopyMemory(pszValue, achValue, dwLength);

    *ppvValue  = pszValue;
    *pdwLength = dwLength;

    return TRUE;
}


//
// Get value and length of REG_MULTI_SZ
//

BOOL GetRegmsz(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount( *pdwLength) PVOID * ppvValue, __out DWORD * pdwLength)
{
    //BYTE  achValue[1024];
    BYTE  achValue[2048];    // careful, some of these strings are quite long

    DWORD dwLength;
    LONG  Status;
    DWORD dwType   = REG_MULTI_SZ;
    PBYTE pszValue = NULL;


    if ( (NULL == pszKey) || (NULL == ppvValue) ||
        (NULL == hKey)    || (NULL == pdwLength))
    {
        return FALSE;
    }

#ifdef _DEBUG
    FillMemory(achValue, sizeof(achValue), 0xcd);
#endif


    dwLength = sizeof(achValue);


    Status = RegQueryValueEx( hKey,
                               pszKey,
                               NULL,
                               &dwType,
                               (PUCHAR) &achValue[0],
                               &dwLength);

    if ((ERROR_SUCCESS != Status) || (REG_MULTI_SZ != dwType))
    {
        return FALSE;
    }

    pszValue = malloc(dwLength);

    if (NULL == pszValue)
    {
        return FALSE;
    }

    CopyMemory(pszValue, achValue, dwLength);

    *ppvValue  = pszValue;
    *pdwLength = dwLength;

    return TRUE;
}


//
// Get value and length of REG_DWORD
//


BOOL GetRegdw(__in HKEY hKey, __in LPTSTR pszKey, __deref_out_bcount(*pdwLength) PVOID * ppvValue, __out DWORD * pdwLength)
{
    DWORD dwValue = 0;

    DWORD dwLength;
    LONG  Status;
    DWORD dwType   = REG_DWORD;



    if ( (NULL == pszKey) || (NULL == ppvValue) ||
         (NULL == hKey)   || (NULL == pdwLength) )
    {
        return FALSE;
    }

    dwLength = sizeof(dwValue);


    Status = RegQueryValueEx( hKey,
                               pszKey,
                               NULL,
                               &dwType,
                               (PUCHAR) &dwValue,
                               &dwLength);

    if ((ERROR_SUCCESS != Status) || (REG_DWORD != dwType))
    {
        return FALSE;
    }

    *ppvValue  = (PVOID) (ULONG_PTR) dwValue;
    *pdwLength = dwLength;

    return TRUE;
}



void
WriteRegistryKeyValues(
    HKEY        hCurrentKey,
    DWORD       NumberOfValues,
    PREGENTRY  pValues)
/*++

Routine Description:

    This routine reads a bunch of values associated with a given key.

Arguments:

    hCurrentKey - the key

    NumberOfValues - the number of values

    pValues - the array of values

Return Value:

   None

--*/
{
    DWORD i;


    for (i = 0; i < NumberOfValues; i++)
    {
        DWORD dwType;
        PVOID pvValue;
        DWORD dwLength;
        LPTSTR pszKey;

        pszKey   = pValues[i].pszKey;
        dwType   = pValues[i].dwType;
        dwLength = pValues[i].dwLength;
        pvValue  = pValues[i].pvValue;

        switch (dwType)
        {
        case REG_SZ:
            AddValue(hCurrentKey, pszKey, dwType, dwLength, pvValue);
            break;

        case REG_DWORD:
            AddValue(hCurrentKey, pszKey, dwType, dwLength, &pvValue);
            break;

        case REG_EXPAND_SZ:
            AddValue(hCurrentKey, pszKey, dwType, dwLength, pvValue);
            break;

        case REG_MULTI_SZ:
            AddValue(hCurrentKey, pszKey, dwType, dwLength, pvValue);
            break;

        case REG_BINARY:
            //
            // There are no binary values we need to copy. If we did, we'd
            // put something here
            //

            break;

        default:
            break;

        }
    }
}

//
// Open a key so we can read the values
//


BOOL OpenKey(
    __in LPTSTR pszKey,
    __out PHKEY phKey)
/*++

Routine Description:

    This routine opens a registry key.

Arguments:

    pszKey - the name of the key relative to HKEY_LOCAL_MACHINE

    phKey - the key handlle

Return Value:

    TRUE if successful, otherwise FALSE

--*/
{
    HKEY  hNewKey = 0;
    DWORD Status;

    Status = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                            pszKey,
                            0,
                            KEY_QUERY_VALUE,
                            &hNewKey);

    if (ERROR_SUCCESS != Status)
    {
        *phKey = NULL;
        return FALSE;
    }
    else
    {
        *phKey = hNewKey;
        return TRUE;
    }
}


BOOL CreateKey(__in LPTSTR pszKey, __out PHKEY phKey)
/*++

Routine Description:

    This routine creates a registry key.

Arguments:

    pszKey - the name of the key relative to HKEY_LOCAL_MACHINE

    phKey - the key handlle

Return Value:

    TRUE if successful, otherwise FALSE

--*/
{
    LONG   Status;
    DWORD  Disposition;

    Status =  RegCreateKeyEx( HKEY_LOCAL_MACHINE,
                               pszKey,
                               0,
                               REG_NONE,
                               REG_OPTION_NON_VOLATILE,
                               KEY_ALL_ACCESS,
                               NULL,
                               phKey,
                               &Disposition);

    if ( ERROR_SUCCESS == Status)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}


//
// Add a value to the registry
//


BOOL AddValue(__in HKEY hKey, __in LPTSTR pszKey, __in DWORD dwType, __in DWORD dwLength, __in PVOID pvValue)
{

    BOOL fSuccess = TRUE;
    LONG Status   = ERROR_SUCCESS;

    Status = RegSetValueEx( hKey,
                             pszKey,
                             0,
                             dwType,
                             pvValue,
                             dwLength);


    if (Status != ERROR_SUCCESS)
    {
        fSuccess = FALSE;
        //RegCloseKey(hKey);
    }

    return fSuccess;
}
