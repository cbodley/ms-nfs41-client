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
/*
 *
 *	This file is just for prepending nfs41_driver to the
 *	correct regestry entry
 *
 */

#include <tchar.h>

#include "nfs41_driver.h"
#include "nfsreginst.h"

void __cdecl _tmain(int argc, TCHAR *argv[])
{
	if(argc == 1 || atoi(argv[1]) == 1)
	{
		RdrSetupProviderOrder();
	}
	else
	{
		while( RdrRemoveProviderFromOrder() ) {};
	}

	return;
}
