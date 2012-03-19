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
