/* This file contains a portion of code from Samba package, *
/* which contains the following license:                    *
/
   Unix SMB/Netbios implementation
   Version 1.9
   Main SMB server routine
   Copyright (C) Andrew Tridgell 1992-199

   This program is free software; you can redistribute it and/or modif
   it under the terms of the GNU General Public License as published b
   the Free Software Foundation; either version 2 of the License, o
   (at your option) any later version

   This program is distributed in the hope that it will be useful
   but WITHOUT ANY WARRANTY; without even the implied warranty o
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
   GNU General Public License for more details

   You should have received a copy of the GNU General Public Licens
   along with this program; if not, write to the Free Softwar
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/time.h>
#include "statusq.h"
#include <string.h>
#include <stdio.h>
#include <stddef.h>




