/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/


#ifndef _SYSTEM_H_
#define _SYSTEM_H_

#include "types.h"
#include "list.h"
#include "fe.h"


#define CFG_WIFI_OFFLOAD
#define MAX_PHY_PORTS           16

/* This should be defined based on board */
#define GEM_PORTS               7
#define WIFI0_PORT              GEM_PORTS
#define MAX_WIFI_VAPS           8

#ifdef CFG_WIFI_OFFLOAD
#define PORT_WIFI_IDX                   WIFI0_PORT
#define IS_WIFI_PORT(port)              (((port) >= WIFI0_PORT) && ((port) < (WIFI0_PORT + MAX_WIFI_VAPS)))
#else
#define IS_WIFI_PORT(port)              0
#endif


#endif

