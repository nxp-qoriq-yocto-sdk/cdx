/** @file
 * This file contains the scheduler messaging related code 
 */

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


/* Error Macros  */
typedef enum
{
  QOS_CEETM_ERR_INVALID_LNI_CTXT = 1, 
  QOS_CEETM_ERR_CONFIG_LNI_FAILED,
  QOS_CEETM_ERR_INVALID_CHANNEL_CTXT,
  QOS_CEETM_ERR_CHANNEL_EXISTS,
  QOS_CEETM_ERR_INVALID_INPUTS_GIVEN_FOR_SHAPED_CHANNEL,
  QOS_CEETM_ERR_INVALID_INPUTS_GIVEN_FOR_UNSHAPED_CHANNEL,
  QOS_CEETM_ERR_FAILED_TO_CREATE_CHANNEL,
  QOS_CEETM_ERR_INVALID_CHANNEL,
  QOS_CEETM_ERR_INVALID_INPUT,
  QOS_CEETM_ERR_FAILED_TO_CREATE_PRIO_QUEUE,
  QOS_CEETM_ERR_FAILED_TO_CREATE_WBFS_QUEUE,
  QOS_CEETM_ERR_CFG_CONGGRP_FAILED,
  QOS_CEETM_ERR_NO_INTERFACE_EXISTS_WITH_GIVEN_NAME,
  QOS_CEETM_ERR_SET_GROUP_FAILED,
  QOS_CEETM_ERR_INVALID_QUEUE_CNT_PER_CHANNEL,
  QOS_CEETM_ERR_SET_GROUP_CR_ER_FAILED,
  QOS_CEETM_ERR_INVALID_DCP_ID,
  QOS_CEETM_ERR_MAX_LNIS_REACHED,
  QOS_CEETM_ERR_MAX_CHANNELS_REACHED,
  QOS_CEETM_ERR_NO_CONG_AVOID_ALG_CONFIGURED,
  QOS_CEETM_ERR_NO_THRESHOLD_FOR_TAILDROP,
  QOS_CEETM_ERR_NO_PROPER_INPUT_FOR_WRED,
  QOS_CEETM_ERR_NO_SCHEDULER_FOR_VLAN,
  QOS_CEETM_ERR_MAX_IFACE_FQ_ELEMENTS,
  QOS_CEETM_MAX_ERROR_CODE,
}cdx_qos_ceetm_error_codes_e;
