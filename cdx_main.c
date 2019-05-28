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


//uncomment to start dpa_app from cdx module
#define START_DPA_APP 1

#define DEFINE_GLOBALS
#include "cdx.h"

extern int cdx_driver_init(void);
extern int dpaa_vwd_init(void);
extern int dpaa_vwd_init(void);
extern void dpaa_vwd_exit(void);
extern int cdx_dpa_ipsec_init(void);
extern int cdx_dpa_ipsec_exit(void);
extern int devman_init_linux_stats(void);
extern int cdx_init_frag_module(void);
extern void cdx_deinit_frag_module(void);
extern int cdx_init_ip_reassembly(void);

static void __exit cdx_ctrl_exit(struct _cdx_info *cdx_info)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	if (ctrl->dma_pool_256)
	{
		dma_pool_destroy(ctrl->dma_pool_256);
		ctrl->dma_pool_256 = NULL;
	}

	if (ctrl->dma_pool_512)
	{
		dma_pool_destroy(ctrl->dma_pool_512);
		ctrl->dma_pool_512 = NULL;
	}

	cdx_ctrl_timer_exit(ctrl);
}


static int __init cdx_ctrl_init(struct _cdx_info *cdx_info)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	int rc;

	mutex_init(&ctrl->mutex);
	spin_lock_init(&ctrl->lock);

	INIT_WORK(&ctrl->work, comcerto_fpp_workqueue);

	INIT_LIST_HEAD(&ctrl->msg_list);

	ctrl->dev = &cdx_info->dev;

	rc = cdx_ctrl_timer_init(ctrl);
	if (rc)
		goto error;

#define DMA_BUF_MIN_ALIGNMENT	8
#define DMA_BUF_BOUNDARY	(4 * 1024) /* bursts can not cross 4k boundary */

	ctrl->dma_pool_256 = dma_pool_create("cdx_dma_pool_256B", ctrl->dev, 256, DMA_BUF_MIN_ALIGNMENT, DMA_BUF_BOUNDARY);
	if (!ctrl->dma_pool_256)
	{
		printk (KERN_ERR "%s: dma_pool_create() failed\n", __func__);
		rc = -ENOMEM;
		goto error;
	}

	ctrl->dma_pool_512 = dma_pool_create("cdx_dma_pool_512B", ctrl->dev, 512, DMA_BUF_MIN_ALIGNMENT, DMA_BUF_BOUNDARY);
	if (!ctrl->dma_pool_512)
	{
		printk (KERN_ERR "%s: dma_pool_create() failed\n", __func__);
		rc = -ENOMEM;
		goto error;
	}

	mutex_lock(&ctrl->mutex);

	/* Initialize interface to fci */
	rc = cdx_cmdhandler_init();

	mutex_unlock(&ctrl->mutex);

	if (rc < 0)
		goto error;

	wake_up_process(ctrl->timer_thread);

	return 0;

error:
	cdx_cmdhandler_exit();
	cdx_ctrl_exit(cdx_info);
	return rc;
}


#ifdef START_DPA_APP
static void free_modprobe_argv(struct subprocess_info *info)
{
        kfree(info->argv);
}


static int start_dpa_app(void)
{
        struct subprocess_info *info;
        static char *envp[] = {
                "HOME=/",
                "TERM=linux",
                "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
                NULL
        };
        static char *modprobe_path = "/usr/bin/dpa_app";

        char **argv = kmalloc(sizeof(char *[2]), GFP_KERNEL);
        if (!argv)
                return -ENOMEM;

        argv[0] = modprobe_path;
        argv[1] = NULL;

        info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
                                         NULL, free_modprobe_argv, NULL);
        if (info) {
                return call_usermodehelper_exec(info, (UMH_WAIT_PROC | UMH_KILLABLE));
        }
        kfree(argv);
        return -ENOMEM;
}
#endif


static int __init cdx_module_init(void)
{
	int rc = 0;

	printk(KERN_INFO "%s\n", __func__);

	cdx_info = kzalloc(sizeof(struct _cdx_info), GFP_KERNEL);
	if (!cdx_info)
	{
		printk(KERN_ERR "%s: Error allocating cdx_info structure\n", __func__);
		rc = -ENOMEM;
		goto exit;
	}

	cdx_info->dev.init_name = "cdx";
	rc = device_register(&cdx_info->dev);
   	if (rc != 0) {
                printk("%s::device_register failed\n", __FUNCTION__);
                goto exit;
        }
	rc = cdx_ctrl_init(cdx_info);
	if (rc != 0) {
		printk("%s::cdx_ctrl_init failed\n", __FUNCTION__);
                goto exit;
	}

        rc = devman_init_linux_stats();
        if (rc != 0)  {
                printk("%s::devman_init call to register for linux stats failed\n", __FUNCTION__);
                goto exit;
        }
	rc = cdx_driver_init();
	if (rc != 0)  {
		printk("%s::cdx_driver_init failed\n", __FUNCTION__);
		goto exit;
	}
	
#ifdef START_DPA_APP
        rc = start_dpa_app();
        if (rc != 0)  {
                printk("%s::start_dpa_app failed\n", __FUNCTION__);
                goto exit;
        }
        printk("%s::start_dpa_app successful\n", __FUNCTION__);
#endif

#ifdef CFG_WIFI_OFFLOAD
	rc = dpaa_vwd_init();
        if (rc != 0)  {
                printk("%s::vwd_driver_init failed\n", __FUNCTION__);
                goto exit;
        }
#endif

	// initialize global fragmentation params
	if (cdx_init_frag_module()) { 
               printk("%s::cdx_init_frag_module failed\n", __FUNCTION__);
               goto exit;
       }

#ifdef DPA_IPSEC_OFFLOAD
	if (cdx_dpa_ipsec_init()) {
               printk("%s::dpa_ipsec start failed\n", __FUNCTION__);
               goto exit;
       }
#endif
        printk("%s::calling cdx_init_ip_reassembly\n", __FUNCTION__);
	if (cdx_init_ip_reassembly()) {
               printk("%s::cdx_init_ip_reassembly failed\n", __FUNCTION__);
               goto exit;
	}

#ifdef CDX_TODO
	clk_put(clk_axi);
#endif
exit:
	return rc;
}


static void __exit cdx_module_exit(void)
{
	printk(KERN_INFO "%s\n", __func__);

#ifdef CFG_WIFI_OFFLOAD
	dpaa_vwd_exit();
#endif
#ifdef DPA_IPSEC_OFFLOAD
	cdx_dpa_ipsec_exit();
#endif
	cdx_deinit_frag_module();
	cdx_cmdhandler_exit();
	cdx_ctrl_exit(cdx_info);

	kfree(cdx_info);
}

MODULE_LICENSE("Dual BSD/GPL");
module_init(cdx_module_init);
module_exit(cdx_module_exit);
