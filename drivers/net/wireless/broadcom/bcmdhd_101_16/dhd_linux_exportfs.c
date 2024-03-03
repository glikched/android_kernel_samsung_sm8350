/*
 * Broadcom Dongle Host Driver (DHD), Linux-specific network interface
 * Basically selected code segments from usb-cdc.c and usb-rndis.c
 *
 * Copyright (C) 2022, Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id$
 */
#include <linux/kobject.h>
#include <linux/proc_fs.h>
#include <linux/sysfs.h>
#include <osl.h>
#include <dhd.h>
#include <dhd_dbg.h>
#include <dhd_linux_priv.h>
#if defined(DHD_ADPS_BAM_EXPORT) && defined(WL_BAM)
#include <wl_bam.h>
<<<<<<< HEAD
#endif	/* DHD_ADPS_BAM_EXPORT && WL_BAM */
=======
#endif /* DHD_ADPS_BAM_EXPORT && WL_BAM */
>>>>>>> lucasblacklu/wip
#ifdef WL_CFG80211
#include <wl_cfg80211.h>
#endif /* WL_CFG80211 */

#ifdef SHOW_LOGTRACE
<<<<<<< HEAD
extern dhd_pub_t* g_dhd_pub;
static int dhd_ring_proc_open(struct inode *inode, struct file *file);
ssize_t dhd_ring_proc_read(struct file *file, char *buffer, size_t tt, loff_t *loff);
=======
extern dhd_pub_t *g_dhd_pub;
static int dhd_ring_proc_open(struct inode *inode, struct file *file);
ssize_t dhd_ring_proc_read(struct file *file, char *buffer, size_t tt,
			   loff_t *loff);
>>>>>>> lucasblacklu/wip

static const struct file_operations dhd_ring_proc_fops = {
	.open = dhd_ring_proc_open,
	.read = dhd_ring_proc_read,
	.release = single_release,
};

<<<<<<< HEAD
static int
dhd_ring_proc_open(struct inode *inode, struct file *file)
=======
static int dhd_ring_proc_open(struct inode *inode, struct file *file)
>>>>>>> lucasblacklu/wip
{
	int ret = BCME_ERROR;
	if (inode) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
		ret = single_open(file, 0, PDE_DATA(inode));
#else
		/* This feature is not supported for lower kernel versions */
		ret = single_open(file, 0, NULL);
#endif
	} else {
		DHD_ERROR(("%s: inode is NULL\n", __FUNCTION__));
	}
	return ret;
}

<<<<<<< HEAD
ssize_t
dhd_ring_proc_read(struct file *file, char __user *buffer, size_t tt, loff_t *loff)
{
	trace_buf_info_t *trace_buf_info;
	int ret = BCME_ERROR;
	dhd_dbg_ring_t *ring = (dhd_dbg_ring_t *)((struct seq_file *)(file->private_data))->private;
=======
ssize_t dhd_ring_proc_read(struct file *file, char __user *buffer, size_t tt,
			   loff_t *loff)
{
	trace_buf_info_t *trace_buf_info;
	int ret = BCME_ERROR;
	dhd_dbg_ring_t *ring =
		(dhd_dbg_ring_t *)((struct seq_file *)(file->private_data))
			->private;
>>>>>>> lucasblacklu/wip

	if (ring == NULL) {
		DHD_ERROR(("%s: ring is NULL\n", __FUNCTION__));
		return ret;
	}

	ASSERT(g_dhd_pub);

<<<<<<< HEAD
	trace_buf_info = (trace_buf_info_t *)MALLOCZ(g_dhd_pub->osh, sizeof(trace_buf_info_t));
	if (trace_buf_info) {
		dhd_dbg_read_ring_into_trace_buf(ring, trace_buf_info);
		if (copy_to_user(buffer, (void*)trace_buf_info->buf, MIN(trace_buf_info->size, tt)))
		{
=======
	trace_buf_info = (trace_buf_info_t *)MALLOCZ(g_dhd_pub->osh,
						     sizeof(trace_buf_info_t));
	if (trace_buf_info) {
		dhd_dbg_read_ring_into_trace_buf(ring, trace_buf_info);
		if (copy_to_user(buffer, (void *)trace_buf_info->buf,
				 MIN(trace_buf_info->size, tt))) {
>>>>>>> lucasblacklu/wip
			ret = -EFAULT;
			goto exit;
		}
		if (trace_buf_info->availability == BUF_NOT_AVAILABLE)
			ret = BUF_NOT_AVAILABLE;
		else
			ret = trace_buf_info->size;
	} else
		DHD_ERROR(("Memory allocation Failed\n"));

exit:
	if (trace_buf_info) {
		MFREE(g_dhd_pub->osh, trace_buf_info, sizeof(trace_buf_info_t));
	}
	return ret;
}

<<<<<<< HEAD
void
dhd_dbg_ring_proc_create(dhd_pub_t *dhdp)
=======
void dhd_dbg_ring_proc_create(dhd_pub_t *dhdp)
>>>>>>> lucasblacklu/wip
{
#ifdef DEBUGABILITY
	dhd_dbg_ring_t *dbg_verbose_ring = NULL;

<<<<<<< HEAD
	dbg_verbose_ring = dhd_dbg_get_ring_from_ring_id(dhdp, FW_VERBOSE_RING_ID);
	if (dbg_verbose_ring) {
		if (!proc_create_data("dhd_trace", S_IRUSR, NULL, &dhd_ring_proc_fops,
			dbg_verbose_ring)) {
			DHD_ERROR(("Failed to create /proc/dhd_trace procfs interface\n"));
		} else {
			DHD_ERROR(("Created /proc/dhd_trace procfs interface\n"));
		}
	} else {
		DHD_ERROR(("dbg_verbose_ring is NULL, /proc/dhd_trace not created\n"));
=======
	dbg_verbose_ring =
		dhd_dbg_get_ring_from_ring_id(dhdp, FW_VERBOSE_RING_ID);
	if (dbg_verbose_ring) {
		if (!proc_create_data("dhd_trace", S_IRUSR, NULL,
				      &dhd_ring_proc_fops, dbg_verbose_ring)) {
			DHD_ERROR((
				"Failed to create /proc/dhd_trace procfs interface\n"));
		} else {
			DHD_ERROR(
				("Created /proc/dhd_trace procfs interface\n"));
		}
	} else {
		DHD_ERROR((
			"dbg_verbose_ring is NULL, /proc/dhd_trace not created\n"));
>>>>>>> lucasblacklu/wip
	}
#endif /* DEBUGABILITY */

#ifdef EWP_ECNTRS_LOGGING
<<<<<<< HEAD
	if (!proc_create_data("dhd_ecounters", S_IRUSR, NULL, &dhd_ring_proc_fops,
		dhdp->ecntr_dbg_ring)) {
		DHD_ERROR(("Failed to create /proc/dhd_ecounters procfs interface\n"));
=======
	if (!proc_create_data("dhd_ecounters", S_IRUSR, NULL,
			      &dhd_ring_proc_fops, dhdp->ecntr_dbg_ring)) {
		DHD_ERROR((
			"Failed to create /proc/dhd_ecounters procfs interface\n"));
>>>>>>> lucasblacklu/wip
	} else {
		DHD_ERROR(("Created /proc/dhd_ecounters procfs interface\n"));
	}
#endif /* EWP_ECNTRS_LOGGING */

#ifdef EWP_RTT_LOGGING
	if (!proc_create_data("dhd_rtt", S_IRUSR, NULL, &dhd_ring_proc_fops,
<<<<<<< HEAD
		dhdp->rtt_dbg_ring)) {
		DHD_ERROR(("Failed to create /proc/dhd_rtt procfs interface\n"));
=======
			      dhdp->rtt_dbg_ring)) {
		DHD_ERROR(
			("Failed to create /proc/dhd_rtt procfs interface\n"));
>>>>>>> lucasblacklu/wip
	} else {
		DHD_ERROR(("Created /proc/dhd_rtt procfs interface\n"));
	}
#endif /* EWP_RTT_LOGGING */
}

<<<<<<< HEAD
void
dhd_dbg_ring_proc_destroy(dhd_pub_t *dhdp)
=======
void dhd_dbg_ring_proc_destroy(dhd_pub_t *dhdp)
>>>>>>> lucasblacklu/wip
{
#ifdef DEBUGABILITY
	remove_proc_entry("dhd_trace", NULL);
#endif /* DEBUGABILITY */

#ifdef EWP_ECNTRS_LOGGING
	remove_proc_entry("dhd_ecounters", NULL);
#endif /* EWP_ECNTRS_LOGGING */

#ifdef EWP_RTT_LOGGING
	remove_proc_entry("dhd_rtt", NULL);
#endif /* EWP_RTT_LOGGING */
<<<<<<< HEAD

=======
>>>>>>> lucasblacklu/wip
}
#endif /* SHOW_LOGTRACE */

/* ----------------------------------------------------------------------------
 * Infrastructure code for sysfs interface support for DHD
 *
 * What is sysfs interface?
 * https://www.kernel.org/doc/Documentation/filesystems/sysfs.txt
 *
 * Why sysfs interface?
 * This is the Linux standard way of changing/configuring Run Time parameters
 * for a driver. We can use this interface to control "linux" specific driver
 * parameters.
 *
 * -----------------------------------------------------------------------------
 */

#if defined(DHD_TRACE_WAKE_LOCK)
extern atomic_t trace_wklock_onoff;

/* Function to show the history buffer */
<<<<<<< HEAD
static ssize_t
show_wklock_trace(struct dhd_info *dev, char *buf)
=======
static ssize_t show_wklock_trace(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	dhd_info_t *dhd = (dhd_info_t *)dev;

	buf[ret] = '\n';
<<<<<<< HEAD
	buf[ret+1] = 0;

	dhd_wk_lock_stats_dump(&dhd->pub);
	return ret+1;
}

/* Function to enable/disable wakelock trace */
static ssize_t
wklock_trace_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
	buf[ret + 1] = 0;

	dhd_wk_lock_stats_dump(&dhd->pub);
	return ret + 1;
}

/* Function to enable/disable wakelock trace */
static ssize_t wklock_trace_onoff(struct dhd_info *dev, const char *buf,
				  size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;
	BCM_REFERENCE(dhd);

	onoff = bcm_strtoul(buf, NULL, 10);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}

	atomic_set(&trace_wklock_onoff, onoff);
	if (atomic_read(&trace_wklock_onoff)) {
		printk("ENABLE WAKLOCK TRACE\n");
	} else {
		printk("DISABLE WAKELOCK TRACE\n");
	}

<<<<<<< HEAD
	return (ssize_t)(onoff+1);
=======
	return (ssize_t)(onoff + 1);
>>>>>>> lucasblacklu/wip
}
#endif /* DHD_TRACE_WAKE_LOCK */

#ifdef DHD_LOG_DUMP
extern int logdump_periodic_flush;
extern int logdump_ecntr_enable;
<<<<<<< HEAD
static ssize_t
show_logdump_periodic_flush(struct dhd_info *dev, char *buf)
=======
static ssize_t show_logdump_periodic_flush(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long val;

	val = logdump_periodic_flush;
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", val);
	return ret;
}

<<<<<<< HEAD
static ssize_t
logdump_periodic_flush_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t logdump_periodic_flush_onoff(struct dhd_info *dev,
					    const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long val;

	val = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &val);
	if (val != 0 && val != 1) {
<<<<<<< HEAD
		 return -EINVAL;
=======
		return -EINVAL;
>>>>>>> lucasblacklu/wip
	}
	logdump_periodic_flush = val;
	return count;
}

<<<<<<< HEAD
static ssize_t
show_logdump_ecntr(struct dhd_info *dev, char *buf)
=======
static ssize_t show_logdump_ecntr(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long val;

	val = logdump_ecntr_enable;
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", val);
	return ret;
}

<<<<<<< HEAD
static ssize_t
logdump_ecntr_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t logdump_ecntr_onoff(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long val;

	val = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &val);
	if (val != 0 && val != 1) {
<<<<<<< HEAD
		 return -EINVAL;
=======
		return -EINVAL;
>>>>>>> lucasblacklu/wip
	}
	logdump_ecntr_enable = val;
	return count;
}

#endif /* DHD_LOG_DUMP */

extern uint enable_ecounter;
<<<<<<< HEAD
static ssize_t
show_enable_ecounter(struct dhd_info *dev, char *buf)
=======
static ssize_t show_enable_ecounter(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long onoff;

	onoff = enable_ecounter;
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n",
		onoff);
	return ret;
}

static ssize_t
ecounter_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", onoff);
	return ret;
}

static ssize_t ecounter_onoff(struct dhd_info *dev, const char *buf,
			      size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;
	dhd_pub_t *dhdp;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return count;
	}
	dhdp = &dhd->pub;
	if (!FW_SUPPORTED(dhdp, ecounters)) {
<<<<<<< HEAD
		DHD_ERROR(("%s: ecounters not supported by FW\n", __FUNCTION__));
=======
		DHD_ERROR(
			("%s: ecounters not supported by FW\n", __FUNCTION__));
>>>>>>> lucasblacklu/wip
		return count;
	}

	onoff = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &onoff);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}

	if (enable_ecounter == onoff) {
<<<<<<< HEAD
		DHD_ERROR(("%s: ecounters already %d\n", __FUNCTION__, enable_ecounter));
=======
		DHD_ERROR(("%s: ecounters already %d\n", __FUNCTION__,
			   enable_ecounter));
>>>>>>> lucasblacklu/wip
		return count;
	}

	enable_ecounter = onoff;
	dhd_ecounter_configure(dhdp, enable_ecounter);

	return count;
}

#ifdef DHD_SSSR_DUMP
<<<<<<< HEAD
static ssize_t
show_sssr_enab(struct dhd_info *dev, char *buf)
=======
static ssize_t show_sssr_enab(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long onoff;

	onoff = sssr_enab;
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n",
		onoff);
	return ret;
}

static ssize_t
set_sssr_enab(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", onoff);
	return ret;
}

static ssize_t set_sssr_enab(struct dhd_info *dev, const char *buf,
			     size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;

	onoff = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &onoff);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}

	sssr_enab = (uint)onoff;

	return count;
}

<<<<<<< HEAD
static ssize_t
show_fis_enab(struct dhd_info *dev, char *buf)
=======
static ssize_t show_fis_enab(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long onoff;

	onoff = fis_enab;
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n",
		onoff);
	return ret;
}

static ssize_t
set_fis_enab(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", onoff);
	return ret;
}

static ssize_t set_fis_enab(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;

	onoff = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &onoff);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}

	fis_enab = (uint)onoff;

	return count;
}
#endif /* DHD_SSSR_DUMP */

<<<<<<< HEAD
#define FMT_BUFSZ	32
extern char firmware_path[];

static ssize_t
show_firmware_path(struct dhd_info *dev, char *buf)
=======
#define FMT_BUFSZ 32
extern char firmware_path[];

static ssize_t show_firmware_path(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n", firmware_path);

	return ret;
}

<<<<<<< HEAD
static ssize_t
store_firmware_path(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t store_firmware_path(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	char fmt_spec[FMT_BUFSZ] = "";

	if ((int)strlen(buf) >= MOD_PARAM_PATHLEN) {
		return -EINVAL;
	}

	snprintf(fmt_spec, FMT_BUFSZ, "%%%ds", MOD_PARAM_PATHLEN - 1);
	sscanf(buf, fmt_spec, firmware_path);

	return count;
}

extern char nvram_path[];

<<<<<<< HEAD
static ssize_t
show_nvram_path(struct dhd_info *dev, char *buf)
=======
static ssize_t show_nvram_path(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n", nvram_path);

	return ret;
}

<<<<<<< HEAD
static ssize_t
store_nvram_path(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t store_nvram_path(struct dhd_info *dev, const char *buf,
				size_t count)
>>>>>>> lucasblacklu/wip
{
	char fmt_spec[FMT_BUFSZ] = "";

	if ((int)strlen(buf) >= MOD_PARAM_PATHLEN) {
		return -EINVAL;
	}

	snprintf(fmt_spec, FMT_BUFSZ, "%%%ds", MOD_PARAM_PATHLEN - 1);
	sscanf(buf, fmt_spec, nvram_path);

	return count;
}

/*
 * Generic Attribute Structure for DHD.
 * If we have to add a new sysfs entry under /sys/bcm-dhd/, we have
 * to instantiate an object of type dhd_attr,  populate it with
 * the required show/store functions (ex:- dhd_attr_cpumask_primary)
 * and add the object to default_attrs[] array, that gets registered
 * to the kobject of dhd (named bcm-dhd).
 */

struct dhd_attr {
	struct attribute attr;
<<<<<<< HEAD
	ssize_t(*show)(struct dhd_info *, char *);
	ssize_t(*store)(struct dhd_info *, const char *, size_t count);
=======
	ssize_t (*show)(struct dhd_info *, char *);
	ssize_t (*store)(struct dhd_info *, const char *, size_t count);
>>>>>>> lucasblacklu/wip
};

#if defined(DHD_TRACE_WAKE_LOCK)
static struct dhd_attr dhd_attr_wklock =
	__ATTR(wklock_trace, 0660, show_wklock_trace, wklock_trace_onoff);
#endif /* defined(DHD_TRACE_WAKE_LOCK */

#ifdef DHD_LOG_DUMP
static struct dhd_attr dhd_attr_logdump_periodic_flush =
<<<<<<< HEAD
     __ATTR(logdump_periodic_flush, 0660, show_logdump_periodic_flush,
		logdump_periodic_flush_onoff);
static struct dhd_attr dhd_attr_logdump_ecntr =
	__ATTR(logdump_ecntr_enable, 0660, show_logdump_ecntr,
		logdump_ecntr_onoff);
=======
	__ATTR(logdump_periodic_flush, 0660, show_logdump_periodic_flush,
	       logdump_periodic_flush_onoff);
static struct dhd_attr dhd_attr_logdump_ecntr = __ATTR(
	logdump_ecntr_enable, 0660, show_logdump_ecntr, logdump_ecntr_onoff);
>>>>>>> lucasblacklu/wip
#endif /* DHD_LOG_DUMP */

static struct dhd_attr dhd_attr_ecounters =
	__ATTR(ecounters, 0660, show_enable_ecounter, ecounter_onoff);

#ifdef DHD_SSSR_DUMP
static struct dhd_attr dhd_attr_sssr_enab =
	__ATTR(sssr_enab, 0660, show_sssr_enab, set_sssr_enab);
static struct dhd_attr dhd_attr_fis_enab =
	__ATTR(fis_enab, 0660, show_fis_enab, set_fis_enab);
#endif /* DHD_SSSR_DUMP */

static struct dhd_attr dhd_attr_firmware_path =
	__ATTR(firmware_path, 0660, show_firmware_path, store_firmware_path);

static struct dhd_attr dhd_attr_nvram_path =
	__ATTR(nvram_path, 0660, show_nvram_path, store_nvram_path);

#define to_dhd(k) container_of(k, struct dhd_info, dhd_kobj)
#define to_attr(a) container_of(a, struct dhd_attr, attr)

#ifdef DHD_MAC_ADDR_EXPORT
struct ether_addr sysfs_mac_addr;
<<<<<<< HEAD
static ssize_t
show_mac_addr(struct dhd_info *dev, char *buf)
=======
static ssize_t show_mac_addr(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, MACF,
<<<<<<< HEAD
		(uint32)sysfs_mac_addr.octet[0], (uint32)sysfs_mac_addr.octet[1],
		(uint32)sysfs_mac_addr.octet[2], (uint32)sysfs_mac_addr.octet[3],
		(uint32)sysfs_mac_addr.octet[4], (uint32)sysfs_mac_addr.octet[5]);
=======
			(uint32)sysfs_mac_addr.octet[0],
			(uint32)sysfs_mac_addr.octet[1],
			(uint32)sysfs_mac_addr.octet[2],
			(uint32)sysfs_mac_addr.octet[3],
			(uint32)sysfs_mac_addr.octet[4],
			(uint32)sysfs_mac_addr.octet[5]);
>>>>>>> lucasblacklu/wip

	return ret;
}

<<<<<<< HEAD
static ssize_t
set_mac_addr(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_mac_addr(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	if (!bcm_ether_atoe(buf, &sysfs_mac_addr)) {
		DHD_ERROR(("Invalid Mac Address \n"));
		return -EINVAL;
	}

<<<<<<< HEAD
	DHD_ERROR(("Mac Address set with "MACDBG"\n", MAC2STRDBG(&sysfs_mac_addr)));
=======
	DHD_ERROR(("Mac Address set with " MACDBG "\n",
		   MAC2STRDBG(&sysfs_mac_addr)));
>>>>>>> lucasblacklu/wip

	return count;
}

static struct dhd_attr dhd_attr_macaddr =
	__ATTR(mac_addr, 0660, show_mac_addr, set_mac_addr);
#endif /* DHD_MAC_ADDR_EXPORT */

#ifdef DHD_FW_COREDUMP
/*
 * XXX The filename to store memdump is defined for each platform.
 * - The default path of CUSTOMER_HW4 device is "PLATFORM_PATH/.memdump.info"
 * - Brix platform will take default path "/installmedia/.memdump.info"
 * New platforms can add their ifdefs accordingly below.
 */

#ifdef CUSTOMER_HW4_DEBUG
<<<<<<< HEAD
#define MEMDUMPINFO PLATFORM_PATH".memdump.info"
#elif defined(BOARD_HIKEY)
#define MEMDUMPINFO PLATFORM_PATH".memdump.info"
=======
#define MEMDUMPINFO PLATFORM_PATH ".memdump.info"
#elif defined(BOARD_HIKEY)
#define MEMDUMPINFO PLATFORM_PATH ".memdump.info"
>>>>>>> lucasblacklu/wip
#elif defined(__ARM_ARCH_7A__)
#define MEMDUMPINFO "/data/misc/wifi/.memdump.info"
#else
#define MEMDUMPINFO_LIVE "/installmedia/.memdump.info"
#define MEMDUMPINFO_INST "/data/.memdump.info"
#define MEMDUMPINFO MEMDUMPINFO_LIVE
#endif /* CUSTOMER_HW4_DEBUG */

<<<<<<< HEAD
uint32
get_mem_val_from_file(void)
=======
uint32 get_mem_val_from_file(void)
>>>>>>> lucasblacklu/wip
{
	struct file *fp = NULL;
	uint32 mem_val = DUMP_MEMFILE_MAX;
	char *p_mem_val = NULL;
	char *filepath = MEMDUMPINFO;
	int ret = 0;

	/* Read memdump info from the file */
	fp = dhd_filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(fp) || (fp == NULL)) {
<<<<<<< HEAD
		DHD_ERROR(("%s: File [%s] doesn't exist\n", __FUNCTION__, filepath));
=======
		DHD_ERROR(("%s: File [%s] doesn't exist\n", __FUNCTION__,
			   filepath));
>>>>>>> lucasblacklu/wip
#if defined(CONFIG_X86)
		/* Check if it is Live Brix Image */
		if (strcmp(filepath, MEMDUMPINFO_LIVE) != 0) {
			goto done;
		}
		/* Try if it is Installed Brix Image */
		filepath = MEMDUMPINFO_INST;
		DHD_ERROR(("%s: Try File [%s]\n", __FUNCTION__, filepath));
		fp = dhd_filp_open(filepath, O_RDONLY, 0);
		if (IS_ERR(fp) || (fp == NULL)) {
<<<<<<< HEAD
			DHD_ERROR(("%s: File [%s] doesn't exist\n", __FUNCTION__, filepath));
=======
			DHD_ERROR(("%s: File [%s] doesn't exist\n",
				   __FUNCTION__, filepath));
>>>>>>> lucasblacklu/wip
			goto done;
		}
#else /* Non Brix Android platform */
		goto done;
#endif /* CONFIG_X86 && OEM_ANDROID */
	}

	/* Handle success case */
	ret = dhd_kernel_read_compat(fp, 0, (char *)&mem_val, sizeof(uint32));
	if (ret < 0) {
		DHD_ERROR(("%s: File read error, ret=%d\n", __FUNCTION__, ret));
		dhd_filp_close(fp, NULL);
		goto done;
	}

<<<<<<< HEAD
	p_mem_val = (char*)&mem_val;
=======
	p_mem_val = (char *)&mem_val;
>>>>>>> lucasblacklu/wip
	p_mem_val[sizeof(uint32) - 1] = '\0';
	mem_val = bcm_atoi(p_mem_val);

	dhd_filp_close(fp, NULL);

done:
	return mem_val;
}

void dhd_get_memdump_info(dhd_pub_t *dhd)
{
#ifndef DHD_EXPORT_CNTL_FILE
	uint32 mem_val = DUMP_MEMFILE_MAX;

	mem_val = get_mem_val_from_file();
	if (mem_val != DUMP_MEMFILE_MAX)
		dhd->memdump_enabled = mem_val;
#ifdef DHD_INIT_DEFAULT_MEMDUMP
	if (mem_val == 0 || mem_val == DUMP_MEMFILE_MAX)
		mem_val = DUMP_MEMFILE_BUGON;
#endif /* DHD_INIT_DEFAULT_MEMDUMP */
#else
#ifdef DHD_INIT_DEFAULT_MEMDUMP
<<<<<<< HEAD
	if (dhd->memdump_enabled == 0 || dhd->memdump_enabled == DUMP_MEMFILE_MAX)
=======
	if (dhd->memdump_enabled == 0 ||
	    dhd->memdump_enabled == DUMP_MEMFILE_MAX)
>>>>>>> lucasblacklu/wip
		dhd->memdump_enabled = DUMP_MEMFILE;
#endif /* DHD_INIT_DEFAULT_MEMDUMP */
#endif /* !DHD_EXPORT_CNTL_FILE */
#ifdef DHD_DETECT_CONSECUTIVE_MFG_HANG
	/* override memdump_enabled value to avoid once trap issues */
	if (dhd_bus_get_fw_mode(dhd) == DHD_FLAG_MFG_MODE &&
<<<<<<< HEAD
			(dhd->memdump_enabled == DUMP_MEMONLY ||
			dhd->memdump_enabled == DUMP_MEMFILE_BUGON)) {
		dhd->memdump_enabled = DUMP_MEMFILE;
		DHD_ERROR(("%s : Override memdump_value to %d\n",
				__FUNCTION__, dhd->memdump_enabled));
	}
#endif /* DHD_DETECT_CONSECUTIVE_MFG_HANG */
	DHD_ERROR(("%s: MEMDUMP ENABLED = %u\n", __FUNCTION__, dhd->memdump_enabled));
}

#ifdef DHD_EXPORT_CNTL_FILE
static ssize_t
show_memdump_info(struct dhd_info *dev, char *buf)
=======
	    (dhd->memdump_enabled == DUMP_MEMONLY ||
	     dhd->memdump_enabled == DUMP_MEMFILE_BUGON)) {
		dhd->memdump_enabled = DUMP_MEMFILE;
		DHD_ERROR(("%s : Override memdump_value to %d\n", __FUNCTION__,
			   dhd->memdump_enabled));
	}
#endif /* DHD_DETECT_CONSECUTIVE_MFG_HANG */
	DHD_ERROR(("%s: MEMDUMP ENABLED = %u\n", __FUNCTION__,
		   dhd->memdump_enabled));
}

#ifdef DHD_EXPORT_CNTL_FILE
static ssize_t show_memdump_info(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	dhd_pub_t *dhdp;

	if (!dev) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return ret;
	}

	dhdp = &dev->pub;
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", dhdp->memdump_enabled);
	return ret;
}

static ssize_t
set_memdump_info(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", dhdp->memdump_enabled);
	return ret;
}

static ssize_t set_memdump_info(struct dhd_info *dev, const char *buf,
				size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long memval;
	dhd_pub_t *dhdp;

	if (!dev) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return count;
	}
	dhdp = &dev->pub;

	memval = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%lu", &memval);

	dhdp->memdump_enabled = (uint32)memval;

<<<<<<< HEAD
	DHD_ERROR(("%s: MEMDUMP ENABLED = %u\n", __FUNCTION__, dhdp->memdump_enabled));
=======
	DHD_ERROR(("%s: MEMDUMP ENABLED = %u\n", __FUNCTION__,
		   dhdp->memdump_enabled));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_memdump =
	__ATTR(memdump, 0660, show_memdump_info, set_memdump_info);
#endif /* DHD_EXPORT_CNTL_FILE */
#endif /* DHD_FW_COREDUMP */

#ifdef BCMASSERT_LOG
/*
 * XXX The filename to store assert type is defined for each platform.
 * New platforms can add their ifdefs accordingly below.
 */
#ifdef CUSTOMER_HW4_DEBUG
<<<<<<< HEAD
#define ASSERTINFO PLATFORM_PATH".assert.info"
=======
#define ASSERTINFO PLATFORM_PATH ".assert.info"
>>>>>>> lucasblacklu/wip
#elif defined(BOARD_HIKEY)
#define ASSERTINFO "/data/misc/wifi/.assert.info"
#else
#define ASSERTINFO "/installmedia/.assert.info"
#endif /* CUSTOMER_HW4_DEBUG */
<<<<<<< HEAD
int
get_assert_val_from_file(void)
=======
int get_assert_val_from_file(void)
>>>>>>> lucasblacklu/wip
{
	struct file *fp = NULL;
	char *filepath = ASSERTINFO;
	char *p_mem_val = NULL;
	int mem_val = -1;

	/*
	 * Read assert info from the file
	 * 0: Trigger Kernel crash by panic()
	 * 1: Print out the logs and don't trigger Kernel panic. (default)
	 * 2: Trigger Kernel crash by BUG()
	 * File doesn't exist: Keep default value (1).
	 */
	fp = dhd_filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(fp) || (fp == NULL)) {
<<<<<<< HEAD
		DHD_ERROR(("%s: File [%s] doesn't exist\n", __FUNCTION__, filepath));
	} else {
		int ret = dhd_kernel_read_compat(fp, 0, (char *)&mem_val, sizeof(uint32));
		if (ret < 0) {
			DHD_ERROR(("%s: File read error, ret=%d\n", __FUNCTION__, ret));
=======
		DHD_ERROR(("%s: File [%s] doesn't exist\n", __FUNCTION__,
			   filepath));
	} else {
		int ret = dhd_kernel_read_compat(fp, 0, (char *)&mem_val,
						 sizeof(uint32));
		if (ret < 0) {
			DHD_ERROR(("%s: File read error, ret=%d\n",
				   __FUNCTION__, ret));
>>>>>>> lucasblacklu/wip
		} else {
			p_mem_val = (char *)&mem_val;
			p_mem_val[sizeof(uint32) - 1] = '\0';
			mem_val = bcm_atoi(p_mem_val);
<<<<<<< HEAD
			DHD_ERROR(("%s: ASSERT ENABLED = %d\n", __FUNCTION__, mem_val));
=======
			DHD_ERROR(("%s: ASSERT ENABLED = %d\n", __FUNCTION__,
				   mem_val));
>>>>>>> lucasblacklu/wip
		}
		dhd_filp_close(fp, NULL);
	}

#ifdef CUSTOMER_HW4_DEBUG
	mem_val = (mem_val >= 0) ? mem_val : 1;
#else
	mem_val = (mem_val >= 0) ? mem_val : 0;
#endif /* CUSTOMER_HW4_DEBUG */
	return mem_val;
}

void dhd_get_assert_info(dhd_pub_t *dhd)
{
#ifndef DHD_EXPORT_CNTL_FILE
	int mem_val = -1;

	mem_val = get_assert_val_from_file();

	g_assert_type = mem_val;
#endif /* !DHD_EXPORT_CNTL_FILE */
}

#ifdef DHD_EXPORT_CNTL_FILE
<<<<<<< HEAD
static ssize_t
show_assert_info(struct dhd_info *dev, char *buf)
=======
static ssize_t show_assert_info(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (!dev) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return ret;
	}

<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE -1, "%d\n", g_assert_type);
	return ret;

}

static ssize_t
set_assert_info(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", g_assert_type);
	return ret;
}

static ssize_t set_assert_info(struct dhd_info *dev, const char *buf,
			       size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long assert_val;

	assert_val = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%lu", &assert_val);

	g_assert_type = (uint32)assert_val;

	DHD_ERROR(("%s: ASSERT ENABLED = %lu\n", __FUNCTION__, assert_val));
	return count;
<<<<<<< HEAD

=======
>>>>>>> lucasblacklu/wip
}

static struct dhd_attr dhd_attr_assert =
	__ATTR(assert, 0660, show_assert_info, set_assert_info);
#endif /* DHD_EXPORT_CNTL_FILE */
#endif /* BCMASSERT_LOG */

#ifdef DHD_EXPORT_CNTL_FILE
#if defined(WRITE_WLANINFO)
<<<<<<< HEAD
static ssize_t
show_wifiver_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE -1, "%s", version_info);
	return ret;
}

static ssize_t
set_wifiver_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t show_wifiver_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%s", version_info);
	return ret;
}

static ssize_t set_wifiver_info(struct dhd_info *dev, const char *buf,
				size_t count)
>>>>>>> lucasblacklu/wip
{
	DHD_ERROR(("Do not set version info\n"));
	return -EINVAL;
}

static struct dhd_attr dhd_attr_wifiver =
	__ATTR(wifiver, 0660, show_wifiver_info, set_wifiver_info);
#endif /* WRITE_WLANINFO */

#if defined(USE_CID_CHECK) || defined(USE_DIRECT_VID_TAG)
char cidinfostr[MAX_VNAME_LEN];

<<<<<<< HEAD
static ssize_t
show_cid_info(struct dhd_info *dev, char *buf)
=======
static ssize_t show_cid_info(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

#ifdef USE_DIRECT_VID_TAG
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE -1, "%x%x", cidinfostr[VENDOR_OFF], cidinfostr[MD_REV_OFF]);
#endif /* USE_DIRECT_VID_TAG */
#ifdef USE_CID_CHECK
	ret = scnprintf(buf, PAGE_SIZE -1, "%s", cidinfostr);
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%x%x", cidinfostr[VENDOR_OFF],
			cidinfostr[MD_REV_OFF]);
#endif /* USE_DIRECT_VID_TAG */
#ifdef USE_CID_CHECK
	ret = scnprintf(buf, PAGE_SIZE - 1, "%s", cidinfostr);
>>>>>>> lucasblacklu/wip
#endif /* USE_CID_CHECK */
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_cid_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_cid_info(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
#ifdef USE_DIRECT_VID_TAG
	uint32 stored_vid = 0, md_rev = 0, vendor = 0;
	uint32 vendor_mask = 0x00FF;

	stored_vid = bcm_strtoul(buf, NULL, 16);

	DHD_ERROR(("%s : stored_vid : 0x%x\n", __FUNCTION__, stored_vid));
	md_rev = stored_vid & vendor_mask;
	vendor = stored_vid >> 8;

	memset(cidinfostr, 0, sizeof(cidinfostr));

	cidinfostr[MD_REV_OFF] = (char)md_rev;
	cidinfostr[VENDOR_OFF] = (char)vendor;
<<<<<<< HEAD
	DHD_INFO(("CID string %x%x\n", cidinfostr[VENDOR_OFF], cidinfostr[MD_REV_OFF]));
=======
	DHD_INFO(("CID string %x%x\n", cidinfostr[VENDOR_OFF],
		  cidinfostr[MD_REV_OFF]));
>>>>>>> lucasblacklu/wip
#endif /* USE_DIRECT_VID_TAG */
#ifdef USE_CID_CHECK
	int len = strlen(buf) + 1;
	int maxstrsz;
	maxstrsz = MAX_VNAME_LEN;

	scnprintf(cidinfostr, ((len > maxstrsz) ? maxstrsz : len), "%s", buf);
	DHD_INFO(("%s : CID info string\n", cidinfostr));
#endif /* USE_CID_CHECK */
	return count;
}

static struct dhd_attr dhd_attr_cidinfo =
	__ATTR(cid, 0660, show_cid_info, set_cid_info);
#endif /* USE_CID_CHECK || USE_DIRECT_VID_TAG */

#if defined(GEN_SOFTAP_INFO_FILE)
char softapinfostr[SOFTAP_INFO_BUF_SZ];
<<<<<<< HEAD
static ssize_t
show_softap_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE -1, "%s", softapinfostr);
	return ret;
}

static ssize_t
set_softap_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t show_softap_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%s", softapinfostr);
	return ret;
}

static ssize_t set_softap_info(struct dhd_info *dev, const char *buf,
			       size_t count)
>>>>>>> lucasblacklu/wip
{
	DHD_ERROR(("Do not set sofap related info\n"));
	return -EINVAL;
}

static struct dhd_attr dhd_attr_softapinfo =
	__ATTR(softap, 0660, show_softap_info, set_softap_info);
#endif /* GEN_SOFTAP_INFO_FILE */

#if defined(MIMO_ANT_SETTING)
unsigned long antsel;

<<<<<<< HEAD
static ssize_t
show_ant_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE -1, "%lu\n", antsel);
	return ret;
}

static ssize_t
set_ant_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t show_ant_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu\n", antsel);
	return ret;
}

static ssize_t set_ant_info(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long ant_val;

	ant_val = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%lu", &ant_val);

	/*
	 * Check value
	 * 0 - Not set, handle same as file not exist
	 */
	if (ant_val > 3) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %lu \n",
<<<<<<< HEAD
			__FUNCTION__, ant_val));
=======
			   __FUNCTION__, ant_val));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	antsel = ant_val;
<<<<<<< HEAD
	DHD_ERROR(("[WIFI_SEC] %s: Set Antinfo val = %lu \n", __FUNCTION__, antsel));
=======
	DHD_ERROR(("[WIFI_SEC] %s: Set Antinfo val = %lu \n", __FUNCTION__,
		   antsel));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_antinfo =
	__ATTR(ant, 0660, show_ant_info, set_ant_info);
#endif /* MIMO_ANT_SETTING */

#ifdef DHD_PM_CONTROL_FROM_FILE
extern uint32 pmmode_val;
<<<<<<< HEAD
static ssize_t
show_pm_info(struct dhd_info *dev, char *buf)
=======
static ssize_t show_pm_info(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (pmmode_val == 0xFF) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE -1, "PM mode is not set\n");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", pmmode_val);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "PM mode is not set\n");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", pmmode_val);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_pm_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_pm_info(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long pm_val;

	pm_val = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%lu", &pm_val);

	if (pm_val > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %lu \n",
<<<<<<< HEAD
			__FUNCTION__, pm_val));
=======
			   __FUNCTION__, pm_val));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	pmmode_val = (uint32)pm_val;
<<<<<<< HEAD
	DHD_ERROR(("[WIFI_SEC] %s: Set pminfo val = %u\n", __FUNCTION__, pmmode_val));
=======
	DHD_ERROR(("[WIFI_SEC] %s: Set pminfo val = %u\n", __FUNCTION__,
		   pmmode_val));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_pminfo =
	__ATTR(pm, 0660, show_pm_info, set_pm_info);
#endif /* DHD_PM_CONTROL_FROM_FILE */

#ifdef LOGTRACE_FROM_FILE
unsigned long logtrace_val = 1;

<<<<<<< HEAD
static ssize_t
show_logtrace_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE -1, "%lu\n", logtrace_val);
	return ret;
}

static ssize_t
set_logtrace_info(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t show_logtrace_info(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu\n", logtrace_val);
	return ret;
}

static ssize_t set_logtrace_info(struct dhd_info *dev, const char *buf,
				 size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;

	onoff = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%lu", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %lu \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	logtrace_val = onoff;
	DHD_ERROR(("[WIFI_SEC] %s: LOGTRACE On/Off from sysfs = %lu\n",
<<<<<<< HEAD
		__FUNCTION__, logtrace_val));
=======
		   __FUNCTION__, logtrace_val));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_logtraceinfo =
	__ATTR(logtrace, 0660, show_logtrace_info, set_logtrace_info);
#endif /* LOGTRACE_FROM_FILE */

<<<<<<< HEAD
#ifdef  USE_WFA_CERT_CONF
#ifdef BCMSDIO
uint32 bus_txglom = VALUENOTSET;

static ssize_t
show_bustxglom(struct dhd_info *dev, char *buf)
=======
#ifdef USE_WFA_CERT_CONF
#ifdef BCMSDIO
uint32 bus_txglom = VALUENOTSET;

static ssize_t show_bustxglom(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (bus_txglom == VALUENOTSET) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n", "bustxglom not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", bus_txglom);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n",
				"bustxglom not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", bus_txglom);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_bustxglom(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_bustxglom(struct dhd_info *dev, const char *buf,
			     size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 onoff;

	onoff = (uint32)bcm_atoi(buf);
	sscanf(buf, "%u", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %u \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	bus_txglom = onoff;
	DHD_ERROR(("[WIFI_SEC] %s: BUS TXGLOM On/Off from sysfs = %u\n",
<<<<<<< HEAD
			__FUNCTION__, bus_txglom));
=======
		   __FUNCTION__, bus_txglom));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_bustxglom =
	__ATTR(bustxglom, 0660, show_bustxglom, set_bustxglom);
#endif /* BCMSDIO */

#if defined(ROAM_ENABLE) || defined(DISABLE_BUILTIN_ROAM)
uint32 roam_off = VALUENOTSET;

<<<<<<< HEAD
static ssize_t
show_roamoff(struct dhd_info *dev, char *buf)
=======
static ssize_t show_roamoff(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (roam_off == VALUENOTSET) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE -1, "%s\n", "roam_off not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", roam_off);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n",
				"roam_off not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", roam_off);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_roamoff(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_roamoff(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 onoff;

	onoff = bcm_atoi(buf);
	sscanf(buf, "%u", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %u \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	roam_off = onoff;
<<<<<<< HEAD
	DHD_ERROR(("[WIFI_SEC] %s: ROAM On/Off from sysfs = %u\n",
		__FUNCTION__, roam_off));
=======
	DHD_ERROR(("[WIFI_SEC] %s: ROAM On/Off from sysfs = %u\n", __FUNCTION__,
		   roam_off));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_roamoff =
	__ATTR(roamoff, 0660, show_roamoff, set_roamoff);
#endif /* ROAM_ENABLE || DISABLE_BUILTIN_ROAM */

#ifdef USE_WL_FRAMEBURST
uint32 frameburst = VALUENOTSET;

<<<<<<< HEAD
static ssize_t
show_frameburst(struct dhd_info *dev, char *buf)
=======
static ssize_t show_frameburst(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (frameburst == VALUENOTSET) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE -1, "%s\n", "frameburst not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", frameburst);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n",
				"frameburst not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", frameburst);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_frameburst(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_frameburst(struct dhd_info *dev, const char *buf,
			      size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 onoff;

	onoff = bcm_atoi(buf);
	sscanf(buf, "%u", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %u \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	frameburst = onoff;
	DHD_ERROR(("[WIFI_SEC] %s: FRAMEBURST On/Off from sysfs = %u\n",
<<<<<<< HEAD
		__FUNCTION__, frameburst));
=======
		   __FUNCTION__, frameburst));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_frameburst =
	__ATTR(frameburst, 0660, show_frameburst, set_frameburst);
#endif /* USE_WL_FRAMEBURST */

#ifdef USE_WL_TXBF
uint32 txbf = VALUENOTSET;

<<<<<<< HEAD
static ssize_t
show_txbf(struct dhd_info *dev, char *buf)
=======
static ssize_t show_txbf(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (txbf == VALUENOTSET) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE -1, "%s\n", "txbf not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", txbf);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n",
				"txbf not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", txbf);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_txbf(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_txbf(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 onoff;

	onoff = bcm_atoi(buf);
	sscanf(buf, "%u", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %u \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	txbf = onoff;
	DHD_ERROR(("[WIFI_SEC] %s: FRAMEBURST On/Off from sysfs = %u\n",
<<<<<<< HEAD
		__FUNCTION__, txbf));
	return count;
}

static struct dhd_attr dhd_attr_txbf =
	__ATTR(txbf, 0660, show_txbf, set_txbf);
=======
		   __FUNCTION__, txbf));
	return count;
}

static struct dhd_attr dhd_attr_txbf = __ATTR(txbf, 0660, show_txbf, set_txbf);
>>>>>>> lucasblacklu/wip
#endif /* USE_WL_TXBF */

#ifdef PROP_TXSTATUS
uint32 proptx = VALUENOTSET;

<<<<<<< HEAD
static ssize_t
show_proptx(struct dhd_info *dev, char *buf)
=======
static ssize_t show_proptx(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	if (proptx == VALUENOTSET) {
<<<<<<< HEAD
		ret = scnprintf(buf, PAGE_SIZE -1, "%s\n", "proptx not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE -1, "%u\n", proptx);
=======
		ret = scnprintf(buf, PAGE_SIZE - 1, "%s\n",
				"proptx not set from sysfs");
	} else {
		ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", proptx);
>>>>>>> lucasblacklu/wip
	}
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_proptx(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_proptx(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 onoff;

	onoff = bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%u", &onoff);

	if (onoff > 2) {
		DHD_ERROR(("[WIFI_SEC] %s: Set Invalid value %u \n",
<<<<<<< HEAD
			__FUNCTION__, onoff));
=======
			   __FUNCTION__, onoff));
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	proptx = onoff;
<<<<<<< HEAD
	DHD_ERROR(("[WIFI_SEC] %s: proptx from sysfs = %u\n",
		__FUNCTION__, proptx));
=======
	DHD_ERROR(("[WIFI_SEC] %s: proptx from sysfs = %u\n", __FUNCTION__,
		   proptx));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_attr_proptx =
	__ATTR(proptx, 0660, show_proptx, set_proptx);

#endif /* PROP_TXSTATUS */
#endif /* USE_WFA_CERT_CONF */
#endif /* DHD_EXPORT_CNTL_FILE */

#if defined(DHD_ADPS_BAM_EXPORT) && defined(WL_BAM)
<<<<<<< HEAD
#define BAD_AP_MAC_ADDR_ELEMENT_NUM	6
#define MACF_READ	"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
wl_bad_ap_mngr_t *g_bad_ap_mngr = NULL;

static ssize_t
show_adps_bam_list(struct dhd_info *dev, char *buf)
=======
#define BAD_AP_MAC_ADDR_ELEMENT_NUM 6
#define MACF_READ "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
wl_bad_ap_mngr_t *g_bad_ap_mngr = NULL;

static ssize_t show_adps_bam_list(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	int offset = 0;
	ssize_t ret = 0;

	wl_bad_ap_info_t *bad_ap;
	wl_bad_ap_info_entry_t *entry;

	if (g_bad_ap_mngr == NULL)
		return ret;

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
<<<<<<< HEAD
	list_for_each_entry(entry, &g_bad_ap_mngr->list, list) {
		bad_ap = &entry->bad_ap;

		ret = scnprintf(buf + offset, PAGE_SIZE - 1, MACF"\n",
			bad_ap->bssid.octet[0], bad_ap->bssid.octet[1],
			bad_ap->bssid.octet[2], bad_ap->bssid.octet[3],
			bad_ap->bssid.octet[4], bad_ap->bssid.octet[5]);
=======
	list_for_each_entry (entry, &g_bad_ap_mngr->list, list) {
		bad_ap = &entry->bad_ap;

		ret = scnprintf(buf + offset, PAGE_SIZE - 1, MACF "\n",
				bad_ap->bssid.octet[0], bad_ap->bssid.octet[1],
				bad_ap->bssid.octet[2], bad_ap->bssid.octet[3],
				bad_ap->bssid.octet[4], bad_ap->bssid.octet[5]);
>>>>>>> lucasblacklu/wip

		offset += ret;
	}
	GCC_DIAGNOSTIC_POP();

	return offset;
}

<<<<<<< HEAD
static ssize_t
store_adps_bam_list(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t store_adps_bam_list(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	int ret;
	size_t len;
	int offset;
	char tmp[128];
	wl_bad_ap_info_t bad_ap;

	if (g_bad_ap_mngr == NULL)
		return count;

	len = count;
	offset = 0;
	do {
<<<<<<< HEAD
		ret = sscanf(buf + offset, MACF_READ"\n",
			&bad_ap.bssid.octet[0], &bad_ap.bssid.octet[1],
			&bad_ap.bssid.octet[2], &bad_ap.bssid.octet[3],
			&bad_ap.bssid.octet[4], &bad_ap.bssid.octet[5]);
		if (ret != BAD_AP_MAC_ADDR_ELEMENT_NUM) {
			DHD_ERROR(("%s - fail to parse bad ap data\n", __FUNCTION__));
=======
		ret = sscanf(buf + offset, MACF_READ "\n",
			     &bad_ap.bssid.octet[0], &bad_ap.bssid.octet[1],
			     &bad_ap.bssid.octet[2], &bad_ap.bssid.octet[3],
			     &bad_ap.bssid.octet[4], &bad_ap.bssid.octet[5]);
		if (ret != BAD_AP_MAC_ADDR_ELEMENT_NUM) {
			DHD_ERROR(("%s - fail to parse bad ap data\n",
				   __FUNCTION__));
>>>>>>> lucasblacklu/wip
			return -EINVAL;
		}

		ret = wl_bad_ap_mngr_add(g_bad_ap_mngr, &bad_ap);
		if (ret < 0)
			return ret;

<<<<<<< HEAD
		ret = snprintf(tmp, ARRAYSIZE(tmp), MACF"\n",
			bad_ap.bssid.octet[0], bad_ap.bssid.octet[1],
			bad_ap.bssid.octet[2], bad_ap.bssid.octet[3],
			bad_ap.bssid.octet[4], bad_ap.bssid.octet[5]);
		if (ret < 0) {
			DHD_ERROR(("%s - fail to get bad ap data length(%d)\n", __FUNCTION__, ret));
=======
		ret = snprintf(tmp, ARRAYSIZE(tmp), MACF "\n",
			       bad_ap.bssid.octet[0], bad_ap.bssid.octet[1],
			       bad_ap.bssid.octet[2], bad_ap.bssid.octet[3],
			       bad_ap.bssid.octet[4], bad_ap.bssid.octet[5]);
		if (ret < 0) {
			DHD_ERROR(("%s - fail to get bad ap data length(%d)\n",
				   __FUNCTION__, ret));
>>>>>>> lucasblacklu/wip
			return ret;
		}

		len -= ret;
		offset += ret;
	} while (len > 0);

	return count;
}

static struct dhd_attr dhd_attr_adps_bam =
	__ATTR(bad_ap_list, 0660, show_adps_bam_list, store_adps_bam_list);
<<<<<<< HEAD
#endif	/* DHD_ADPS_BAM_EXPORT && WL_BAM */
=======
#endif /* DHD_ADPS_BAM_EXPORT && WL_BAM */
>>>>>>> lucasblacklu/wip

#ifdef DHD_SEND_HANG_PRIVCMD_ERRORS
uint32 report_hang_privcmd_err = 1;

<<<<<<< HEAD
static ssize_t
show_hang_privcmd_err(struct dhd_info *dev, char *buf)
=======
static ssize_t show_hang_privcmd_err(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%u\n", report_hang_privcmd_err);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_hang_privcmd_err(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_hang_privcmd_err(struct dhd_info *dev, const char *buf,
				    size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	val = bcm_atoi(buf);
	sscanf(buf, "%u", &val);

	report_hang_privcmd_err = val ? 1 : 0;
	DHD_INFO(("%s: Set report HANG for private cmd error: %d\n",
<<<<<<< HEAD
		__FUNCTION__, report_hang_privcmd_err));
	return count;
}

static struct dhd_attr dhd_attr_hang_privcmd_err =
	__ATTR(hang_privcmd_err, 0660, show_hang_privcmd_err, set_hang_privcmd_err);
#endif /* DHD_SEND_HANG_PRIVCMD_ERRORS */

#if defined(SHOW_LOGTRACE)
static ssize_t
show_control_logtrace(struct dhd_info *dev, char *buf)
=======
		  __FUNCTION__, report_hang_privcmd_err));
	return count;
}

static struct dhd_attr dhd_attr_hang_privcmd_err = __ATTR(
	hang_privcmd_err, 0660, show_hang_privcmd_err, set_hang_privcmd_err);
#endif /* DHD_SEND_HANG_PRIVCMD_ERRORS */

#if defined(SHOW_LOGTRACE)
static ssize_t show_control_logtrace(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", control_logtrace);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_control_logtrace(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_control_logtrace(struct dhd_info *dev, const char *buf,
				    size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	val = bcm_atoi(buf);

	control_logtrace = val;
<<<<<<< HEAD
	DHD_ERROR(("%s: Set control logtrace: %d\n", __FUNCTION__, control_logtrace));
	return count;
}

static struct dhd_attr dhd_attr_control_logtrace =
__ATTR(control_logtrace, 0660, show_control_logtrace, set_control_logtrace);
=======
	DHD_ERROR(("%s: Set control logtrace: %d\n", __FUNCTION__,
		   control_logtrace));
	return count;
}

static struct dhd_attr dhd_attr_control_logtrace = __ATTR(
	control_logtrace, 0660, show_control_logtrace, set_control_logtrace);
>>>>>>> lucasblacklu/wip
#endif /* SHOW_LOGTRACE */

#if defined(DISABLE_HE_ENAB) || defined(CUSTOM_CONTROL_HE_ENAB)
uint8 control_he_enab = 1;
#endif /* DISABLE_HE_ENAB || CUSTOM_CONTROL_HE_ENAB */

#ifdef RX_PKT_POOL
<<<<<<< HEAD
static ssize_t
show_max_rx_pkt_pool(struct dhd_info *dhd, char *buf)
=======
static ssize_t show_max_rx_pkt_pool(struct dhd_info *dhd, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return ret;
	}

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", dhd->rx_pkt_pool.max_size);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_max_rx_pkt_pool(struct dhd_info *dhd, const char *buf, size_t count)
=======
static ssize_t set_max_rx_pkt_pool(struct dhd_info *dhd, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return count;
	}

	val = bcm_atoi(buf);

<<<<<<< HEAD
	dhd->rx_pkt_pool.max_size = ((val > MAX_RX_PKT_POOL) &&
		(val <= (MAX_RX_PKT_POOL * 8))) ? val : MAX_RX_PKT_POOL;
	DHD_ERROR(("%s: MAX_RX_PKT_POOL: %d\n", __FUNCTION__, dhd->rx_pkt_pool.max_size));
	return count;
}

static struct dhd_attr dhd_attr_max_rx_pkt_pool=
__ATTR(dhd_max_rx_pkt_pool, 0660, show_max_rx_pkt_pool, set_max_rx_pkt_pool);
#endif /* RX_PKT_POOL */

#if defined(CUSTOM_CONTROL_HE_ENAB)
static ssize_t
show_control_he_enab(struct dhd_info *dev, char *buf)
=======
	dhd->rx_pkt_pool.max_size =
		((val > MAX_RX_PKT_POOL) && (val <= (MAX_RX_PKT_POOL * 8))) ?
			val :
			MAX_RX_PKT_POOL;
	DHD_ERROR(("%s: MAX_RX_PKT_POOL: %d\n", __FUNCTION__,
		   dhd->rx_pkt_pool.max_size));
	return count;
}

static struct dhd_attr dhd_attr_max_rx_pkt_pool = __ATTR(
	dhd_max_rx_pkt_pool, 0660, show_max_rx_pkt_pool, set_max_rx_pkt_pool);
#endif /* RX_PKT_POOL */

#if defined(CUSTOM_CONTROL_HE_ENAB)
static ssize_t show_control_he_enab(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", control_he_enab);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_control_he_enab(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_control_he_enab(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	val = bcm_atoi(buf);

	control_he_enab = val ? 1 : 0;
<<<<<<< HEAD
	DHD_ERROR(("%s: Set control he enab: %d\n", __FUNCTION__, control_he_enab));
	return count;
}

static struct dhd_attr dhd_attr_control_he_enab=
__ATTR(control_he_enab, 0660, show_control_he_enab, set_control_he_enab);
#endif /* CUSTOM_CONTROL_HE_ENAB */

#if defined(WLAN_ACCEL_BOOT)
static ssize_t
show_wl_accel_force_reg_on(struct dhd_info *dhd, char *buf)
=======
	DHD_ERROR(("%s: Set control he enab: %d\n", __FUNCTION__,
		   control_he_enab));
	return count;
}

static struct dhd_attr dhd_attr_control_he_enab = __ATTR(
	control_he_enab, 0660, show_control_he_enab, set_control_he_enab);
#endif /* CUSTOM_CONTROL_HE_ENAB */

#if defined(WLAN_ACCEL_BOOT)
static ssize_t show_wl_accel_force_reg_on(struct dhd_info *dhd, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return ret;
	}

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", dhd->wl_accel_force_reg_on);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_wl_accel_force_reg_on(struct dhd_info *dhd, const char *buf, size_t count)
=======
static ssize_t set_wl_accel_force_reg_on(struct dhd_info *dhd, const char *buf,
					 size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return count;
	}

	val = bcm_atoi(buf);

	dhd->wl_accel_force_reg_on = val ? 1 : 0;
<<<<<<< HEAD
	DHD_ERROR(("%s: wl_accel_force_reg_on: %d\n", __FUNCTION__, dhd->wl_accel_force_reg_on));
	return count;
}

static struct dhd_attr dhd_attr_wl_accel_force_reg_on=
__ATTR(wl_accel_force_reg_on, 0660, show_wl_accel_force_reg_on, set_wl_accel_force_reg_on);
=======
	DHD_ERROR(("%s: wl_accel_force_reg_on: %d\n", __FUNCTION__,
		   dhd->wl_accel_force_reg_on));
	return count;
}

static struct dhd_attr dhd_attr_wl_accel_force_reg_on =
	__ATTR(wl_accel_force_reg_on, 0660, show_wl_accel_force_reg_on,
	       set_wl_accel_force_reg_on);
>>>>>>> lucasblacklu/wip
#endif /* WLAN_ACCEL_BOOT */

/*
 * Dumps the lock and other state information useful for debug
 *
 */
<<<<<<< HEAD
static ssize_t
dhd_debug_dump_stateinfo(struct dhd_info *dhd, char *buf)
=======
static ssize_t dhd_debug_dump_stateinfo(struct dhd_info *dhd, char *buf)
>>>>>>> lucasblacklu/wip
{
	u32 buf_size = PAGE_SIZE - 1;
	u8 *ptr = buf;
	ssize_t len = 0;

	len += scnprintf(ptr, buf_size, "[DHD]\nlock info:\n");
#ifdef BT_OVER_SDIO
<<<<<<< HEAD
	len += scnprintf((ptr+len), (buf_size-len), "bus_user_lock:\n",
			mutex_is_locked(&dhd->bus_user_lock));
#endif /* BT_OVER_SDIO */

#ifdef WL_CFG80211
	len += wl_cfg80211_debug_data_dump(dhd_linux_get_primary_netdev(&dhd->pub),
			(ptr + len), (buf_size - len));
=======
	len += scnprintf((ptr + len), (buf_size - len), "bus_user_lock:\n",
			 mutex_is_locked(&dhd->bus_user_lock));
#endif /* BT_OVER_SDIO */

#ifdef WL_CFG80211
	len += wl_cfg80211_debug_data_dump(
		dhd_linux_get_primary_netdev(&dhd->pub), (ptr + len),
		(buf_size - len));
>>>>>>> lucasblacklu/wip
#endif /* WL_CFG80211 */

	/* Ensure buffer ends with null char */
	buf[len] = '\0';
	return len + 1;
}
static struct dhd_attr dhd_attr_dhd_debug_data =
<<<<<<< HEAD
__ATTR(dump_stateinfo, 0660, dhd_debug_dump_stateinfo, NULL);
=======
	__ATTR(dump_stateinfo, 0660, dhd_debug_dump_stateinfo, NULL);
>>>>>>> lucasblacklu/wip

#ifdef WL_CFG80211
#define _S(x) #x
#define S(x) _S(x)
#define SUBLOGLEVEL 20
#define SUBLOGLEVELZ ((SUBLOGLEVEL) + (1))
static const struct {
	u32 log_level;
	char *sublogname;
} sublogname_map[] = {
<<<<<<< HEAD
	{WL_DBG_ERR, "ERR"},
	{WL_DBG_INFO, "INFO"},
	{WL_DBG_DBG, "DBG"},
	{WL_DBG_SCAN, "SCAN"},
	{WL_DBG_TRACE, "TRACE"},
	{WL_DBG_P2P_ACTION, "P2PACTION"},
	{WL_DBG_PNO, "PNO"}
=======
	{ WL_DBG_ERR, "ERR" },	   { WL_DBG_INFO, "INFO" },
	{ WL_DBG_DBG, "DBG" },	   { WL_DBG_SCAN, "SCAN" },
	{ WL_DBG_TRACE, "TRACE" }, { WL_DBG_P2P_ACTION, "P2PACTION" },
	{ WL_DBG_PNO, "PNO" }
>>>>>>> lucasblacklu/wip
};

/**
* Format : echo "SCAN:1 DBG:1" > /sys/wifi/wl_dbg_level
* to turn on SCAN and DBG log.
* To turn off SCAN partially, echo "SCAN:0" > /sys/wifi/wl_dbg_level
* To see current setting of debug level,
* cat /sys/wifi/wl_dbg_level
*/
<<<<<<< HEAD
static ssize_t
show_wl_debug_level(struct dhd_info *dhd, char *buf)
=======
static ssize_t show_wl_debug_level(struct dhd_info *dhd, char *buf)
>>>>>>> lucasblacklu/wip
{
	char *param;
	char tbuf[SUBLOGLEVELZ * ARRAYSIZE(sublogname_map)];
	uint i;
	ssize_t ret = 0;

	bzero(tbuf, sizeof(tbuf));
	param = &tbuf[0];
	for (i = 0; i < ARRAYSIZE(sublogname_map); i++) {
<<<<<<< HEAD
		param += snprintf(param, sizeof(tbuf) - 1, "%s:%d ",
=======
		param += snprintf(
			param, sizeof(tbuf) - 1, "%s:%d ",
>>>>>>> lucasblacklu/wip
			sublogname_map[i].sublogname,
			(wl_dbg_level & sublogname_map[i].log_level) ? 1 : 0);
	}
	ret = scnprintf(buf, PAGE_SIZE - 1, "%s \n", tbuf);
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_wl_debug_level(struct dhd_info *dhd, const char *buf, size_t count)
{
	char tbuf[SUBLOGLEVELZ * ARRAYSIZE(sublogname_map)], sublog[SUBLOGLEVELZ];
=======
static ssize_t set_wl_debug_level(struct dhd_info *dhd, const char *buf,
				  size_t count)
{
	char tbuf[SUBLOGLEVELZ * ARRAYSIZE(sublogname_map)],
		sublog[SUBLOGLEVELZ];
>>>>>>> lucasblacklu/wip
	char *params, *token, *colon;
	uint i, tokens, log_on = 0;
	size_t minsize = min_t(size_t, (sizeof(tbuf) - 1), count);

	bzero(tbuf, sizeof(tbuf));
	bzero(sublog, sizeof(sublog));
	strlcpy(tbuf, buf, minsize);

	DHD_INFO(("current wl_dbg_level %d \n", wl_dbg_level));

	tbuf[minsize] = '\0';
	params = &tbuf[0];
	colon = strchr(params, '\n');
	if (colon != NULL)
		*colon = '\0';
	while ((token = strsep(&params, " ")) != NULL) {
		bzero(sublog, sizeof(sublog));
		if (token == NULL || !*token)
			break;
		if (*token == '\0')
			continue;
		colon = strchr(token, ':');
		if (colon != NULL) {
			*colon = ' ';
		}
<<<<<<< HEAD
		tokens = sscanf(token, "%"S(SUBLOGLEVEL)"s %u", sublog, &log_on);
=======
		tokens = sscanf(token, "%" S(SUBLOGLEVEL) "s %u", sublog,
				&log_on);
>>>>>>> lucasblacklu/wip
		if (colon != NULL)
			*colon = ':';

		if (tokens == 2) {
<<<<<<< HEAD
				for (i = 0; i < ARRAYSIZE(sublogname_map); i++) {
					if (!strncmp(sublog, sublogname_map[i].sublogname,
						strlen(sublogname_map[i].sublogname))) {
						if (log_on)
							wl_dbg_level |=
							(sublogname_map[i].log_level);
						else
							wl_dbg_level &=
							~(sublogname_map[i].log_level);
					}
				}
		} else
			WL_ERR(("%s: can't parse '%s' as a "
			       "SUBMODULE:LEVEL (%d tokens)\n",
			       tbuf, token, tokens));

=======
			for (i = 0; i < ARRAYSIZE(sublogname_map); i++) {
				if (!strncmp(sublog,
					     sublogname_map[i].sublogname,
					     strlen(sublogname_map[i]
							    .sublogname))) {
					if (log_on)
						wl_dbg_level |=
							(sublogname_map[i]
								 .log_level);
					else
						wl_dbg_level &=
							~(sublogname_map[i]
								  .log_level);
				}
			}
		} else
			WL_ERR(("%s: can't parse '%s' as a "
				"SUBMODULE:LEVEL (%d tokens)\n",
				tbuf, token, tokens));
>>>>>>> lucasblacklu/wip
	}
	DHD_INFO(("changed wl_dbg_level %d \n", wl_dbg_level));
	return count;
}

static struct dhd_attr dhd_attr_wl_dbg_level =
<<<<<<< HEAD
__ATTR(wl_dbg_level, 0660, show_wl_debug_level, set_wl_debug_level);

#ifdef DHD_FILE_DUMP_EVENT
#define DUMP_TRIGGER	1

static ssize_t
show_dhd_dump_in_progress(struct dhd_info *dhd, char *buf)
=======
	__ATTR(wl_dbg_level, 0660, show_wl_debug_level, set_wl_debug_level);

#ifdef DHD_FILE_DUMP_EVENT
#define DUMP_TRIGGER 1

static ssize_t show_dhd_dump_in_progress(struct dhd_info *dhd, char *buf)
>>>>>>> lucasblacklu/wip
{
	size_t ret = 0;
	dhd_dongledump_status_t dump_status;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return BCME_ERROR;
	}

	dump_status = dhd_get_dump_status(&dhd->pub);
	ret = scnprintf(buf, PAGE_SIZE - 1, "%d \n", dump_status);

	return ret;
}

<<<<<<< HEAD
static ssize_t
set_dhd_dump_in_progress(struct dhd_info *dhd, const char *buf, size_t count)
=======
static ssize_t set_dhd_dump_in_progress(struct dhd_info *dhd, const char *buf,
					size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 input;
	dhd_dongledump_status_t dump_status;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return count;
	}

	dump_status = dhd_get_dump_status(&dhd->pub);
	if (dump_status == DUMP_NOT_READY || dump_status == DUMP_IN_PROGRESS) {
		DHD_ERROR(("%s: Could not start dongle dump: %d\n",
<<<<<<< HEAD
			__FUNCTION__, dump_status));
=======
			   __FUNCTION__, dump_status));
>>>>>>> lucasblacklu/wip
		goto exit;
	}

	input = bcm_atoi(buf);
	if (input == DUMP_TRIGGER) {
		DHD_INFO(("%s: Trigger dongle dump\n", __FUNCTION__));
		dhd_set_dump_status(&dhd->pub, DUMP_IN_PROGRESS);
		schedule_work(&dhd->dhd_dump_proc_work);
<<<<<<< HEAD
	}
	else {
=======
	} else {
>>>>>>> lucasblacklu/wip
		DHD_ERROR(("%s: Invalid value %d\n", __FUNCTION__, input));
	}

exit:
	return count;
}

static struct dhd_attr dhd_attr_dump_in_progress =
<<<<<<< HEAD
__ATTR(dump_in_progress, 0660, show_dhd_dump_in_progress, set_dhd_dump_in_progress);
=======
	__ATTR(dump_in_progress, 0660, show_dhd_dump_in_progress,
	       set_dhd_dump_in_progress);
>>>>>>> lucasblacklu/wip
#endif /* DHD_FILE_DUMP_EVENT */
#endif /* WL_CFG80211 */

/* Attribute object that gets registered with "wifi" kobject tree */
static struct attribute *default_file_attrs[] = {
#ifdef DHD_MAC_ADDR_EXPORT
	&dhd_attr_macaddr.attr,
#endif /* DHD_MAC_ADDR_EXPORT */
#ifdef DHD_EXPORT_CNTL_FILE
#ifdef DHD_FW_COREDUMP
	&dhd_attr_memdump.attr,
#endif /* DHD_FW_COREDUMP */
#ifdef BCMASSERT_LOG
	&dhd_attr_assert.attr,
#endif /* BCMASSERT_LOG */
#ifdef WRITE_WLANINFO
	&dhd_attr_wifiver.attr,
#endif /* WRITE_WLANINFO */
#if defined(USE_CID_CHECK) || defined(USE_DIRECT_VID_TAG)
	&dhd_attr_cidinfo.attr,
#endif /* USE_CID_CHECK || USE_DIRECT_VID_TAG */
#ifdef GEN_SOFTAP_INFO_FILE
	&dhd_attr_softapinfo.attr,
#endif /* GEN_SOFTAP_INFO_FILE */
#ifdef MIMO_ANT_SETTING
	&dhd_attr_antinfo.attr,
#endif /* MIMO_ANT_SETTING */
#ifdef DHD_PM_CONTROL_FROM_FILE
	&dhd_attr_pminfo.attr,
#endif /* DHD_PM_CONTROL_FROM_FILE */
#ifdef LOGTRACE_FROM_FILE
	&dhd_attr_logtraceinfo.attr,
#endif /* LOGTRACE_FROM_FILE */
#ifdef USE_WFA_CERT_CONF
#ifdef BCMSDIO
	&dhd_attr_bustxglom.attr,
#endif /* BCMSDIO */
	&dhd_attr_roamoff.attr,
#ifdef USE_WL_FRAMEBURST
	&dhd_attr_frameburst.attr,
#endif /* USE_WL_FRAMEBURST */
#ifdef USE_WL_TXBF
	&dhd_attr_txbf.attr,
#endif /* USE_WL_TXBF */
#ifdef PROP_TXSTATUS
	&dhd_attr_proptx.attr,
#endif /* PROP_TXSTATUS */
#endif /* USE_WFA_CERT_CONF */
#endif /* DHD_EXPORT_CNTL_FILE */
#if defined(DHD_ADPS_BAM_EXPORT) && defined(WL_BAM)
	&dhd_attr_adps_bam.attr,
<<<<<<< HEAD
#endif	/* DHD_ADPS_BAM_EXPORT && WL_BAM */
=======
#endif /* DHD_ADPS_BAM_EXPORT && WL_BAM */
>>>>>>> lucasblacklu/wip
#ifdef DHD_SEND_HANG_PRIVCMD_ERRORS
	&dhd_attr_hang_privcmd_err.attr,
#endif /* DHD_SEND_HANG_PRIVCMD_ERRORS */
#if defined(SHOW_LOGTRACE)
	&dhd_attr_control_logtrace.attr,
#endif /* SHOW_LOGTRACE */
#if defined(DHD_TRACE_WAKE_LOCK)
	&dhd_attr_wklock.attr,
#endif
#ifdef DHD_LOG_DUMP
	&dhd_attr_logdump_periodic_flush.attr,
	&dhd_attr_logdump_ecntr.attr,
#endif
	&dhd_attr_ecounters.attr,
#ifdef DHD_SSSR_DUMP
	&dhd_attr_sssr_enab.attr,
	&dhd_attr_fis_enab.attr,
#endif /* DHD_SSSR_DUMP */
	&dhd_attr_firmware_path.attr,
	&dhd_attr_nvram_path.attr,
#if defined(CUSTOM_CONTROL_HE_ENAB)
	&dhd_attr_control_he_enab.attr,
#endif /* CUSTOM_CONTROL_HE_ENAB */
#if defined(WLAN_ACCEL_BOOT)
	&dhd_attr_wl_accel_force_reg_on.attr,
#endif /* WLAN_ACCEL_BOOT */
#if defined(WL_CFG80211)
	&dhd_attr_wl_dbg_level.attr,
#if defined(DHD_FILE_DUMP_EVENT)
	&dhd_attr_dump_in_progress.attr,
#endif /* DHD_FILE_DUMP_EVENT */
#endif /* WL_CFG80211 */
	&dhd_attr_dhd_debug_data.attr,
#if defined(RX_PKT_POOL)
	&dhd_attr_max_rx_pkt_pool.attr,
#endif /* RX_PKT_POOL */
	NULL
};

/*
 * wifi kobject show function, the "attr" attribute specifices to which
 * node under "sys/wifi" the show function is called.
 */
static ssize_t dhd_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	dhd_info_t *dhd;
	struct dhd_attr *d_attr;
	int ret;

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	dhd = to_dhd(kobj);
	d_attr = to_attr(attr);
	GCC_DIAGNOSTIC_POP();

	if (d_attr->show)
		ret = d_attr->show(dhd, buf);
	else
		ret = -EIO;

	return ret;
}

/*
 * wifi kobject show function, the "attr" attribute specifices to which
 * node under "sys/wifi" the store function is called.
 */
static ssize_t dhd_store(struct kobject *kobj, struct attribute *attr,
<<<<<<< HEAD
	const char *buf, size_t count)
=======
			 const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd;
	struct dhd_attr *d_attr;
	int ret;

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	dhd = to_dhd(kobj);
	d_attr = to_attr(attr);
	GCC_DIAGNOSTIC_POP();

	if (d_attr->store)
		ret = d_attr->store(dhd, buf, count);
	else
		ret = -EIO;

	return ret;
<<<<<<< HEAD

=======
>>>>>>> lucasblacklu/wip
}

static struct sysfs_ops dhd_sysfs_ops = {
	.show = dhd_show,
	.store = dhd_store,
};

static struct kobj_type dhd_ktype = {
	.sysfs_ops = &dhd_sysfs_ops,
	.default_attrs = default_file_attrs,
};

/*
 * sysfs for dhd_lb
 */
#ifdef DHD_LB
#if defined(DHD_LB_TXP)
<<<<<<< HEAD
static ssize_t
show_lbtxp(struct dhd_info *dev, char *buf)
=======
static ssize_t show_lbtxp(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;

	onoff = atomic_read(&dhd->lb_txp_active);
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n",
		onoff);
	return ret;
}

static ssize_t
lbtxp_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", onoff);
	return ret;
}

static ssize_t lbtxp_onoff(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;
	int i;

	onoff = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &onoff);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}
	atomic_set(&dhd->lb_txp_active, onoff);

	/* Since the scheme is changed clear the counters */
	for (i = 0; i < NR_CPUS; i++) {
		DHD_LB_STATS_CLR(dhd->txp_percpu_run_cnt[i]);
		DHD_LB_STATS_CLR(dhd->tx_start_percpu_run_cnt[i]);
	}

	return count;
}

static struct dhd_attr dhd_attr_lbtxp =
	__ATTR(lbtxp, 0660, show_lbtxp, lbtxp_onoff);
#endif /* DHD_LB_TXP */

#if defined(DHD_LB_RXP)
<<<<<<< HEAD
static ssize_t
show_lbrxp(struct dhd_info *dev, char *buf)
=======
static ssize_t show_lbrxp(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;

	onoff = atomic_read(&dhd->lb_rxp_active);
<<<<<<< HEAD
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n",
		onoff);
	return ret;
}

static ssize_t
lbrxp_onoff(struct dhd_info *dev, const char *buf, size_t count)
=======
	ret = scnprintf(buf, PAGE_SIZE - 1, "%lu \n", onoff);
	return ret;
}

static ssize_t lbrxp_onoff(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	unsigned long onoff;
	dhd_info_t *dhd = (dhd_info_t *)dev;

	onoff = bcm_strtoul(buf, NULL, 10);

	sscanf(buf, "%lu", &onoff);
	if (onoff != 0 && onoff != 1) {
		return -EINVAL;
	}
	atomic_set(&dhd->lb_rxp_active, onoff);

	return count;
}
static struct dhd_attr dhd_attr_lbrxp =
	__ATTR(lbrxp, 0660, show_lbrxp, lbrxp_onoff);

<<<<<<< HEAD
static ssize_t
get_lb_rxp_stop_thr(struct dhd_info *dev, char *buf)
=======
static ssize_t get_lb_rxp_stop_thr(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd = (dhd_info_t *)dev;
	dhd_pub_t *dhdp;
	ssize_t ret = 0;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return -EINVAL;
	}
	dhdp = &dhd->pub;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%u \n",
<<<<<<< HEAD
		(dhdp->lb_rxp_stop_thr / D2HRING_RXCMPLT_MAX_ITEM));
=======
			(dhdp->lb_rxp_stop_thr / D2HRING_RXCMPLT_MAX_ITEM));
>>>>>>> lucasblacklu/wip
	return ret;
}

#define ONE_GB (1024 * 1024 * 1024)

<<<<<<< HEAD
static ssize_t
set_lb_rxp_stop_thr(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_lb_rxp_stop_thr(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd = (dhd_info_t *)dev;
	dhd_pub_t *dhdp;
	uint32 lb_rxp_stop_thr;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return -EINVAL;
	}
	dhdp = &dhd->pub;

	lb_rxp_stop_thr = (uint32)bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%u", &lb_rxp_stop_thr);

	/* disable lb_rxp flow ctrl */
	if (lb_rxp_stop_thr == 0) {
		dhdp->lb_rxp_stop_thr = 0;
		dhdp->lb_rxp_strt_thr = 0;
		atomic_set(&dhd->pub.lb_rxp_flow_ctrl, FALSE);
		return count;
	}
	/* 1. by the time lb_rxp_stop_thr gets into picture,
	 * DHD RX path should not consume more than 1GB
	 * 2. lb_rxp_stop_thr should always be more than dhdp->lb_rxp_strt_thr
	 */
<<<<<<< HEAD
	if (((lb_rxp_stop_thr *
		D2HRING_RXCMPLT_MAX_ITEM *
		dhd_prot_get_rxbufpost_sz(dhdp)) > ONE_GB) ||
		(lb_rxp_stop_thr <= (dhdp->lb_rxp_strt_thr / D2HRING_RXCMPLT_MAX_ITEM))) {
=======
	if (((lb_rxp_stop_thr * D2HRING_RXCMPLT_MAX_ITEM *
	      dhd_prot_get_rxbufpost_sz(dhdp)) > ONE_GB) ||
	    (lb_rxp_stop_thr <=
	     (dhdp->lb_rxp_strt_thr / D2HRING_RXCMPLT_MAX_ITEM))) {
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}

	dhdp->lb_rxp_stop_thr = (D2HRING_RXCMPLT_MAX_ITEM * lb_rxp_stop_thr);
	return count;
}

static struct dhd_attr dhd_attr_lb_rxp_stop_thr =
	__ATTR(lbrxp_stop_thr, 0660, get_lb_rxp_stop_thr, set_lb_rxp_stop_thr);

<<<<<<< HEAD
static ssize_t
get_lb_rxp_strt_thr(struct dhd_info *dev, char *buf)
=======
static ssize_t get_lb_rxp_strt_thr(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd = (dhd_info_t *)dev;
	dhd_pub_t *dhdp;
	ssize_t ret = 0;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return -EINVAL;
	}
	dhdp = &dhd->pub;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%u \n",
<<<<<<< HEAD
		(dhdp->lb_rxp_strt_thr / D2HRING_RXCMPLT_MAX_ITEM));
	return ret;
}

static ssize_t
set_lb_rxp_strt_thr(struct dhd_info *dev, const char *buf, size_t count)
=======
			(dhdp->lb_rxp_strt_thr / D2HRING_RXCMPLT_MAX_ITEM));
	return ret;
}

static ssize_t set_lb_rxp_strt_thr(struct dhd_info *dev, const char *buf,
				   size_t count)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd = (dhd_info_t *)dev;
	dhd_pub_t *dhdp;
	uint32 lb_rxp_strt_thr;

	if (!dhd) {
		DHD_ERROR(("%s: dhd is NULL\n", __FUNCTION__));
		return -EINVAL;
	}
	dhdp = &dhd->pub;

	lb_rxp_strt_thr = (uint32)bcm_strtoul(buf, NULL, 10);
	sscanf(buf, "%u", &lb_rxp_strt_thr);

	/* disable lb_rxp flow ctrl */
	if (lb_rxp_strt_thr == 0) {
		dhdp->lb_rxp_strt_thr = 0;
		dhdp->lb_rxp_stop_thr = 0;
		atomic_set(&dhd->pub.lb_rxp_flow_ctrl, FALSE);
		return count;
	}
	/* should be less than dhdp->lb_rxp_stop_thr */
	if ((lb_rxp_strt_thr <= 0) ||
<<<<<<< HEAD
		(lb_rxp_strt_thr >= (dhdp->lb_rxp_stop_thr / D2HRING_RXCMPLT_MAX_ITEM))) {
=======
	    (lb_rxp_strt_thr >=
	     (dhdp->lb_rxp_stop_thr / D2HRING_RXCMPLT_MAX_ITEM))) {
>>>>>>> lucasblacklu/wip
		return -EINVAL;
	}
	dhdp->lb_rxp_strt_thr = (D2HRING_RXCMPLT_MAX_ITEM * lb_rxp_strt_thr);
	return count;
}
static struct dhd_attr dhd_attr_lb_rxp_strt_thr =
	__ATTR(lbrxp_strt_thr, 0660, get_lb_rxp_strt_thr, set_lb_rxp_strt_thr);

#endif /* DHD_LB_RXP */

<<<<<<< HEAD
static ssize_t
show_candidacy_override(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1,
			"%d\n", (int)dev->dhd_lb_candidacy_override);
	return ret;
}

static ssize_t
set_candidacy_override(struct dhd_info *dev, const char *buf, size_t count)
{

=======
static ssize_t show_candidacy_override(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n",
			(int)dev->dhd_lb_candidacy_override);
	return ret;
}

static ssize_t set_candidacy_override(struct dhd_info *dev, const char *buf,
				      size_t count)
{
>>>>>>> lucasblacklu/wip
	int val = 0;
	val = bcm_atoi(buf);

	if (val > 0) {
		dev->dhd_lb_candidacy_override = TRUE;
	} else {
		dev->dhd_lb_candidacy_override = FALSE;
	}

<<<<<<< HEAD
	DHD_ERROR(("set dhd_lb_candidacy_override %d\n", dev->dhd_lb_candidacy_override));
=======
	DHD_ERROR(("set dhd_lb_candidacy_override %d\n",
		   dev->dhd_lb_candidacy_override));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_candidacy_override =
<<<<<<< HEAD
__ATTR(candidacy_override, 0660, show_candidacy_override, set_candidacy_override);

static ssize_t
show_primary_mask(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1,
			"%02lx\n", *cpumask_bits(dev->cpumask_primary));
	return ret;
}

static ssize_t
set_primary_mask(struct dhd_info *dev, const char *buf, size_t count)
=======
	__ATTR(candidacy_override, 0660, show_candidacy_override,
	       set_candidacy_override);

static ssize_t show_primary_mask(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%02lx\n",
			*cpumask_bits(dev->cpumask_primary));
	return ret;
}

static ssize_t set_primary_mask(struct dhd_info *dev, const char *buf,
				size_t count)
>>>>>>> lucasblacklu/wip
{
	int ret;

	cpumask_var_t primary_mask;

	if (!alloc_cpumask_var(&primary_mask, GFP_KERNEL)) {
		DHD_ERROR(("Can't allocate cpumask vars\n"));
		return count;
	}

	cpumask_clear(primary_mask);
	ret = cpumask_parse(buf, primary_mask);
	if (ret < 0) {
		DHD_ERROR(("Setting cpumask failed ret = %d\n", ret));
		return count;
	}

	cpumask_clear(dev->cpumask_primary);
	cpumask_or(dev->cpumask_primary, dev->cpumask_primary, primary_mask);

	DHD_ERROR(("set cpumask results cpumask_primary 0x%2lx\n",
<<<<<<< HEAD
		*cpumask_bits(dev->cpumask_primary)));
=======
		   *cpumask_bits(dev->cpumask_primary)));
>>>>>>> lucasblacklu/wip

	dhd_select_cpu_candidacy(dev);
	return count;
}

static struct dhd_attr dhd_primary_mask =
<<<<<<< HEAD
__ATTR(primary_mask, 0660, show_primary_mask, set_primary_mask);

static ssize_t
show_secondary_mask(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1,
			"%02lx\n", *cpumask_bits(dev->cpumask_secondary));
	return ret;
}

static ssize_t
set_secondary_mask(struct dhd_info *dev, const char *buf, size_t count)
=======
	__ATTR(primary_mask, 0660, show_primary_mask, set_primary_mask);

static ssize_t show_secondary_mask(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%02lx\n",
			*cpumask_bits(dev->cpumask_secondary));
	return ret;
}

static ssize_t set_secondary_mask(struct dhd_info *dev, const char *buf,
				  size_t count)
>>>>>>> lucasblacklu/wip
{
	int ret;

	cpumask_var_t secondary_mask;

	if (!alloc_cpumask_var(&secondary_mask, GFP_KERNEL)) {
		DHD_ERROR(("Can't allocate cpumask vars\n"));
		return count;
	}

	cpumask_clear(secondary_mask);

	ret = cpumask_parse(buf, secondary_mask);

	if (ret < 0) {
		DHD_ERROR(("Setting cpumask failed ret = %d\n", ret));
		return count;
	}

	cpumask_clear(dev->cpumask_secondary);
<<<<<<< HEAD
	cpumask_or(dev->cpumask_secondary, dev->cpumask_secondary, secondary_mask);

	DHD_ERROR(("set cpumask results cpumask_secondary 0x%2lx\n",
		*cpumask_bits(dev->cpumask_secondary)));
=======
	cpumask_or(dev->cpumask_secondary, dev->cpumask_secondary,
		   secondary_mask);

	DHD_ERROR(("set cpumask results cpumask_secondary 0x%2lx\n",
		   *cpumask_bits(dev->cpumask_secondary)));
>>>>>>> lucasblacklu/wip

	dhd_select_cpu_candidacy(dev);

	return count;
}

static struct dhd_attr dhd_secondary_mask =
<<<<<<< HEAD
__ATTR(secondary_mask, 0660, show_secondary_mask, set_secondary_mask);

static ssize_t
show_rx_cpu(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", atomic_read(&dev->rx_napi_cpu));
	return ret;
}

static ssize_t
set_rx_cpu(struct dhd_info *dev, const char *buf, size_t count)
=======
	__ATTR(secondary_mask, 0660, show_secondary_mask, set_secondary_mask);

static ssize_t show_rx_cpu(struct dhd_info *dev, char *buf)
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n",
			atomic_read(&dev->rx_napi_cpu));
	return ret;
}

static ssize_t set_rx_cpu(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	if (!dev->dhd_lb_candidacy_override) {
		DHD_ERROR(("dhd_lb_candidacy_override is required %d\n",
<<<<<<< HEAD
			dev->dhd_lb_candidacy_override));
=======
			   dev->dhd_lb_candidacy_override));
>>>>>>> lucasblacklu/wip
		return count;
	}

	val = (uint32)bcm_atoi(buf);
<<<<<<< HEAD
	if (val >= nr_cpu_ids)
	{
		DHD_ERROR(("%s : can't set the value out of number of cpus, val = %u\n",
=======
	if (val >= nr_cpu_ids) {
		DHD_ERROR((
			"%s : can't set the value out of number of cpus, val = %u\n",
>>>>>>> lucasblacklu/wip
			__FUNCTION__, val));
	}

	atomic_set(&dev->rx_napi_cpu, val);
<<<<<<< HEAD
	DHD_ERROR(("%s: rx_napi_cpu = %d\n", __FUNCTION__, atomic_read(&dev->rx_napi_cpu)));
=======
	DHD_ERROR(("%s: rx_napi_cpu = %d\n", __FUNCTION__,
		   atomic_read(&dev->rx_napi_cpu)));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_rx_cpu =
<<<<<<< HEAD
__ATTR(rx_cpu, 0660, show_rx_cpu, set_rx_cpu);

static ssize_t
show_tx_cpu(struct dhd_info *dev, char *buf)
=======
	__ATTR(rx_cpu, 0660, show_rx_cpu, set_rx_cpu);

static ssize_t show_tx_cpu(struct dhd_info *dev, char *buf)
>>>>>>> lucasblacklu/wip
{
	ssize_t ret = 0;

	ret = scnprintf(buf, PAGE_SIZE - 1, "%d\n", atomic_read(&dev->tx_cpu));
	return ret;
}

<<<<<<< HEAD
static ssize_t
set_tx_cpu(struct dhd_info *dev, const char *buf, size_t count)
=======
static ssize_t set_tx_cpu(struct dhd_info *dev, const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	uint32 val;

	if (!dev->dhd_lb_candidacy_override) {
		DHD_ERROR(("dhd_lb_candidacy_override is required %d\n",
<<<<<<< HEAD
			dev->dhd_lb_candidacy_override));
=======
			   dev->dhd_lb_candidacy_override));
>>>>>>> lucasblacklu/wip
		return count;
	}

	val = (uint32)bcm_atoi(buf);
<<<<<<< HEAD
	if (val >= nr_cpu_ids)
	{
		DHD_ERROR(("%s : can't set the value out of number of cpus, val = %u\n",
=======
	if (val >= nr_cpu_ids) {
		DHD_ERROR((
			"%s : can't set the value out of number of cpus, val = %u\n",
>>>>>>> lucasblacklu/wip
			__FUNCTION__, val));
		return count;
	}

	atomic_set(&dev->tx_cpu, val);
<<<<<<< HEAD
	DHD_ERROR(("%s: tx_cpu = %d\n", __FUNCTION__, atomic_read(&dev->tx_cpu)));
=======
	DHD_ERROR(
		("%s: tx_cpu = %d\n", __FUNCTION__, atomic_read(&dev->tx_cpu)));
>>>>>>> lucasblacklu/wip
	return count;
}

static struct dhd_attr dhd_tx_cpu =
<<<<<<< HEAD
__ATTR(tx_cpu, 0660, show_tx_cpu, set_tx_cpu);
=======
	__ATTR(tx_cpu, 0660, show_tx_cpu, set_tx_cpu);
>>>>>>> lucasblacklu/wip

static struct attribute *debug_lb_attrs[] = {
#if defined(DHD_LB_TXP)
	&dhd_attr_lbtxp.attr,
#endif /* DHD_LB_TXP */
#if defined(DHD_LB_RXP)
	&dhd_attr_lbrxp.attr,
	&dhd_attr_lb_rxp_stop_thr.attr,
	&dhd_attr_lb_rxp_strt_thr.attr,
#endif /* DHD_LB_RXP */
	&dhd_candidacy_override.attr,
	&dhd_primary_mask.attr,
	&dhd_secondary_mask.attr,
	&dhd_rx_cpu.attr,
	&dhd_tx_cpu.attr,
	NULL
};

#define to_dhd_lb(k) container_of(k, struct dhd_info, dhd_lb_kobj)

/*
 * wifi/lb kobject show function, the "attr" attribute specifices to which
 * node under "sys/wifi/lb" the show function is called.
 */
<<<<<<< HEAD
static ssize_t dhd_lb_show(struct kobject *kobj, struct attribute *attr, char *buf)
=======
static ssize_t dhd_lb_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd;
	struct dhd_attr *d_attr;
	int ret;

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	dhd = to_dhd_lb(kobj);
	d_attr = to_attr(attr);
	GCC_DIAGNOSTIC_POP();

	if (d_attr->show)
		ret = d_attr->show(dhd, buf);
	else
		ret = -EIO;

	return ret;
}

/*
 * wifi kobject show function, the "attr" attribute specifices to which
 * node under "sys/wifi/lb" the store function is called.
 */
static ssize_t dhd_lb_store(struct kobject *kobj, struct attribute *attr,
<<<<<<< HEAD
		const char *buf, size_t count)
=======
			    const char *buf, size_t count)
>>>>>>> lucasblacklu/wip
{
	dhd_info_t *dhd;
	struct dhd_attr *d_attr;
	int ret;

	GCC_DIAGNOSTIC_PUSH_SUPPRESS_CAST();
	dhd = to_dhd_lb(kobj);
	d_attr = to_attr(attr);
	GCC_DIAGNOSTIC_POP();

	if (d_attr->store)
		ret = d_attr->store(dhd, buf, count);
	else
		ret = -EIO;

	return ret;
<<<<<<< HEAD

=======
>>>>>>> lucasblacklu/wip
}

static struct sysfs_ops dhd_sysfs_lb_ops = {
	.show = dhd_lb_show,
	.store = dhd_lb_store,
};

static struct kobj_type dhd_lb_ktype = {
	.sysfs_ops = &dhd_sysfs_lb_ops,
	.default_attrs = debug_lb_attrs,
};
#endif /* DHD_LB */

/* Create a kobject and attach to sysfs interface */
int dhd_sysfs_init(dhd_info_t *dhd)
{
	int ret = -1;

	if (dhd == NULL) {
		DHD_ERROR(("%s(): dhd is NULL \r\n", __FUNCTION__));
		return ret;
	}

	/* Initialize the kobject */
	ret = kobject_init_and_add(&dhd->dhd_kobj, &dhd_ktype, NULL, "wifi");
	if (ret) {
		kobject_put(&dhd->dhd_kobj);
<<<<<<< HEAD
		DHD_ERROR(("%s(): Unable to allocate kobject \r\n", __FUNCTION__));
=======
		DHD_ERROR(("%s(): Unable to allocate kobject \r\n",
			   __FUNCTION__));
>>>>>>> lucasblacklu/wip
		return ret;
	}

	/*
	 * We are always responsible for sending the uevent that the kobject
	 * was added to the system.
	 */
	kobject_uevent(&dhd->dhd_kobj, KOBJ_ADD);

#ifdef DHD_LB
<<<<<<< HEAD
	ret  = kobject_init_and_add(&dhd->dhd_lb_kobj,
			&dhd_lb_ktype, &dhd->dhd_kobj, "lb");
	if (ret) {
		kobject_put(&dhd->dhd_lb_kobj);
		DHD_ERROR(("%s(): Unable to allocate kobject \r\n", __FUNCTION__));
=======
	ret = kobject_init_and_add(&dhd->dhd_lb_kobj, &dhd_lb_ktype,
				   &dhd->dhd_kobj, "lb");
	if (ret) {
		kobject_put(&dhd->dhd_lb_kobj);
		DHD_ERROR(("%s(): Unable to allocate kobject \r\n",
			   __FUNCTION__));
>>>>>>> lucasblacklu/wip
		return ret;
	}

	kobject_uevent(&dhd->dhd_lb_kobj, KOBJ_ADD);
#endif /* DHD_LB */

	return ret;
}

/* Done with the kobject and detach the sysfs interface */
void dhd_sysfs_exit(dhd_info_t *dhd)
{
	if (dhd == NULL) {
		DHD_ERROR(("%s(): dhd is NULL \r\n", __FUNCTION__));
		return;
	}

#ifdef DHD_LB
	kobject_put(&dhd->dhd_lb_kobj);
#endif /* DHD_LB */

	/* Releae the kobject */
	kobject_put(&dhd->dhd_kobj);
}

#ifdef DHD_SUPPORT_HDM
<<<<<<< HEAD
static ssize_t
hdm_load_module(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
=======
static ssize_t hdm_load_module(struct kobject *kobj,
			       struct kobj_attribute *attr, const char *buf,
			       size_t count)
>>>>>>> lucasblacklu/wip
{
	int val = bcm_atoi(buf);

	if (val == 1) {
<<<<<<< HEAD
		DHD_ERROR(("%s : Load module from the hdm %d\n", __FUNCTION__, val));
		dhd_module_init_hdm();
	} else {
		DHD_ERROR(("Module load triggered with invalid value : %d\n", val));
=======
		DHD_ERROR(("%s : Load module from the hdm %d\n", __FUNCTION__,
			   val));
		dhd_module_init_hdm();
	} else {
		DHD_ERROR(("Module load triggered with invalid value : %d\n",
			   val));
>>>>>>> lucasblacklu/wip
	}

	return count;
}

static struct kobj_attribute hdm_wlan_attr =
	__ATTR(hdm_wlan_loader, 0660, NULL, hdm_load_module);

<<<<<<< HEAD
void
dhd_hdm_wlan_sysfs_init(void)
=======
void dhd_hdm_wlan_sysfs_init(void)
>>>>>>> lucasblacklu/wip
{
	DHD_ERROR(("export hdm_wlan_loader\n"));
	if (sysfs_create_file(kernel_kobj, &hdm_wlan_attr.attr)) {
		DHD_ERROR(("export hdm_load failed\n"));
	}
}

<<<<<<< HEAD
void
dhd_hdm_wlan_sysfs_deinit(struct work_struct *work)
{
	sysfs_remove_file(kernel_kobj,  &hdm_wlan_attr.attr);

=======
void dhd_hdm_wlan_sysfs_deinit(struct work_struct *work)
{
	sysfs_remove_file(kernel_kobj, &hdm_wlan_attr.attr);
>>>>>>> lucasblacklu/wip
}
#endif /* DHD_SUPPORT_HDM */
