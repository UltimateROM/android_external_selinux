/*
 * sestatus.c
 *
 * APIs to reference SELinux kernel status page (/selinux/status)
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 */
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "avc_internal.h"
#include "policy.h"

/*
 * copied from the selinux/include/security.h
 */
struct selinux_status_t
{
	uint32_t	version;	/* version number of thie structure */
	uint32_t	sequence;	/* sequence number of seqlock logic */
	uint32_t	enforcing;	/* current setting of enforcing mode */
	uint32_t	policyload;	/* times of policy reloaded */
	uint32_t	deny_unknown;	/* current setting of deny_unknown */
	/* version > 0 support above status */
} __attribute((packed));

/*
 * `selinux_status'
 *
 * NULL : not initialized yet
 * MAP_FAILED : opened, but fallback-mode
 * Valid Pointer : opened and mapped correctly
 */
static struct selinux_status_t *selinux_status = NULL;
static int			selinux_status_fd;
static uint32_t			last_seqno;

static uint32_t			fallback_sequence;
static int			fallback_enforcing;
static int			fallback_policyload;

/*
 * read_sequence
 *
 * A utility routine to reference kernel status page according to
 * seqlock logic. Since selinux_status->sequence is an odd value during
 * the kernel status page being updated, we try to synchronize completion
 * of this updating, but we assume it is rare.
 * The sequence is almost even number.
 *
 * __sync_synchronize is a portable memory barrier for various kind
 * of architecture that is supported by GCC.
 */
static inline uint32_t read_sequence(struct selinux_status_t *status)
{
	uint32_t	seqno = 0;

	do {
		/*
		 * No need for sched_yield() in the first trial of
		 * this loop.
		 */
		if (seqno & 0x0001)
			sched_yield();

		seqno = status->sequence;

		__sync_synchronize();

	} while (seqno & 0x0001);

	return seqno;
}

/*
 * selinux_status_updated
 *
 * It returns whether something has been happened since the last call.
 * Because `selinux_status->sequence' shall be always incremented on
 * both of setenforce/policyreload events, so differences from the last
 * value informs us something has been happened.
 */
int selinux_status_updated(void)
{
        return 0;
}

/*
 * selinux_status_getenforce
 *
 * It returns the current performing mode of SELinux.
 * 1 means currently we run in enforcing mode, or 0 means permissive mode.
 */
int selinux_status_getenforce(void)
{
        return 0;
}

/*
 * selinux_status_policyload
 *
 * It returns times of policy reloaded on the running system.
 * Note that it is not a reliable value on fallback-mode until it receives
 * the first event message via netlink socket, so, a correct usage of this
 * value is to compare it with the previous value to detect policy reloaded
 * event.
 */
int selinux_status_policyload(void)
{
        return 0;
}

/*
 * selinux_status_deny_unknown
 *
 * It returns a guideline to handle undefined object classes or permissions.
 * 0 means SELinux treats policy queries on undefined stuff being allowed,
 * however, 1 means such queries are denied.
 */
int selinux_status_deny_unknown(void)
{
        return 0;
}

/*
 * callback routines for fallback case using netlink socket
 */
static int fallback_cb_setenforce(int enforcing)
{
	fallback_sequence += 2;
	fallback_enforcing = enforcing;

	return 0;
}

static int fallback_cb_policyload(int policyload)
{
	fallback_sequence += 2;
	fallback_policyload = policyload;

	return 0;
}

/*
 * selinux_status_open
 *
 * It tries to open and mmap kernel status page (/selinux/status).
 * Since Linux 2.6.37 or later supports this feature, we may run
 * fallback routine using a netlink socket on older kernels, if
 * the supplied `fallback' is not zero.
 * It returns 0 on success, or -1 on error.
 */
int selinux_status_open(int fallback)
{
        return 0;
}

/*
 * selinux_status_close
 *
 * It unmap and close the kernel status page, or close netlink socket
 * if fallback mode.
 */
void selinux_status_close(void)
{
}
