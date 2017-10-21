/*
 * Callbacks for user-supplied memory allocation, supplemental
 * auditing, and locking routines.
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 *
 * Netlink code derived in part from sample code by
 * James Morris <jmorris@redhat.com>.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include "callbacks.h"
#include "selinux_netlink.h"
#include "avc_internal.h"

#ifndef NETLINK_SELINUX
#define NETLINK_SELINUX 7
#endif

/* callback pointers */
void *(*avc_func_malloc) (size_t) = NULL;
void (*avc_func_free) (void *) = NULL;

void (*avc_func_log) (const char *, ...) = NULL;
void (*avc_func_audit) (void *, security_class_t, char *, size_t) = NULL;

int avc_using_threads = 0;
int avc_app_main_loop = 0;
void *(*avc_func_create_thread) (void (*)(void)) = NULL;
void (*avc_func_stop_thread) (void *) = NULL;

void *(*avc_func_alloc_lock) (void) = NULL;
void (*avc_func_get_lock) (void *) = NULL;
void (*avc_func_release_lock) (void *) = NULL;
void (*avc_func_free_lock) (void *) = NULL;

/* message prefix string and avc enforcing mode */
char avc_prefix[AVC_PREFIX_SIZE] = "uavc";
int avc_running = 0;
int avc_enforcing = 1;
int avc_setenforce = 0;
int avc_netlink_trouble = 0;

/* netlink socket code */
static int fd = -1;

int avc_netlink_open(int blocking)
{
        return 0;
}

void avc_netlink_close(void)
{
}

static int avc_netlink_receive(void *buf, unsigned buflen, int blocking)
{
	return 0;
}

static int avc_netlink_process(void *buf)
{
	return 0;
}

int avc_netlink_check_nb(void)
{
        return 0;
}

/* run routine for the netlink listening thread */
void avc_netlink_loop(void)
{
}

int avc_netlink_acquire_fd(void)
{
        return 0;
}

void avc_netlink_release_fd(void)
{
}
