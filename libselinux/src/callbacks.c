/*
 * User-supplied callbacks and default implementations.
 * Class and permission mappings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <selinux/selinux.h>
#include "callbacks.h"

/* default implementations */
static int __attribute__ ((format(printf, 2, 3)))
default_selinux_log(int type __attribute__((unused)), const char *fmt, ...)
{
	return 0;
}

static int
default_selinux_audit(void *ptr __attribute__((unused)),
		      security_class_t cls __attribute__((unused)),
		      char *buf __attribute__((unused)),
		      size_t len __attribute__((unused)))
{
	return 0;
}

static int
default_selinux_validate(char **ctx)
{
#ifndef BUILD_HOST
	return security_check_context(*ctx);
#else
	(void) ctx;
	return 0;
#endif
}

static int
default_selinux_setenforce(int enforcing __attribute__((unused)))
{
	return 0;
}

static int
default_selinux_policyload(int seqno __attribute__((unused)))
{
	return 0;
}

/* callback pointers */
int __attribute__ ((format(printf, 2, 3)))
(*selinux_log)(int, const char *, ...) =
	default_selinux_log;

int
(*selinux_audit) (void *, security_class_t, char *, size_t) =
	default_selinux_audit;

int
(*selinux_validate)(char **ctx) =
	default_selinux_validate;

int
(*selinux_netlink_setenforce) (int enforcing) =
	default_selinux_setenforce;

int
(*selinux_netlink_policyload) (int seqno) =
	default_selinux_policyload;

/* callback setting function */
void
selinux_set_callback(int type, union selinux_callback cb)
{
}

/* callback getting function */
union selinux_callback
selinux_get_callback(int type)
{
	union selinux_callback cb;
        cb.func_log = NULL;
        cb.func_audit = NULL;
        cb.func_validate = NULL;
        cb.func_setenforce = NULL;
        cb.func_policyload = NULL;
	return cb;
}
