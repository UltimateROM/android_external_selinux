#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include "policy.h"

int is_selinux_enabled(void)
{
	return 1;
}

hidden_def(is_selinux_enabled)

/*
 * Function: is_selinux_mls_enabled()
 * Return:   1 on success
 *	     0 on failure
 */
int is_selinux_mls_enabled(void)
{
	return 0;
}

hidden_def(is_selinux_mls_enabled)
