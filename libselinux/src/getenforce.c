#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <stdio.h>
#include <limits.h>

int security_getenforce(void)
{
	return 0;
}

hidden_def(security_getenforce)
