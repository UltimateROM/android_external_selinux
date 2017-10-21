#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

int security_check_context_raw(const char * con)
{
	return 0;
}

hidden_def(security_check_context_raw)

int security_check_context(const char * con)
{
        return 0;
}

hidden_def(security_check_context)
