#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

int security_canonicalize_context_raw(const char * con,
				      char ** canoncon)
{
        return 0;
}

hidden_def(security_canonicalize_context_raw)

int security_canonicalize_context(const char * con,
				      char ** canoncon)
{
        return 0;
}

hidden_def(security_canonicalize_context)
