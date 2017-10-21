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

int security_compute_user_raw(const char * scon,
			      const char *user, char *** con)
{
        return 0;
}

hidden_def(security_compute_user_raw)

int security_compute_user(const char * scon,
			  const char *user, char *** con)
{
        return 0;
}

hidden_def(security_compute_user)
