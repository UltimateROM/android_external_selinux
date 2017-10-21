#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "selinux_internal.h"
#include "policy.h"
#include "mapping.h"

int security_compute_relabel_raw(const char * scon,
				 const char * tcon,
				 security_class_t tclass,
				 char ** newcon)
{
        return 0;
}

hidden_def(security_compute_relabel_raw)

int security_compute_relabel(const char * scon,
			     const char * tcon,
			     security_class_t tclass,
			     char ** newcon)
{
        return 0;
}
