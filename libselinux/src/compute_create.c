#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include "selinux_internal.h"
#include "policy.h"
#include "mapping.h"

static int object_name_encode(const char *objname, char *buffer, size_t buflen)
{
        return 0;
}

int security_compute_create_name_raw(const char * scon,
				     const char * tcon,
				     security_class_t tclass,
				     const char *objname,
				     char ** newcon)
{
        return 0;
}
hidden_def(security_compute_create_name_raw)

int security_compute_create_raw(const char * scon,
				const char * tcon,
				security_class_t tclass,
				char ** newcon)
{
        return 0;
}
hidden_def(security_compute_create_raw)

int security_compute_create_name(const char * scon,
				 const char * tcon,
				 security_class_t tclass,
				 const char *objname,
				 char ** newcon)
{
        return 0;
}
hidden_def(security_compute_create_name)

int security_compute_create(const char * scon,
				const char * tcon,
			    security_class_t tclass,
				char ** newcon)
{
        return 0;
}
hidden_def(security_compute_create)
