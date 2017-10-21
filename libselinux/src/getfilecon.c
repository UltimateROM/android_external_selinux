#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "policy.h"

int getfilecon_raw(const char *path, char ** context)
{
	return 0;
}

hidden_def(getfilecon_raw)

int getfilecon(const char *path, char ** context)
{
        return 0;
}

hidden_def(getfilecon)
