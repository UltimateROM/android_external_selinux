#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int fgetfilecon_raw(int fd, char ** context)
{
	return 0;
}

hidden_def(fgetfilecon_raw)

int fgetfilecon(int fd, char ** context)
{
	return 0;
}
