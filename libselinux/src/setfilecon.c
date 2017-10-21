#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int setfilecon_raw(const char *path, const char * context)
{
        return 0;
}

hidden_def(setfilecon_raw)

int setfilecon(const char *path, const char *context)
{
        return 0;
}
