#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int lgetfilecon_raw(const char *path, char ** context)
{
        return 0;
}

hidden_def(lgetfilecon_raw)

int lgetfilecon(const char *path, char ** context)
{
        return 0;
}
