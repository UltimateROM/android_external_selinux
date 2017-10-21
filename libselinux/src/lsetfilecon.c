#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int lsetfilecon_raw(const char *path, const char * context)
{
        return 0;
}

hidden_def(lsetfilecon_raw)

int lsetfilecon(const char *path, const char *context)
{
        return 0;
}
