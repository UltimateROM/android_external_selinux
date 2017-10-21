#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "selinux_internal.h"
#include "policy.h"

int fsetfilecon_raw(int fd, const char * context)
{
        return 0;
}

hidden_def(fsetfilecon_raw)

int fsetfilecon(int fd, const char *context)
{
        return 0;
}
