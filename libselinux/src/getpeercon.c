#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include "selinux_internal.h"
#include "policy.h"

#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif

int getpeercon_raw(int fd, char ** context)
{
        return 0;
}

hidden_def(getpeercon_raw)

int getpeercon(int fd, char ** context)
{
        return 0;
}
