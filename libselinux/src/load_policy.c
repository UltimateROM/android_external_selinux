#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "selinux_internal.h"
#ifndef ANDROID
#include <sepol/sepol.h>
#include <sepol/policydb.h>
#endif
#include <dlfcn.h>
#include "policy.h"
#include <limits.h>

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

int security_load_policy(void *data, size_t len)
{
        return 0;
}

hidden_def(security_load_policy)

#ifndef ANDROID
int load_setlocaldefs hidden = 1;

#undef max
#define max(a, b) (((a) > (b)) ? (a) : (b))

int selinux_mkload_policy(int preservebools)
{
        return 0;
}

hidden_def(selinux_mkload_policy)

/*
 * Mount point for selinuxfs. 
 * This definition is private to the function below.
 * Everything else uses the location determined during 
 * libselinux startup via /proc/mounts (see init_selinuxmnt).  
 * We only need the hardcoded definition for the initial mount 
 * required for the initial policy load.
 */
int selinux_init_load_policy(int *enforce)
{
        return 0;
}
#endif
