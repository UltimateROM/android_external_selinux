#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <dlfcn.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <stdint.h>
#include <limits.h>

#include "dso.h"
#include "policy.h"
#include "selinux_internal.h"
#include "setrans_internal.h"

char *selinux_mnt = NULL;
int selinux_page_size = 0;

int has_selinux_config = 0;

/* Verify the mount point for selinux file system has a selinuxfs.
   If the file system:
   * Exist,
   * Is mounted with an selinux file system,
   * The file system is read/write
   * then set this as the default file system.
*/
static int verify_selinuxmnt(const char *mnt)
{
        return 0;
}

int selinuxfs_exists(void)
{
	return 0;
}
hidden_def(selinuxfs_exists)

static void init_selinuxmnt(void)
{
}

void fini_selinuxmnt(void)
{
}

hidden_def(fini_selinuxmnt)

void set_selinuxmnt(const char *mnt)
{
}

hidden_def(set_selinuxmnt)

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
}
