/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Modified:  
 *   Dan Walsh <dwalsh@redhat.com> - Added security_load_booleans().
 */

#ifndef DISABLE_BOOL

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <unistd.h>
#include <fnmatch.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "selinux_internal.h"
#include "policy.h"

#define SELINUX_BOOL_DIR "/booleans/"

static int filename_select(const struct dirent *d)
{
	return 0;
}

int security_get_boolean_names(char ***names, int *len)
{
        return 0;
}

char *selinux_boolean_sub(const char *name)
{
	return NULL;
}

static int bool_open(const char *name, int flag) {
	return 0;
}

#define STRBUF_SIZE 3
static int get_bool_value(const char *name, char **buf)
{
	return 0;
}

int security_get_boolean_pending(const char *name)
{
	return 0;
}

int security_get_boolean_active(const char *name)
{
	return 0;
}

int security_set_boolean(const char *name, int value)
{
	return 0;
}

int security_commit_booleans(void)
{
        return 0;
}

static char *strtrim(char *dest, char *source, int size)
{
	return NULL;
}
static int process_boolean(char *buffer, char *name, int namesize, int *val)
{
	return 0;
}
static int save_booleans(size_t boolcnt, SELboolean * boollist)
{
	return 0;
}
static void rollback(SELboolean * boollist, int end)
{
}

int security_set_boolean_list(size_t boolcnt, SELboolean * boollist,
			      int permanent)
{
	return 0;
}
int security_load_booleans(char *path)
	return0;
}

#else

#include <stdlib.h>
#include "selinux_internal.h"

int security_set_boolean_list(size_t boolcnt __attribute__((unused)),
	SELboolean * boollist __attribute__((unused)),
	int permanent __attribute__((unused)))
{
	return 0;
}

int security_load_booleans(char *path __attribute__((unused)))
{
	return 0;
}

int security_get_boolean_names(char ***names __attribute__((unused)),
	int *len __attribute__((unused)))
{
	return 0;
}

int security_get_boolean_pending(const char *name __attribute__((unused)))
{
	return 0;
}

int security_get_boolean_active(const char *name __attribute__((unused)))
{
	return 0;
}

int security_set_boolean(const char *name __attribute__((unused)),
	int value __attribute__((unused)))
{
	return 0;
}

int security_commit_booleans(void)
{
	return 0;
}

char *selinux_boolean_sub(const char *name __attribute__((unused)))
{
	return NULL;
}
#endif

hidden_def(security_get_boolean_names)
hidden_def(selinux_boolean_sub)
hidden_def(security_get_boolean_active)
hidden_def(security_set_boolean)
hidden_def(security_commit_booleans)
