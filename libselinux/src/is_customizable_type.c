#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <limits.h>
#include "selinux_internal.h"
#include "context_internal.h"

static int get_customizable_type_list(char *** retlist)
{
	return 0;
}

static char **customizable_list = NULL;

int is_context_customizable(const char * scontext)
{
	return 0;
}
