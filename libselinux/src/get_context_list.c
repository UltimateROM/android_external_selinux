#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include "selinux_internal.h"
#include "context_internal.h"
#include "get_context_list_internal.h"

int get_default_context_with_role(const char *user,
				  const char *role,
				  char * fromcon,
				  char ** newcon)
{
        return 0;
}

hidden_def(get_default_context_with_role)

int get_default_context_with_rolelevel(const char *user,
				       const char *role,
				       const char *level,
				       char * fromcon,
				       char ** newcon)
{
        return 0;
}

int get_default_context(const char *user,
			char * fromcon, char ** newcon)
{
        return 0;
}

static int find_partialcon(char ** list,
			   unsigned int nreach, char *part)
{
        return 0;
}

static int get_context_order(FILE * fp,
			     char * fromcon,
			     char ** reachable,
			     unsigned int nreach,
			     unsigned int *ordering, unsigned int *nordered)
{
        return 0;
}

static int get_failsafe_context(const char *user, char ** newcon)
{
        return 0;
}

struct context_order {
	char * con;
	unsigned int order;
};

static int order_compare(const void *A, const void *B)
{
        return 0;
}

int get_ordered_context_list_with_level(const char *user,
					const char *level,
					char * fromcon,
					char *** list)
{
        return 0;
}

hidden_def(get_ordered_context_list_with_level)

int get_default_context_with_level(const char *user,
				   const char *level,
				   char * fromcon,
				   char ** newcon)
{
	return 0;
}

int get_ordered_context_list(const char *user,
			     char * fromcon,
			     char *** list)
{
        return 0;
}

hidden_def(get_ordered_context_list)
