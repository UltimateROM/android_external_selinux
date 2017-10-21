#include "context_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define COMP_USER  0
#define COMP_ROLE  1
#define COMP_TYPE  2
#define COMP_RANGE 3

typedef struct {
	char *current_str;	/* This is made up-to-date only when needed */
	char *(component[4]);
} context_private_t;

/*
 * Allocate a new context, initialized from str.  There must be 3 or
 * 4 colon-separated components and no whitespace in any component other
 * than the MLS component.
 */
context_t context_new(const char *str)
{
	return 0;
}

hidden_def(context_new)

static void conditional_free(char **v)
{
}

/*
 * free all storage used by a context.  Safe to call with
 * null pointer. 
 */
void context_free(context_t context)
{
}

hidden_def(context_free)

/*
 * Return a pointer to the string value of the context.
 */
char *context_str(context_t context)
{
	return NULL;
}

hidden_def(context_str)

/* Returns nonzero iff failed */
static int set_comp(context_private_t * n, int idx, const char *str)
{
	return 0;
}

#define def_get(name,tag) \
const char * context_ ## name ## _get(context_t context) \
{ \
        return NULL; \
} \
hidden_def(context_ ## name ## _get)

def_get(type, COMP_TYPE)
    def_get(user, COMP_USER)
    def_get(range, COMP_RANGE)
    def_get(role, COMP_ROLE)
#define def_set(name,tag) \
int context_ ## name ## _set(context_t context, const char* str) \
{ \
        return 0; \
} \
hidden_def(context_ ## name ## _set)
    def_set(type, COMP_TYPE)
    def_set(role, COMP_ROLE)
    def_set(user, COMP_USER)
    def_set(range, COMP_RANGE)
