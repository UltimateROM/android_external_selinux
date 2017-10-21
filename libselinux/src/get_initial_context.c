#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

#define SELINUX_INITCON_DIR "/initial_contexts/"

int security_get_initial_context_raw(const char * name, char ** con)
{
        return 0;
}

hidden_def(security_get_initial_context_raw)

int security_get_initial_context(const char * name, char ** con)
{
        return 0;
}

hidden_def(security_get_initial_context)
