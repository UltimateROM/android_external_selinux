#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "selinux_internal.h"
#include "context_internal.h"

int selinux_check_securetty_context(const char * tty_context)
{
        return 0;
}

hidden_def(selinux_check_securetty_context)
