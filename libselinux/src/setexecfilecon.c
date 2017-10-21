#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include "context_internal.h"

int setexecfilecon(const char *filename, const char *fallback_type)
{
        return 0;
}

#ifndef DISABLE_RPM
int rpm_execcon(unsigned int verified __attribute__ ((unused)),
		const char *filename, char *const argv[], char *const envp[])
{
        return 0;
}
#endif
