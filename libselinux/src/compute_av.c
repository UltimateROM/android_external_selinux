#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "selinux_internal.h"
#include "policy.h"
#include "mapping.h"

int security_compute_av_flags_raw(const char * scon,
				  const char * tcon,
				  security_class_t tclass,
				  access_vector_t requested,
				  struct av_decision *avd)
{
        return 0;
}

hidden_def(security_compute_av_flags_raw)

int security_compute_av_raw(const char * scon,
			    const char * tcon,
			    security_class_t tclass,
			    access_vector_t requested,
			    struct av_decision *avd)
{
        return 0;
}

hidden_def(security_compute_av_raw)

int security_compute_av_flags(const char * scon,
			      const char * tcon,
			      security_class_t tclass,
			      access_vector_t requested,
			      struct av_decision *avd)
{
        return 0;
}

hidden_def(security_compute_av_flags)

int security_compute_av(const char * scon,
			const char * tcon,
			security_class_t tclass,
			access_vector_t requested, struct av_decision *avd)
{
        return 0;
}

hidden_def(security_compute_av)
