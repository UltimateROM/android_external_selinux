/*
 * Implementation of the userspace SID hashtable.
 *
 * Author : Eamon Walsh, <ewalsh@epoch.ncsc.mil>
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "selinux_internal.h"
#include <selinux/avc.h>
#include "avc_sidtab.h"
#include "avc_internal.h"

static inline unsigned sidtab_hash(const char * key)
{
        return 0;
}

int sidtab_init(struct sidtab *s)
{
        return 0;
}

int sidtab_insert(struct sidtab *s, const char * ctx)
{
	return 0;
}

int
sidtab_context_to_sid(struct sidtab *s,
		      const char * ctx, security_id_t * sid)
{
	return 0;
}

void sidtab_sid_stats(struct sidtab *h, char *buf, int buflen)
{
}

void sidtab_destroy(struct sidtab *s)
{
}
