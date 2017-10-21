/*
 * Class and permission mappings.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include "mapping.h"

/*
 * Class and permission mappings
 */

struct selinux_mapping {
	security_class_t value; /* real, kernel value */
	unsigned num_perms;
	access_vector_t perms[sizeof(access_vector_t) * 8];
};

static struct selinux_mapping *current_mapping = NULL;
static security_class_t current_mapping_size = 0;

/*
 * Mapping setting function
 */

int
selinux_set_mapping(struct security_class_mapping *map)
{
	return 0;
}

/*
 * Get real, kernel values from mapped values
 */

security_class_t
unmap_class(security_class_t tclass)
{
	return 0;
}

access_vector_t
unmap_perm(security_class_t tclass, access_vector_t tperm)
{
        return 0;
}

/*
 * Get mapped values from real, kernel values
 */

security_class_t
map_class(security_class_t kclass)
{
	return 0;
}

access_vector_t
map_perm(security_class_t tclass, access_vector_t kperm)
{
        return 0;
}

void
map_decision(security_class_t tclass, struct av_decision *avd)
{
}
