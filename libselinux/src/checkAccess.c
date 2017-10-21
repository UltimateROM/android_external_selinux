/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include <selinux/avc.h>
#include "avc_internal.h"

static pthread_once_t once = PTHREAD_ONCE_INIT;
static int selinux_enabled;

static int avc_reset_callback(uint32_t event __attribute__((unused)),
		      security_id_t ssid __attribute__((unused)),
		      security_id_t tsid __attribute__((unused)),
		      security_class_t tclass __attribute__((unused)),
		      access_vector_t perms __attribute__((unused)),
		      access_vector_t *out_retained __attribute__((unused)))
{
	return 0;
}

static void avc_init_once(void)
{
}

int selinux_check_access(const char *scon, const char *tcon, const char *class, const char *perm, void *aux) {
		return 0;
}

int selinux_check_passwd_access(access_vector_t requested)
{
		return 0;
}

hidden_def(selinux_check_passwd_access)

int checkPasswdAccess(access_vector_t requested)
{
	return 0;
}
