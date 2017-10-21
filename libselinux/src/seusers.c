#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <ctype.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include "selinux_internal.h"

/* Process line from seusers.conf and split into its fields.
   Returns 0 on success, -1 on comments, and -2 on error. */
static int process_seusers(const char *buffer,
			   char **luserp,
			   char **seuserp, char **levelp, int mls_enabled)
{
	char *newbuf = strdup(buffer);
	char *luser = NULL, *seuser = NULL, *level = NULL;
	char *start, *end;
	int mls_found = 1;

	if (!newbuf)
		goto err;

	start = newbuf;
	while (isspace(*start))
		start++;
	if (*start == '#' || *start == 0) {
		free(newbuf);
		return -1;	/* Comment or empty line, skip over */
	}
	end = strchr(start, ':');
	if (!end)
		goto err;
	*end = 0;

	luser = strdup(start);
	if (!luser)
		goto err;

	start = end + 1;
	end = strchr(start, ':');
	if (!end) {
		mls_found = 0;

		end = start;
		while (*end && !isspace(*end))
			end++;
	}
	*end = 0;

	seuser = strdup(start);
	if (!seuser)
		goto err;

	if (!strcmp(seuser, ""))
		goto err;

	/* Skip MLS if disabled, or missing. */
	if (!mls_enabled || !mls_found)
		goto out;

	start = ++end;
	while (*end && !isspace(*end))
		end++;
	*end = 0;

	level = strdup(start);
	if (!level)
		goto err;

	if (!strcmp(level, ""))
		goto err;

      out:
	free(newbuf);
	*luserp = luser;
	*seuserp = seuser;
	*levelp = level;
	return 0;
      err:
	free(newbuf);
	free(luser);
	free(seuser);
	free(level);
	return -2;		/* error */
}

int require_seusers hidden = 0;

#include <pwd.h>
#include <grp.h>

static gid_t get_default_gid(const char *name) {
	struct passwd pwstorage, *pwent = NULL;
	gid_t gid = -1;
	/* Allocate space for the getpwnam_r buffer */
	long rbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (rbuflen <= 0) return -1;
	char *rbuf = malloc(rbuflen);
	if (rbuf == NULL) return -1;

	int retval = getpwnam_r(name, &pwstorage, rbuf, rbuflen, &pwent);
	if (retval == 0 && pwent) {
		gid = pwent->pw_gid;
	}
	free(rbuf);
	return gid;
}

static int check_group(const char *group, const char *name, const gid_t gid) {
	int match = 0;
	int i, ng = 0;
	gid_t *groups = NULL;
	struct group gbuf, *grent = NULL;

	long rbuflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (rbuflen <= 0)
		return 0;
	char *rbuf;

	while(1) {
		rbuf = malloc(rbuflen);
		if (rbuf == NULL)
			return 0;
		int retval = getgrnam_r(group, &gbuf, rbuf, 
				rbuflen, &grent);
		if ( retval == ERANGE )
		{
			free(rbuf);
			rbuflen = rbuflen * 2;
		} else if ( retval != 0 || grent == NULL )
		{
			goto done;
		} else
		{
			break;
		}
	}

	if (getgrouplist(name, gid, NULL, &ng) < 0) {
		if (ng == 0)
			goto done;
		groups = calloc(ng, sizeof(*groups));
		if (!groups)
			goto done;
		if (getgrouplist(name, gid, groups, &ng) < 0)
			goto done;
	} else {
		/* WTF?  ng was 0 and we didn't fail? Are we in 0 groups? */
		goto done;
	}

	for (i = 0; i < ng; i++) {
		if (grent->gr_gid == groups[i]) {
			match = 1;
			goto done;
		}
	}

 done:
	free(groups);
	free(rbuf);
	return match;
}

int getseuserbyname(const char *name, char **r_seuser, char **r_level)
{
	return 0;
}

int getseuser(const char *username, const char *service, 
	      char **r_seuser, char **r_level) {
	return 0;
}
