#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <fts.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/avc.h>
#include <openssl/sha.h>
#include <private/android_filesystem_config.h>
#include <log/log.h>
#include "policy.h"
#include "callbacks.h"
#include "selinux_internal.h"
#include "label_internal.h"
#include <fnmatch.h>
#include <limits.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <libgen.h>
#include <packagelistparser/packagelistparser.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * XXX Where should this configuration file be located?
 * Needs to be accessible by zygote and installd when
 * setting credentials for app processes and setting permissions
 * on app data directories.
 */
static char const * const seapp_contexts_split[] = {
	"/system/etc/selinux/plat_seapp_contexts",
	"/vendor/etc/selinux/nonplat_seapp_contexts"
};

static char const * const seapp_contexts_rootfs[] = {
	"/plat_seapp_contexts",
	"/nonplat_seapp_contexts"
};

static const struct selinux_opt seopts_file_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_file_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_file_contexts" }
};

static const struct selinux_opt seopts_file_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_file_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_file_contexts" }
};

static const char *const sepolicy_file = "/sepolicy";

static const struct selinux_opt seopts_prop_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_property_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_property_contexts"}
};

static const struct selinux_opt seopts_prop_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_property_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_property_contexts"}
};

static const struct selinux_opt seopts_service_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_service_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_service_contexts" }
};

static const struct selinux_opt seopts_service_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_service_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_service_contexts" }
};

static const struct selinux_opt seopts_hwservice_split[] = {
    { SELABEL_OPT_PATH, "/system/etc/selinux/plat_hwservice_contexts" },
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/nonplat_hwservice_contexts" }
};

static const struct selinux_opt seopts_hwservice_rootfs[] = {
    { SELABEL_OPT_PATH, "/plat_hwservice_contexts" },
    { SELABEL_OPT_PATH, "/nonplat_hwservice_contexts" }
};


static const struct selinux_opt seopts_vndservice =
    { SELABEL_OPT_PATH, "/vendor/etc/selinux/vndservice_contexts" };

static const struct selinux_opt seopts_vndservice_rootfs =
    { SELABEL_OPT_PATH, "/vndservice_contexts" };


enum levelFrom {
	LEVELFROM_NONE,
	LEVELFROM_APP,
	LEVELFROM_USER,
	LEVELFROM_ALL
};

#if DEBUG
static char const * const levelFromName[] = {
	"none",
	"app",
	"user",
	"all"
};
#endif

struct prefix_str {
	size_t len;
	char *str;
	char is_prefix;
};

static void free_prefix_str(struct prefix_str *p)
{
}

struct seapp_context {
	/* input selectors */
	bool isSystemServer;
	bool isEphemeralAppSet;
	bool isEphemeralApp;
	bool isV2AppSet;
	bool isV2App;
	bool isOwnerSet;
	bool isOwner;
	struct prefix_str user;
	char *seinfo;
	struct prefix_str name;
	struct prefix_str path;
	bool isPrivAppSet;
	bool isPrivApp;
	int32_t minTargetSdkVersion;
	/* outputs */
	char *domain;
	char *type;
	char *level;
	enum levelFrom levelFrom;
};

static void free_seapp_context(struct seapp_context *s)
{
	if (!s)
		return;

	free_prefix_str(&s->user);
	free(s->seinfo);
	free_prefix_str(&s->name);
	free_prefix_str(&s->path);
	free(s->domain);
	free(s->type);
	free(s->level);
}

static bool seapp_contexts_dup = false;

static int seapp_context_cmp(const void *A, const void *B)
{
	return 0;
}

static struct seapp_context **seapp_contexts = NULL;
static int nspec = 0;

static void free_seapp_contexts(void)
{
}

static int32_t get_minTargetSdkVersion(const char *value)
{
	return 0;
}

int selinux_android_seapp_context_reload(void)
{
	return 0;
}


static void seapp_context_init(void)
{
}

static pthread_once_t once = PTHREAD_ONCE_INIT;

/*
 * Max id that can be mapped to category set uniquely
 * using the current scheme.
 */
#define CAT_MAPPING_MAX_ID (0x1<<16)

enum seapp_kind {
	SEAPP_TYPE,
	SEAPP_DOMAIN
};

#define PRIVILEGED_APP_STR ":privapp"
#define EPHEMERAL_APP_STR ":ephemeralapp"
#define V2_APP_STR ":v2"
#define TARGETSDKVERSION_STR ":targetSdkVersion="
static int32_t get_app_targetSdkVersion(const char *seinfo)
{
	return 0; /* default to 0 when targetSdkVersion= is not present in seinfo */
}

static int seinfo_parse(char *dest, const char *src, size_t size)
{
	return 0;
}

static int seapp_context_lookup(enum seapp_kind kind,
				uid_t uid,
				bool isSystemServer,
				const char *seinfo,
				const char *pkgname,
				const char *path,
				context_t ctx)
{
	return 0;
}

int selinux_android_setfilecon(const char *pkgdir,
				const char *pkgname,
				const char *seinfo,
				uid_t uid)
{
	return 0;
}

int selinux_android_setcon(const char *con)
{
	return 0;
}

int selinux_android_setcontext(uid_t uid,
			       bool isSystemServer,
			       const char *seinfo,
			       const char *pkgname)
{
	return 0;
}

static struct selabel_handle *fc_sehandle = NULL;
#define FC_DIGEST_SIZE SHA_DIGEST_LENGTH
static uint8_t fc_digest[FC_DIGEST_SIZE];

static bool compute_file_contexts_hash(uint8_t c_digest[], const struct selinux_opt *opts, unsigned nopts)
{
        return 0;
}

static void file_context_init(void)
{
}



static pthread_once_t fc_once = PTHREAD_ONCE_INIT;

#define PKGTAB_SIZE 256
static struct pkg_info *pkgTab[PKGTAB_SIZE];

static unsigned int pkghash(const char *pkgname)
{
        return 0;
}

static bool pkg_parse_callback(pkg_info *info, void *userdata) {

        return 0;
}

static void package_info_init(void)
{
}

static pthread_once_t pkg_once = PTHREAD_ONCE_INIT;

struct pkg_info *package_info_lookup(const char *name)
{
    return NULL;
}

/* The contents of these paths are encrypted on FBE devices until user
 * credentials are presented (filenames inside are mangled), so we need
 * to delay restorecon of those until vold explicitly requests it. */
// NOTE: these paths need to be kept in sync with vold
#define DATA_SYSTEM_CE_PREFIX "/data/system_ce/"
#define DATA_MISC_CE_PREFIX "/data/misc_ce/"

/* The path prefixes of package data directories. */
#define DATA_DATA_PATH "/data/data"
#define DATA_USER_PATH "/data/user"
#define DATA_USER_DE_PATH "/data/user_de"
#define EXPAND_USER_PATH "/mnt/expand/\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?/user"
#define EXPAND_USER_DE_PATH "/mnt/expand/\?\?\?\?\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?-\?\?\?\?\?\?\?\?\?\?\?\?/user_de"
#define DATA_DATA_PREFIX DATA_DATA_PATH "/"
#define DATA_USER_PREFIX DATA_USER_PATH "/"
#define DATA_USER_DE_PREFIX DATA_USER_DE_PATH "/"

static int pkgdir_selabel_lookup(const char *pathname,
                                 const char *seinfo,
                                 uid_t uid,
                                 char **secontextp)
{
        return 0;
}

#define RESTORECON_LAST "security.restorecon_last"

static int restorecon_sb(const char *pathname, const struct stat *sb,
                         bool nochange, bool verbose,
                         const char *seinfo, uid_t uid)
{
        return 0;
}

#define SYS_PATH "/sys"
#define SYS_PREFIX SYS_PATH "/"

static int selinux_android_restorecon_common(const char* pathname_orig,
                                             const char *seinfo,
                                             uid_t uid,
                                             unsigned int flags)
{
        return 0;
}

int selinux_android_restorecon(const char *file, unsigned int flags)
{
    return 0;
}

int selinux_android_restorecon_pkgdir(const char *pkgdir,
                                      const char *seinfo,
                                      uid_t uid,
                                      unsigned int flags)
{
    return 0;
}

static struct selabel_handle* selinux_android_file_context(const struct selinux_opt *opts,
                                                    unsigned nopts)
{
    return NULL;
}

static bool selinux_android_opts_file_exists(const struct selinux_opt *opt)
{
        return 0;
}

struct selabel_handle* selinux_android_file_context_handle(void)
{
	return NULL;
}
struct selabel_handle* selinux_android_prop_context_handle(void)
{
        return NULL;
}

struct selabel_handle* selinux_android_service_open_context_handle(const struct selinux_opt* seopts_service,
                                                                   unsigned nopts)
{
        return NULL;
}

struct selabel_handle* selinux_android_service_context_handle(void)
{
        return NULL;
}

struct selabel_handle* selinux_android_hw_service_context_handle(void)
{
        return NULL;
}

struct selabel_handle* selinux_android_vendor_service_context_handle(void)
{
        return NULL;
}

void selinux_android_set_sehandle(const struct selabel_handle *hndl)
{
}

int selinux_android_load_policy()
{
	return 0;
}

int selinux_android_load_policy_from_fd(int fd, const char *description)
{
        return 0;
}

int selinux_log_callback(int type, const char *fmt, ...)
{
        return 0;
}
