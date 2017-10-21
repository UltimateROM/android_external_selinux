#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "selinux_internal.h"
#include "label_internal.h"
#include "callbacks.h"
#include <limits.h>

static int (*myinvalidcon) (const char *p, unsigned l, char *c) = NULL;
static int (*mycanoncon) (const char *p, unsigned l, char **c) =  NULL;

static void
#ifdef __GNUC__
    __attribute__ ((format(printf, 1, 2)))
#endif
    default_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
#ifdef __GNUC__
    __attribute__ ((format(printf, 1, 2)))
#endif
    (*myprintf) (const char *fmt,...) = &default_printf;
int myprintf_compat = 0;

void set_matchpathcon_printf(void (*f) (const char *fmt, ...))
{
}

int compat_validate(struct selabel_handle *rec,
		    struct selabel_lookup_rec *contexts,
		    const char *path, unsigned lineno)
{
        return 0;
}

#ifndef BUILD_HOST

static __thread struct selabel_handle *hnd;

/*
 * An array for mapping integers to contexts
 */
static __thread char **con_array;
static __thread int con_array_size;
static __thread int con_array_used;

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t destructor_key;
static int destructor_key_initialized = 0;

static int add_array_elt(char *con)
{
	if (con_array_size) {
		while (con_array_used >= con_array_size) {
			con_array_size *= 2;
			con_array = (char **)realloc(con_array, sizeof(char*) *
						     con_array_size);
			if (!con_array) {
				con_array_size = con_array_used = 0;
				return -1;
			}
		}
	} else {
		con_array_size = 1000;
		con_array = (char **)malloc(sizeof(char*) * con_array_size);
		if (!con_array) {
			con_array_size = con_array_used = 0;
			return -1;
		}
	}

	con_array[con_array_used] = strdup(con);
	if (!con_array[con_array_used])
		return -1;
	return con_array_used++;
}

static void free_array_elts(void)
{
	con_array_size = con_array_used = 0;
	free(con_array);
	con_array = NULL;
}

void set_matchpathcon_invalidcon(int (*f) (const char *p, unsigned l, char *c))
{
}

static int default_canoncon(const char *path, unsigned lineno, char **context)
{
	char *tmpcon;
	if (security_canonicalize_context_raw(*context, &tmpcon) < 0) {
		if (errno == ENOENT)
			return 0;
		if (lineno)
			myprintf("%s:  line %u has invalid context %s\n", path,
				 lineno, *context);
		else
			myprintf("%s:  invalid context %s\n", path, *context);
		return 1;
	}
	free(*context);
	*context = tmpcon;
	return 0;
}

void set_matchpathcon_canoncon(int (*f) (const char *p, unsigned l, char **c))
{
}

static __thread struct selinux_opt options[SELABEL_NOPT];
static __thread int notrans;

void set_matchpathcon_flags(unsigned int flags)
{
}

/*
 * An association between an inode and a 
 * specification.  
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	int specind;		/* index of specification in spec */
	char *file;		/* full pathname for diagnostic messages about conflicts */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

/*
 * The hash table of associations, hashed by inode number.
 * Chaining is used for collisions, with elements ordered
 * by inode number in each bucket.  Each hash bucket has a dummy 
 * header.
 */
#define HASH_BITS 16
#define HASH_BUCKETS (1 << HASH_BITS)
#define HASH_MASK (HASH_BUCKETS-1)
static file_spec_t *fl_head;

/*
 * Try to add an association between an inode and
 * a specification.  If there is already an association
 * for the inode and it conflicts with this specification,
 * then use the specification that occurs later in the
 * specification array.
 */
int matchpathcon_filespec_add(ino_t ino, int specind, const char *file)
{
        return 0;
}

/*
 * Evaluate the association hash table distribution.
 */
void matchpathcon_filespec_eval(void)
{
}

/*
 * Destroy the association hash table.
 */
void matchpathcon_filespec_destroy(void)
{
}

static void matchpathcon_thread_destructor(void __attribute__((unused)) *ptr)
{
	matchpathcon_fini();
}

void __attribute__((destructor)) matchpathcon_lib_destructor(void);

void hidden __attribute__((destructor)) matchpathcon_lib_destructor(void)
{
}

static void matchpathcon_init_once(void)
{
	if (__selinux_key_create(&destructor_key, matchpathcon_thread_destructor) == 0)
		destructor_key_initialized = 1;
}

int matchpathcon_init_prefix(const char *path, const char *subset)
{
        return 0;
}

hidden_def(matchpathcon_init_prefix)

int matchpathcon_init(const char *path)
{
        return 0;
}

void matchpathcon_fini(void)
{
}

/*
 * We do not want to resolve a symlink to a real path if it is the final
 * component of the name.  Thus we split the pathname on the last "/" and
 * determine a real path component of the first portion.  We then have to
 * copy the last part back on to get the final real path.  Wheww.
 */
int realpath_not_final(const char *name, char *resolved_path)
{
        return 0;
}

int matchpathcon(const char *path, mode_t mode, char ** con)
{
        return 0;
}

int matchpathcon_index(const char *name, mode_t mode, char ** con)
{
        return 0;
}

void matchpathcon_checkmatches(char *str __attribute__((unused)))
{
}

/* Compare two contexts to see if their differences are "significant",
 * or whether the only difference is in the user. */
int selinux_file_context_cmp(const char * a,
			     const char * b)
{
        return 0;
}

int selinux_file_context_verify(const char *path, mode_t mode)
{
        return 0;
}

int selinux_lsetfilecon_default(const char *path)
{
        return 0;
}

#endif
