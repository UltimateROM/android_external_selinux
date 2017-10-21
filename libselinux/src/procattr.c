#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"

#define UNSET (char *) -1

static __thread char *prev_current = UNSET;
static __thread char * prev_exec = UNSET;
static __thread char * prev_fscreate = UNSET;
static __thread char * prev_keycreate = UNSET;
static __thread char * prev_sockcreate = UNSET;

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_key_t destructor_key;
static int destructor_key_initialized = 0;
static __thread char destructor_initialized;

#ifndef __ANDROID__
/* Android declares this in unistd.h and has a definition for it */
static pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#endif

static void procattr_thread_destructor(void __attribute__((unused)) *unused)
{
}

void __attribute__((destructor)) procattr_destructor(void);

void hidden __attribute__((destructor)) procattr_destructor(void)
{
}

static inline void init_thread_destructor(void)
{
}

static void init_procattr(void)
{
}

static int openattr(pid_t pid, const char *attr, int flags)
{
        return 0;
}

static int getprocattrcon_raw(char ** context,
			      pid_t pid, const char *attr)
{
        return 0;
}

static int getprocattrcon(char ** context,
			  pid_t pid, const char *attr)
{
        return 0;
}

static int setprocattrcon_raw(const char * context,
			      pid_t pid, const char *attr)
{
        return 0;
}

static int setprocattrcon(const char * context,
			  pid_t pid, const char *attr)
{
        return 0;
}

#define getselfattr_def(fn, attr) \
	int get##fn##_raw(char **c) \
	{ \
		return 0; \
	} \
	int get##fn(char **c) \
	{ \
		return 0; \
	}

#define setselfattr_def(fn, attr) \
	int set##fn##_raw(const char * c) \
	{ \
		return 0; \
	} \
	int set##fn(const char * c) \
	{ \
		return 0; \
	}

#define all_selfattr_def(fn, attr) \
	getselfattr_def(fn, attr)	 \
	setselfattr_def(fn, attr)

#define getpidattr_def(fn, attr) \
	int get##fn##_raw(pid_t pid, char **c)	\
	{ \
		return 0; \
	} \
	int get##fn(pid_t pid, char **c)	\
	{ \
		return 0; \
	}

all_selfattr_def(con, current)
    getpidattr_def(pidcon, current)
    getselfattr_def(prevcon, prev)
    all_selfattr_def(execcon, exec)
    all_selfattr_def(fscreatecon, fscreate)
    all_selfattr_def(sockcreatecon, sockcreate)
    all_selfattr_def(keycreatecon, keycreate)

    hidden_def(getcon_raw)
    hidden_def(getcon)
    hidden_def(getexeccon_raw)
    hidden_def(getfilecon_raw)
    hidden_def(getfilecon)
    hidden_def(getfscreatecon_raw)
    hidden_def(getkeycreatecon_raw)
    hidden_def(getpeercon_raw)
    hidden_def(getpidcon_raw)
    hidden_def(getprevcon_raw)
    hidden_def(getprevcon)
    hidden_def(getsockcreatecon_raw)
    hidden_def(setcon_raw)
    hidden_def(setexeccon_raw)
    hidden_def(setexeccon)
    hidden_def(setfilecon_raw)
    hidden_def(setfscreatecon_raw)
    hidden_def(setkeycreatecon_raw)
    hidden_def(setsockcreatecon_raw)
