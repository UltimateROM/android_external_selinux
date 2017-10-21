/*
 * Implementation of the userspace access vector cache (AVC).
 *
 * Author : Eamon Walsh <ewalsh@epoch.ncsc.mil>
 *
 * Derived from the kernel AVC implementation by
 * Stephen Smalley <sds@epoch.ncsc.mil> and 
 * James Morris <jmorris@redhat.com>.
 */
#include <selinux/avc.h>
#include "selinux_internal.h"
#include <assert.h>
#include "avc_sidtab.h"
#include "avc_internal.h"

#define AVC_CACHE_SLOTS		512
#define AVC_CACHE_MAXNODES	410

struct avc_entry {
	security_id_t ssid;
	security_id_t tsid;
	security_class_t tclass;
	struct av_decision avd;
	security_id_t	create_sid;
	int used;		/* used recently */
};

struct avc_node {
	struct avc_entry ae;
	struct avc_node *next;
};

struct avc_cache {
	struct avc_node *slots[AVC_CACHE_SLOTS];
	uint32_t lru_hint;	/* LRU hint for reclaim scan */
	uint32_t active_nodes;
	uint32_t latest_notif;	/* latest revocation notification */
};

struct avc_callback_node {
	int (*callback) (uint32_t event, security_id_t ssid,
			 security_id_t tsid,
			 security_class_t tclass, access_vector_t perms,
			 access_vector_t * out_retained);
	uint32_t events;
	security_id_t ssid;
	security_id_t tsid;
	security_class_t tclass;
	access_vector_t perms;
	struct avc_callback_node *next;
};

static void *avc_netlink_thread = NULL;
static void *avc_lock = NULL;
static void *avc_log_lock = NULL;
static struct avc_node *avc_node_freelist = NULL;
static struct avc_cache avc_cache;
static char *avc_audit_buf = NULL;
static struct avc_cache_stats cache_stats;
static struct avc_callback_node *avc_callbacks = NULL;
static struct sidtab avc_sidtab;

static inline int avc_hash(security_id_t ssid,
			   security_id_t tsid, security_class_t tclass)
{
	return 0;
}

int avc_context_to_sid_raw(const char * ctx, security_id_t * sid)
{
	return 0;
}

int avc_context_to_sid(const char * ctx, security_id_t * sid)
{
        return 0;
}

int avc_sid_to_context_raw(security_id_t sid, char ** ctx)
{
        return 0;
}

int avc_sid_to_context(security_id_t sid, char ** ctx)
{
        return 0;
}

int sidget(security_id_t sid __attribute__((unused)))
{
	return 0;
}

int sidput(security_id_t sid __attribute__((unused)))
{
	return 0;
}

int avc_get_initial_sid(const char * name, security_id_t * sid)
{
        return 0;
}

int avc_open(struct selinux_opt *opts, unsigned nopts)
{
        return 0;
}

int avc_init(const char *prefix,
	     const struct avc_memory_callback *mem_cb,
	     const struct avc_log_callback *log_cb,
	     const struct avc_thread_callback *thread_cb,
	     const struct avc_lock_callback *lock_cb)
{
        return 0;
}

void avc_cache_stats(struct avc_cache_stats *p)
{
}

void avc_sid_stats(void)
{
}

void avc_av_stats(void)
{
}

hidden_def(avc_av_stats)

static inline struct avc_node *avc_reclaim_node(void)
{
	return NULL;
}

static inline void avc_clear_avc_entry(struct avc_entry *ae)
{
}

static inline struct avc_node *avc_claim_node(security_id_t ssid,
					      security_id_t tsid,
					      security_class_t tclass)
{
	return NULL;
}

static inline struct avc_node *avc_search_node(security_id_t ssid,
					       security_id_t tsid,
					       security_class_t tclass,
					       int *probes)
{
	return NULL;
}

/**
 * avc_lookup - Look up an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @aeref:  AVC entry reference
 *
 * Look up an AVC entry that is valid for the
 * @requested permissions between the SID pair
 * (@ssid, @tsid), interpreting the permissions
 * based on @tclass.  If a valid AVC entry exists,
 * then this function updates @aeref to refer to the
 * entry and returns %0.  Otherwise, -1 is returned.
 */
static int avc_lookup(security_id_t ssid, security_id_t tsid,
		      security_class_t tclass,
		      access_vector_t requested, struct avc_entry_ref *aeref)
{
	return 0;
}

/**
 * avc_insert - Insert an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @ae: AVC entry
 * @aeref:  AVC entry reference
 *
 * Insert an AVC entry for the SID pair
 * (@ssid, @tsid) and class @tclass.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av() call.  If the
 * sequence number @ae->avd.seqno is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry, updates
 * @aeref to refer to the entry, and returns %0.
 * Otherwise, this function returns -%1 with @errno set to %EAGAIN.
 */
static int avc_insert(security_id_t ssid, security_id_t tsid,
		      security_class_t tclass,
		      struct avc_entry *ae, struct avc_entry_ref *aeref)
{
	return 0;
}

void avc_cleanup(void)
{
}

hidden_def(avc_cleanup)

int avc_reset(void)
{
		return 0;
}

hidden_def(avc_reset)

void avc_destroy(void)
{
}

/* ratelimit stuff put aside for now --EFW */
#if 0
/*
 * Copied from net/core/utils.c:net_ratelimit and modified for
 * use by the AVC audit facility.
 */
#define AVC_MSG_COST	5*HZ
#define AVC_MSG_BURST	10*5*HZ

/*
 * This enforces a rate limit: not more than one kernel message
 * every 5secs to make a denial-of-service attack impossible.
 */
static int avc_ratelimit(void)
{
	static unsigned long toks = 10 * 5 * HZ;
	static unsigned long last_msg;
	static int missed, rc = 0;
	unsigned long now = jiffies;
	void *ratelimit_lock = avc_alloc_lock();

	avc_get_lock(ratelimit_lock);
	toks += now - last_msg;
	last_msg = now;
	if (toks > AVC_MSG_BURST)
		toks = AVC_MSG_BURST;
	if (toks >= AVC_MSG_COST) {
		int lost = missed;
		missed = 0;
		toks -= AVC_MSG_COST;
		avc_release_lock(ratelimit_lock);
		if (lost) {
			avc_log(SELINUX_WARNING,
				"%s:  %d messages suppressed.\n", avc_prefix,
				lost);
		}
		rc = 1;
		goto out;
	}
	missed++;
	avc_release_lock(ratelimit_lock);
      out:
	avc_free_lock(ratelimit_lock);
	return rc;
}

static inline int check_avc_ratelimit(void)
{
	if (avc_enforcing)
		return avc_ratelimit();
	else {
		/* If permissive, then never suppress messages. */
		return 1;
	}
}
#endif				/* ratelimit stuff */

/**
 * avc_dump_av - Display an access vector in human-readable form.
 * @tclass: target security class
 * @av: access vector
 */
static void avc_dump_av(security_class_t tclass, access_vector_t av)
{
}

/**
 * avc_dump_query - Display a SID pair and a class in human-readable form.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 */
static void avc_dump_query(security_id_t ssid, security_id_t tsid,
			   security_class_t tclass)
{
}

void avc_audit(security_id_t ssid, security_id_t tsid,
	       security_class_t tclass, access_vector_t requested,
	       struct av_decision *avd, int result, void *a)
{
}

hidden_def(avc_audit)


static void avd_init(struct av_decision *avd)
{
}

int avc_has_perm_noaudit(security_id_t ssid,
			 security_id_t tsid,
			 security_class_t tclass,
			 access_vector_t requested,
			 struct avc_entry_ref *aeref, struct av_decision *avd)
{
	return 0;
}

hidden_def(avc_has_perm_noaudit)

int avc_has_perm(security_id_t ssid, security_id_t tsid,
		 security_class_t tclass, access_vector_t requested,
		 struct avc_entry_ref *aeref, void *auditdata)
{
	return 0;
}

int avc_compute_create(security_id_t ssid,  security_id_t tsid,
		       security_class_t tclass, security_id_t *newsid)
{
	return 0;
}

int avc_compute_member(security_id_t ssid,  security_id_t tsid,
		       security_class_t tclass, security_id_t *newsid)
{
	return 0;
}

int avc_add_callback(int (*callback) (uint32_t event, security_id_t ssid,
				      security_id_t tsid,
				      security_class_t tclass,
				      access_vector_t perms,
				      access_vector_t * out_retained),
		     uint32_t events, security_id_t ssid,
		     security_id_t tsid,
		     security_class_t tclass, access_vector_t perms)
{
	return 0;
}

static inline int avc_sidcmp(security_id_t x, security_id_t y)
{
        return 0;
}

static inline void avc_update_node(uint32_t event, struct avc_node *node,
				   access_vector_t perms)
{
}

static int avc_update_cache(uint32_t event, security_id_t ssid,
			    security_id_t tsid, security_class_t tclass,
			    access_vector_t perms)
{
	return 0;
}

/* avc_control - update cache and call callbacks
 *
 * This should not be called directly; use the individual event
 * functions instead.
 */
static int avc_control(uint32_t event, security_id_t ssid,
		       security_id_t tsid, security_class_t tclass,
		       access_vector_t perms,
		       uint32_t seqno, access_vector_t * out_retained)
{
	return 0;
}

/**
 * avc_ss_grant - Grant previously denied permissions.
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions to grant
 * @seqno: policy sequence number
 */
int avc_ss_grant(security_id_t ssid, security_id_t tsid,
		 security_class_t tclass, access_vector_t perms,
		 uint32_t seqno)
{
	return 0;
}

/**
 * avc_ss_try_revoke - Try to revoke previously granted permissions.
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions to grant
 * @seqno: policy sequence number
 * @out_retained: subset of @perms that are retained
 *
 * Try to revoke previously granted permissions, but
 * only if they are not retained as migrated permissions.
 * Return the subset of permissions that are retained via @out_retained.
 */
int avc_ss_try_revoke(security_id_t ssid, security_id_t tsid,
		      security_class_t tclass,
		      access_vector_t perms, uint32_t seqno,
		      access_vector_t * out_retained)
{
        return 0;
}

/**
 * avc_ss_revoke - Revoke previously granted permissions.
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions to grant
 * @seqno: policy sequence number
 *
 * Revoke previously granted permissions, even if
 * they are retained as migrated permissions.
 */
int avc_ss_revoke(security_id_t ssid, security_id_t tsid,
		  security_class_t tclass, access_vector_t perms,
		  uint32_t seqno)
{
        return 0;
}

/**
 * avc_ss_reset - Flush the cache and revalidate migrated permissions.
 * @seqno: policy sequence number
 */
int avc_ss_reset(uint32_t seqno)
{
        return 0;
}

/**
 * avc_ss_set_auditallow - Enable or disable auditing of granted permissions.
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions to grant
 * @seqno: policy sequence number
 * @enable: enable flag.
 */
int avc_ss_set_auditallow(security_id_t ssid, security_id_t tsid,
			  security_class_t tclass, access_vector_t perms,
			  uint32_t seqno, uint32_t enable)
{
        return 0;
}

/**
 * avc_ss_set_auditdeny - Enable or disable auditing of denied permissions.
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions to grant
 * @seqno: policy sequence number
 * @enable: enable flag.
 */
int avc_ss_set_auditdeny(security_id_t ssid, security_id_t tsid,
			 security_class_t tclass, access_vector_t perms,
			 uint32_t seqno, uint32_t enable)
{
        return 0;
}
