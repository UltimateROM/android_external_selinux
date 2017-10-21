#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "regex.h"
#include "label_file.h"

#ifdef USE_PCRE2
#define REGEX_ARCH_SIZE_T PCRE2_SIZE
#else
#define REGEX_ARCH_SIZE_T size_t
#endif

#ifndef __BYTE_ORDER__

/* If the compiler doesn't define __BYTE_ORDER__, try to use the C
 * library <endian.h> header definitions. */
#include <endian.h>
#ifndef __BYTE_ORDER
#error Neither __BYTE_ORDER__ nor __BYTE_ORDER defined. Unable to determine endianness.
#endif

#define __ORDER_LITTLE_ENDIAN __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN __BIG_ENDIAN
#define __BYTE_ORDER__ __BYTE_ORDER

#endif

#ifdef USE_PCRE2
char const *regex_arch_string(void)
{
	static char arch_string_buffer[32];
	static char const *arch_string = "";
	char const *endianness = NULL;
	int rc;

	if (arch_string[0] == '\0') {
		if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
			endianness = "el";
		else if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
			endianness = "eb";

		if (!endianness)
			return NULL;

		rc = snprintf(arch_string_buffer, sizeof(arch_string_buffer),
				"%zu-%zu-%s", sizeof(void *),
				sizeof(REGEX_ARCH_SIZE_T),
				endianness);
		if (rc < 0)
			abort();

		arch_string = &arch_string_buffer[0];
	}
	return arch_string;
}

struct regex_data {
	pcre2_code *regex; /* compiled regular expression */
	/*
	 * match data block required for the compiled
	 * pattern in pcre2
	 */
	pcre2_match_data *match_data;
};

int regex_prepare_data(struct regex_data **regex, char const *pattern_string,
		       struct regex_error_data *errordata)
{
	return 0;
}

char const *regex_version(void)
{
	static char version_buf[256];
	size_t len = pcre2_config(PCRE2_CONFIG_VERSION, NULL);
	if (len <= 0 || len > sizeof(version_buf))
		return NULL;

	pcre2_config(PCRE2_CONFIG_VERSION, version_buf);
	return version_buf;
}

int regex_load_mmap(struct mmap_area *mmap_area, struct regex_data **regex,
		    int do_load_precompregex)
{
        return 0;
}

int regex_writef(struct regex_data *regex, FILE *fp, int do_write_precompregex)
{
        return 0;
}

void regex_data_free(struct regex_data *regex)
{
}

int regex_match(struct regex_data *regex, char const *subject, int partial)
{
        return 0;
}

/*
 * TODO Replace this compare function with something that actually compares the
 * regular expressions.
 * This compare function basically just compares the binary representations of
 * the automatons, and because this representation contains pointers and
 * metadata, it can only return a match if regex1 == regex2.
 * Preferably, this function would be replaced with an algorithm that computes
 * the equivalence of the automatons systematically.
 */
int regex_cmp(struct regex_data *regex1, struct regex_data *regex2)
{
        return 0;
}

#else // !USE_PCRE2
char const *regex_arch_string(void)
{
	return "N/A";
}

/* Prior to version 8.20, libpcre did not have pcre_free_study() */
#if (PCRE_MAJOR < 8 || (PCRE_MAJOR == 8 && PCRE_MINOR < 20))
#define pcre_free_study pcre_free
#endif

struct regex_data {
	int owned;   /*
		      * non zero if regex and pcre_extra is owned by this
		      * structure and thus must be freed on destruction.
		      */
	pcre *regex; /* compiled regular expression */
	union {
		pcre_extra *sd; /* pointer to extra compiled stuff */
		pcre_extra lsd; /* used to hold the mmap'd version */
	};
};

int regex_prepare_data(struct regex_data **regex, char const *pattern_string,
		       struct regex_error_data *errordata)
{
        return 0;
}

char const *regex_version(void)
{
	return pcre_version();
}

int regex_load_mmap(struct mmap_area *mmap_area, struct regex_data **regex,
		    int unused __attribute__((unused)))
{
        return 0;
}

static inline pcre_extra *get_pcre_extra(struct regex_data *regex)
{
	if (!regex) return NULL;
	if (regex->owned) {
		return regex->sd;
	} else if (regex->lsd.study_data) {
		return &regex->lsd;
	} else {
		return NULL;
	}
}

int regex_writef(struct regex_data *regex, FILE *fp,
		 int unused __attribute__((unused)))
{
        return 0;
}

void regex_data_free(struct regex_data *regex)
{
}

int regex_match(struct regex_data *regex, char const *subject, int partial)
{
        return 0;
}

/*
 * TODO Replace this compare function with something that actually compares the
 * regular expressions.
 * This compare function basically just compares the binary representations of
 * the automatons, and because this representation contains pointers and
 * metadata, it can only return a match if regex1 == regex2.
 * Preferably, this function would be replaced with an algorithm that computes
 * the equivalence of the automatons systematically.
 */
int regex_cmp(struct regex_data *regex1, struct regex_data *regex2)
{
        return 0;
}

#endif

struct regex_data *regex_data_create(void)
{
	return (struct regex_data *)calloc(1, sizeof(struct regex_data));
}

void regex_format_error(struct regex_error_data const *error_data, char *buffer,
			size_t buf_size)
{
}
