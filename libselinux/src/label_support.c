/*
 * This file contains helper functions for labeling support.
 *
 * Author : Richard Haines <richard_c_haines@btinternet.com>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <errno.h>
#include "label_internal.h"

/*
 * Read an entry from a spec file (e.g. file_contexts)
 * entry - Buffer to allocate for the entry.
 * ptr - current location of the line to be processed.
 * returns  - 0 on success and *entry is set to be a null
 *            terminated value. On Error it returns -1 and
 *            errno will be set.
 *
 */
static inline int read_spec_entry(char **entry, char **ptr, int *len, const char **errbuf)
{
	*entry = NULL;
	char *tmp_buf = NULL;

	while (isspace(**ptr) && **ptr != '\0')
		(*ptr)++;

	tmp_buf = *ptr;
	*len = 0;

	while (!isspace(**ptr) && **ptr != '\0') {
		if (!isascii(**ptr)) {
			errno = EINVAL;
			*errbuf = "Non-ASCII characters found";
			return -1;
		}
		(*ptr)++;
		(*len)++;
	}

	if (*len) {
		*entry = strndup(tmp_buf, *len);
		if (!*entry)
			return -1;
	}

	return 0;
}

/*
 * line_buf - Buffer containing the spec entries .
 * errbuf   - Double pointer used for passing back specific error messages.
 * num_args - The number of spec parameter entries to process.
 * ...      - A 'char **spec_entry' for each parameter.
 * returns  - The number of items processed. On error, it returns -1 with errno
 *            set and may set errbuf to a specific error message.
 *
 * This function calls read_spec_entry() to do the actual string processing.
 * As such, can return anything from that function as well.
 */
int hidden read_spec_entries(char *line_buf, const char **errbuf, int num_args, ...)
{
        return 0;
}

/* Once all the specfiles are in the hash_buf, generate the hash. */
void hidden digest_gen_hash(struct selabel_digest *digest)
{
}

/**
 * digest_add_specfile - Add a specfile to the hashbuf and if gen_hash true
 *			 then generate the hash.
 * @digest: pointer to the selabel_digest struct
 * @fp: file pointer for fread(3) or NULL if not.
 * @from_addr: pointer at start of buffer for memcpy or NULL if not (used for
 *	       mmap(3) files).
 * @buf_len: length of buffer to copy.
 * @path: pointer to the specfile.
 *
 * Return %0 on success, -%1 with @errno set on failure.
 */
int hidden digest_add_specfile(struct selabel_digest *digest, FILE *fp,
				    char *from_addr, size_t buf_len,
				    const char *path)
{
        return 0;
}
