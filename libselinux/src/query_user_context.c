#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "selinux_internal.h"
#include "context_internal.h"
#include <selinux/get_context_list.h>

/* context_menu - given a list of contexts, presents a menu of security contexts
 *            to the user.  Returns the number (position in the list) of
 *            the user selected context.
 */
static int context_menu(char ** list)
{
        return 0;
}

/* query_user_context - given a list of context, allow the user to choose one.  The 
 *                  default is the first context in the list.  Returns 0 on
 *                  success, -1 on failure
 */
int query_user_context(char ** list, char ** usercon)
{
	return 0;
}

/* get_field - given fieldstr - the "name" of a field, query the user 
 *             and set the new value of the field
 */
static void get_field(const char *fieldstr, char *newfield, int newfieldlen)
{
	int done = 0;		/* true if a non-empty field has been obtained */

	while (!done) {		/* Keep going until we get a value for the field */
		printf("\tEnter %s ", fieldstr);
		fflush(stdin);
		if (fgets(newfield, newfieldlen, stdin) == NULL)
			continue;
		fflush(stdin);
		if (newfield[strlen(newfield) - 1] == '\n')
			newfield[strlen(newfield) - 1] = '\0';

		if (strlen(newfield) == 0) {
			printf("You must enter a %s\n", fieldstr);
		} else {
			done = 1;
		}
	}
}

/* manual_user_enter_context - provides a way for a user to manually enter a
 *                     context in case the policy doesn't allow a list
 *                     to be obtained.
 *                     given the userid, queries the user and places the
 *                     context chosen by the user into usercon.  Returns 0
 *                     on success.
 */
int manual_user_enter_context(const char *user, char ** newcon)
{
	return 0;
}
