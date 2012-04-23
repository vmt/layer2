/* main.c - main interface (command line)
 *
 * Copyright (c) 2005 Vivek Mohan <vivek@sig9.com>
 * All rights reserved.
 * See (LICENSE)
 */
#include "layer2.h"
#include "conf.h"

int main()
{
	/* initialize l2 */
	if (! l2_init())
		exit(EXIT_FAILURE);

	/* expect config file from stdin */
	if (! l2_parse_conf(stdin)) {
		fprintf(stderr, "Error: Please review your config file.\n");
		exit(EXIT_FAILURE);
	}

	/* compile and set filters */
	if (! l2_set_filters()) {
		fprintf(stderr, "Error: Please review your config file.\n");
		exit(EXIT_FAILURE);
	}

	/* start router */
	if (! l2_route())
		exit(EXIT_FAILURE);

	/* deinitialize l2 */
	l2_deinit();

	/* exit */
	exit(EXIT_SUCCESS);
}
