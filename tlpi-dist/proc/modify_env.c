/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2018.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 6-4 */

/* modify_env.c

   Demonstrate modification of the process environment list.

   Usage: modify_env name=value...

   Note: some UNIX implementations do not provide clearenv(), setenv(),
   and unsetenv().
*/
#define _GNU_SOURCE     /* Get various declarations from <stdlib.h> */
#include <stdlib.h>
#include "tlpi_hdr.h"

extern char **environ;

int
main(int argc, char *argv[])
{
    int j;
    char **ep;

    clearenv();         /* Erase entire environment */

    /* Add any definitions specified on command line to environment */

    for (j = 1; j < argc; j++)
        if (putenv(argv[j]) != 0)
            errExit("putenv: %s", argv[j]);

    /* Add a definition for GREET if one does not already exist */
    /*The setenv function doesn't change the environment if the variable 
    identified by name already exists and overwrite has the value 0.If 
    overwrite is nonzero,the environment is always changed.
    
    */
    if (setenv("GREET", "Hello world", 0) == -1)
        errExit("setenv");

    /* Remove any existing definition of BYE */

    unsetenv("BYE");

    /* Display current environment */

    for (ep = environ; *ep != NULL; ep++)
        puts(*ep);

    exit(EXIT_SUCCESS);
}
