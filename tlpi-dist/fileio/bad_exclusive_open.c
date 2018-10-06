/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2018.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 5-1 */

/* bad_exclusive_open.c

   The following code shows why we need the open() O_EXCL flag.

   This program tries ensure that it is the one that creates the file
   named in its command-line argument. It does this by trying to open()
   the filename once without the O_CREAT flag (if this open() succeeds
   then the program know it is not the creator of the file), and if
   that open() fails, it calls open() a second time, with the O_CREAT flag.

   If the first open() fails, the program assumes that it is the creator
   of the file. However this may not be true: some other process may have
   created the file between the two calls to open().
*/
#include <sys/stat.h>
#include <fcntl.h>
#include "tlpi_hdr.h"
/*
ENOENT
The specified file does't exist,and O_CREAT was not specified,or O_CREATE was 
specified,and one of the directories in pathname doesn't exist or is a symbolic
link pointing to a nonexistent pathname(a dangling link)
*/

/*结合O_CREAT和O_EXECL标志一次性调用open()可以确保检查文件和创建文件的步骤属于一个原子操作*/
int
main(int argc, char *argv[])
{
    int fd;

    if (argc < 2 || strcmp(argv[1], "--help") == 0)
        usageErr("%s file\n", argv[0]);

    fd = open(argv[1], O_WRONLY);       /* Open 1: check if file exists */
    if (fd != -1) {                     /* Open succeeded */
        printf("[PID %ld] File \"%s\" already exists\n",
                (long) getpid(), argv[1]);
        close(fd);
    } else {
        if (errno != ENOENT) {          /* Failed for unexpected reason */
            errExit("open");
        } else {
            printf("[PID %ld] File \"%s\" doesn't exist yet\n",
                    (long) getpid(), argv[1]);
            if (argc > 2) {             /* Delay between check and create */
                sleep(5);               /* Suspend execution for 5 seconds */
                /*第三个命令行参数任意输入，此处只是通过argc进入sleep*/
                /*./bad_exclusive_open tfile hello &然后再执行./bad_exclusive tfile*/
                printf("[PID %ld] Done sleeping\n", (long) getpid());
            }
            fd = open(argv[1], O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
            if (fd == -1)
                errExit("open");

            printf("[PID %ld] Created file \"%s\" exclusively\n",
                    (long) getpid(), argv[1]);          /* MAY NOT BE TRUE! */
        }
    }

    exit(EXIT_SUCCESS);
}
