/**
 * @file tsh.c
 * @brief
 * Implementation of a simple Linux Shell program. The eval function first
 * checks if the command is a builtin command using the builtin_command
 * function. This function immediately executes the necessary procedure for the
 * quit, fg, bg, and jobs commands. Otherwise, the parent forks a child process
 * to run the exeutable supplied by the user. Sigchld, sigint, and sigstsp
 * handlers are written to deal with child termination, ctrl-c, and ctrl-z
 * respectively. Signal masks are used to block and unblock signals as needed.
 * Error checking is also handled appropriately with a conditional check and a
 * print statement.
 *
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Abishek Anand <abisheka@andrew.cmu.edu>
 * TODO: Include your name and Andrew ID here.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 *
 * TODO:
 *
 * Main function of the shell program responsible for reading user input,
 * parsing and evaluating commands, and executing them. It also handles signals,
 * manages background jobs, and deals with the job list.
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
Handles built-in commands for the shell.
 *
 * @param token A struct containing the parsed command-line tokens.
 * @return Returns 1 if the command is a recognized built-in command and
 *         has been executed successfully. Returns 0 if the command is not
 *         a built-in command and needs further processing.
 *
 * Error cases relevant to the caller:
 *   - If the 'outfile' field of 'token' is provided for the 'jobs' built-in
 *     command, and there is an issue opening or creating the file, an error
 *     message will be printed, and the function returns 1.
 *   - If the argument for the 'bg' or 'fg' built-in command is not provided
 *     in the correct format (PID or %jobid), an error message will be printed,
 *     and the function returns 1.
 *   - If the job with the specified jobid does not exist for the 'bg' or 'fg'
 *     built-in command, an error message will be printed, and the function
 *     returns 1.
*/
int builtin_command(struct cmdline_tokens token) {
    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    // quit command
    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    } else if (token.builtin == BUILTIN_JOBS) {
        int fd = STDOUT_FILENO;
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        if (token.outfile) {
            fd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
            if (fd < 0) {
                perror(token.outfile);
                return 1;
            }
        }
        list_jobs(fd);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return 1;
    } else if (token.builtin == BUILTIN_BG) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        jid_t jid;
        pid_t pid;
        if (token.argv[1] == NULL) {
            sio_printf("%s command requires PID or %%jobid argument\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return 1;
        } else if (token.argv[1][0] == '%') {
            jid = atoi(token.argv[1] + 1);
            if (!job_exists(jid)) {
                sio_printf("%s: No such job\n", token.argv[1]);
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return 1;
            }
            pid = job_get_pid(jid);
        } else if (isdigit(token.argv[1][0])) {
            pid = atoi(token.argv[1]);
            jid = job_from_pid(pid);
        } else {
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return 1;
        }
        kill(-(pid), SIGCONT);
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        job_set_state(jid, BG);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return 1;
    } else if (token.builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        jid_t jid;
        pid_t pid;
        if (token.argv[1] == NULL) {
            sio_printf("%s command requires PID or %%jobid argument\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return 1;
        } else if (token.argv[1][0] == '%') {
            jid = atoi(token.argv[1] + 1);
            if (!job_exists(jid)) {
                sio_printf("%s: No such job\n", token.argv[1]);
                sigprocmask(SIG_SETMASK, &prev_mask, NULL);
                return 1;
            }
            pid = job_get_pid(jid);
        } else if (isdigit(token.argv[1][0])) {
            pid = atoi(token.argv[1]);
            jid = job_from_pid(pid);
        } else {
            sio_printf("%s: argument must be a PID or %%jobid\n",
                       token.argv[0]);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return 1;
        }
        kill(-(pid), SIGCONT);
        job_set_state(jid, FG);
        while (fg_job()) {
            sigsuspend(&prev_mask);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return 1;
    }
    return 0;
}

/**
 * @param cmdline The input command line to be evaluated and executed.
 *
 * Purpose:
 *   This function parses the given command line, checks if it is a built-in
 *   command, and if not, forks a new process to execute the external command.
 *   It also handles background and foreground processes and manages the job
 * list.
 *
 * Error cases relevant to the caller:
 *   - If there is an error during parsing the command line using the
 * 'parseline' function, this function returns without any further processing.
 *   - If there is an error opening or creating a file for input or output
 *     redirection, this function prints an error message and terminates the
 *     child process.
 *   - If there is an error during the execution of the external command using
 *     'execvp' or 'execve', this function prints an error message and
 * terminates the child process.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    pid_t pid;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    jid_t jid;

    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    if (!builtin_command(token)) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        if ((pid = fork()) == 0) {
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            if (token.infile) {
                int fd = open(token.infile, O_RDONLY, 0);
                if (fd < 0) {
                    perror(token.infile);
                    exit(0);
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            }
            if (token.outfile) {
                int fd = open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC,
                              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
                if (fd < 0) {
                    perror(token.outfile);
                    exit(0);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }
            setpgid(0, 0);
            if (execvp(token.argv[0], token.argv) < 0) {
                perror(token.argv[0]);
                exit(0);
            }
            if (execve(token.argv[0], token.argv, environ) < 0) {
                perror(token.argv[0]);
                exit(0);
            }
        }

        if (parse_result != PARSELINE_BG) {
            add_job(pid, FG, cmdline);
            while (fg_job()) {
                sigsuspend(&prev_mask);
            }
        } else {
            jid = add_job(pid, BG, cmdline);
            sio_printf("[%d] (%d) %s \n", jid, pid, cmdline);
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * Signal handler for the SIGCHLD signal, which is sent to the parent process
 * when a child process changes its state (e.g., terminates, stops, or exits).
 *
 * @param sig The signal number corresponding to the SIGCHLD signal.
 *
 * Purpose:
 *   This function is a signal handler for the SIGCHLD signal, and it is used to
 *   handle the termination or stopping of child processes. It waits for the
 *   state changes of child processes and updates the job list accordingly. It
 *   also prints relevant information about stopped or terminated background
 * jobs.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;

    sigset_t mask, prev_mask;
    pid_t pid;

    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    int status;
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        if (WIFSTOPPED(status)) {
            sio_printf("Job [%d] (%d) stopped by signal %d \n",
                       job_from_pid(pid), pid, WSTOPSIG(status));
            job_set_state(job_from_pid(pid), ST);
        }

        else if (WIFSIGNALED(status)) {
            sio_printf("Job [%d] (%d) terminated by signal %d \n",
                       job_from_pid(pid), pid, WTERMSIG(status));
            delete_job(job_from_pid(pid));
        } else if (WIFEXITED(status)) {
            delete_job(job_from_pid(pid));
        }
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }

    errno = olderrno;
    return;
}

/**
 * Signal handler for the SIGINT signal (Ctrl-C), which is sent to the shell's
 * foreground process group when the user presses Ctrl-C.
 *
 * @param sig The signal number corresponding to the SIGINT signal.
 *
 * Purpose:
 *   This function is a signal handler for the SIGINT signal, which is sent to
 *   the shell's foreground process group when the user presses Ctrl-C. It is
 *   responsible for forwarding the SIGINT signal to the foreground job, thereby
 *   terminating its execution if the job is running in the foreground.
 */
void sigint_handler(int sig) {
    int olderrno = errno;

    sigset_t mask, prev_mask;

    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    jid_t jid;

    if ((jid = fg_job())) {
        kill(-(job_get_pid(jid)), sig);
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = olderrno;

    return;
}

/**
 * Signal handler for the SIGTSTP signal (Ctrl-Z), which is sent to the shell's
 * foreground process group when the user presses Ctrl-Z.
 *
 * @param sig The signal number corresponding to the SIGTSTP signal.
 *
 * Purpose:
 *   This function is a signal handler for the SIGTSTP signal, which is sent to
 *   the shell's foreground process group when the user presses Ctrl-Z. It is
 *   responsible for forwarding the SIGTSTP signal to the foreground job,
 * thereby stopping its execution if the job is running in the foreground.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;

    sigset_t mask, prev_mask;

    sigemptyset(&mask);
    sigemptyset(&prev_mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTSTP);

    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    jid_t jid;

    if ((jid = fg_job())) {
        kill(-(job_get_pid(jid)), sig);
    }

    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = olderrno;

    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
