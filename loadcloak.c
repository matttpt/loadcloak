// loadcloak - run shell commands without affecting the load average
//
// Copyright (c) 2021 Matthew Ingwersen <matttpt@gmail.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////
// THEORY OF OPERATION                                                //
////////////////////////////////////////////////////////////////////////

// On several Unix-like operating systems, the load average is
// recalculated at fixed intervals, generally around 5 seconds. On
// Linux, it's actually 5 seconds + 1 jiffy, so the interval will depend
// on the kernel's configured HZ value.
//
// The load average is affected by the number of processes in the run
// queue when the recalculation is made. In order to run a program
// without affecting the load average, "cloaking" its operation from the
// load average (so to speak), we can pause every time we know a
// load-average update is coming and resume afterward. That way, we'll
// never be in the run queue when the recalculations occur, and the load
// average will not reflect our CPU usage.
//
// (On Linux, processes in uninterruptible sleep states are also
// included in the calculation, so on Linux, we're addressing the CPU
// aspect only.)
//
// This program accepts a shell command and runs it, while cloaking its
// CPU usage from the load average in the manner described. First, the
// load-average update interval is measured. Then, the program forks.
// The child creates a new process group sharing its PID and spawns a
// shell to run the command. The parent, meanwhile, configures a timer
// that will send SIGSTOP to the child process's group shortly before
// every load-average update, and then will send SIGCONT to the group
// right after every load-average update. In this manner, the processes
// spawned by the shell command (so long as they don't leave the process
// group that's created) will escape the attention of load-average
// recalculation.
//
// Is this useful? No, not really. You can tell that something is amiss
// based on the CPU usage, of course, and anybody monitoring a system
// will hopefully keep an eye on CPU usage in addition to load average!
// On Linux, uninterruptible sleep states are also included in
// load-average calculations; stopping processes a few tens of
// milliseconds before the load-average recalculation may not be enough
// time for them to get out of uninterruptible sleep states and let
// SIGSTOP be delivered.
//
// However, it's a fun demonstration that load averages can be
// manipulated. Seeing near-100% CPU usage with a near-zero load average
// can be amusing, at least for me!

////////////////////////////////////////////////////////////////////////
// TIME UTILITIES                                                     //
////////////////////////////////////////////////////////////////////////

// Gets the current time, using CLOCK_MONOTONIC.
static struct timespec get_time(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        perror("failed to get time");
        exit(EXIT_FAILURE);
    }
    return time;
}

// Computes the (rounded) number of milliseconds that occured between
// the given times. end must be later than start.
static int compute_interval_in_ms(const struct timespec *start,
                                  const struct timespec *end)
{
    int64_t nanos;
    if (end->tv_nsec < start->tv_nsec) {
        nanos = (end->tv_sec - start->tv_sec) * INT64_C(1000000000)
                + (start->tv_nsec - end->tv_nsec)
                - INT64_C(1000000000);
    } else {
        nanos = (end->tv_sec - start->tv_sec) * INT64_C(1000000000)
                + (end->tv_nsec - start->tv_nsec);
    }
    if (nanos % 1000000 >= 500000) {
        return (int) (nanos / 1000000 + 1);
    } else {
        return (int) (nanos / 1000000);
    }
}

// Adds the given number of milliseconds to the provided time. millis
// must be positive.
static struct timespec add_ms_to_time(const struct timespec *time,
                                      int millis)
{
    long add_to_tv_nsec = (millis % 1000) * 1000000;
    long new_tv_nsec = time->tv_nsec + add_to_tv_nsec;
    if (new_tv_nsec >= 1000000000) {
        return (struct timespec) {
            .tv_sec = time->tv_sec + (millis / 1000) + 1,
            .tv_nsec = new_tv_nsec - 1000000000,
        };
    } else {
        return (struct timespec) {
            .tv_sec = time->tv_sec + millis / 1000,
            .tv_nsec = new_tv_nsec,
        };
    }
}

////////////////////////////////////////////////////////////////////////
// LOAD AVERAGE CALCULATIONS                                          //
////////////////////////////////////////////////////////////////////////

// Timing information regarding load average updates. I'm assuming that
// the load-average recalculation interval will be a multiple of 1 ms,
// which works for Linux at least. So interval is expressed in
// milliseconds.
struct loadavg_timing {
    struct timespec last_update;
    int interval;
};

// Gets the current 1-minute load average.
static double get_load1(void)
{
    double load1;
    if (getloadavg(&load1, 1) < 0) {
        fputs("failed to get load average\n", stderr);
        exit(EXIT_FAILURE);
    }
    return load1;
}

// Busy-waits for the 1-minute load average to change from the given
// value. Returns the new 1-minute load average.
static double wait_for_load1_change(double starting_load1)
{
    double new_load1;
    do {
        new_load1 = get_load1();
    } while (new_load1 == starting_load1);
    return new_load1;
}

// Determines (by observing changes to the 1-minute load average) the
// interval between load-average updates. (This is based on the
// assumption/hope that busy-waiting for the 1-minute load average to
// change will, in fact, steadily raise the 1-minute load average so
// that the correct value is calculated.) Returns timing information,
// giving both the interval measured and the time of the last observed
// load average update.
//
// This interval measurement is actually completed three times; if the
// measurements disagree, the program fails. The reasoning is that if we
// want to cloak our activity by keeping it out of the load average,
// better to fail than to accidentally reveal ourselves.
static void measure_loadavg_timing(struct loadavg_timing *timing)
{
    struct timespec first_update, second_update;
    int intervals[3];

    double load1 = get_load1();
    load1 = wait_for_load1_change(load1);
    second_update = get_time();
    for (int i = 0; i < 3; i++) {
        first_update = second_update;
        load1 = wait_for_load1_change(load1);
        second_update = get_time();
        intervals[i] = compute_interval_in_ms(&first_update,
                                              &second_update);
        if (i > 0 && intervals[i] != intervals[0]) {
            fprintf(stderr,
                    "measure inconsistent load-average update "
                    "intervals: %d ms, %d ms\n",
                    intervals[0],
                    intervals[i]);
            exit(EXIT_FAILURE);
        }
    }

    timing->last_update = second_update;
    timing->interval = intervals[0];
}

////////////////////////////////////////////////////////////////////////
// TIMER                                                              //
////////////////////////////////////////////////////////////////////////

// The timer is responsible for stopping a given process group before a
// load-average update, and restarting it afterward. In this manner,
// the load average will never reflect any running processes in that
// group.
//
// Under the hood, the timer uses a POSIX timer which is configured to
// send SIGUSR1 at the appropriate times. The signal handler uses kill()
// to send SIGSTOP or SIGCONT, as determined by the timer's state. It
// then updates the timer state, computes the next time an action needs
// to occur, and reconfigures the POSIX timer.
//
// The timer state is global, since it uses Unix signals. The
// start_timer() routine initializes the timer for the process, and
// should not be called more than once!

enum pgrp_state {
    RUNNING,
    STOPPED,
};

struct timer {
    timer_t posix_timer;
    struct loadavg_timing timing;
    pid_t pgrp;
    enum pgrp_state pgrp_state;
};

static struct timer timer;

// These constants give the margin by which to stop the process group
// before a load-average update, and the margin by which to restart the
// process group after a load-average update, respectively. The values
// are in milliseconds.
//
// CONT_AFTER need not be large---I've made it nonzero just to be safe.
// But STOP_BEFORE must be carefully picked so that SIGSTOP is actually
// delivered before the load-average update occurs. As I understand it,
// a target process needs to be scheduled for this to happen. If a
// target process is in the run queue and is not scheduled for execution
// between the sending of the signal and the load-average calculation,
// it will still be sitting in the run queue when the calculation
// occurs, and it will therefore affect the load average. Not good! If
// we leave enough time, though, the process will almost always be
// scheduled before the calculation. SIGSTOP will be delivered, and the
// process will consequently be taken out of the run queue in time.
//
// On the flip side, we actually want the processes to get work done,
// so we shouldn't make STOP_BEFORE too big. I have found that 50 ms is
// long enough, while still allowing the target processeses to use
// almost all CPU time. Your system may be different. (Kernel scheduler
// parameters and system load could both affect the minimum workable
// value of STOP_BEFORE.)
static const int STOP_BEFORE = 50;
static const int CONT_AFTER = 1;

// Arms the timer to fire a certain number of milliseconds after the
// last load-average update (as recorded by timer.timing.last_update).
// This is basically a convenient wrapper around timer_settime(). This
// subroutine is signal-safe (since timer_settime() is).
static int set_timer(int ms_from_last_update)
{
    struct itimerspec its = {
        .it_interval = {
            .tv_sec = 0,
            .tv_nsec = 0,
        },
        .it_value = add_ms_to_time(&timer.timing.last_update,
                                   ms_from_last_update),
    };
    return timer_settime(timer.posix_timer,
                         TIMER_ABSTIME,
                         &its,
                         NULL) != 0;
}

// Handles errors in the timer signal handler by printing a basic error
// message and exiting. It's hard to be more specific, since we are
// restricted to signal-safe library routines. This subroutine should be
// signal-safe (note that write(), strlen(), and _exit() are all
// signal-safe).
static void timer_error(const char *call)
{
    const char *rest_of_message = " failed in timer signal handler\n";
    write(STDERR_FILENO, call, strlen(call));
    write(STDERR_FILENO, rest_of_message, strlen(rest_of_message));
    _exit(EXIT_FAILURE);
}

// Responds to the timer firing by starting or stopping the target
// process group (as determined by the timer's state) and rearming the
// timer for the next event. This should be signal-safe (note that
// kill(), set_timer(), and timer_error() are all signal-safe, and
// add_ms_to_time() is a pure function).
static void timer_handler(int signal_num)
{
    (void) signal_num;

    if (timer.pgrp_state == RUNNING) {
        if (kill(-timer.pgrp, SIGSTOP) != 0) {            
            timer_error("kill");
        }
        timer.pgrp_state = STOPPED;
        if (set_timer(timer.timing.interval + CONT_AFTER) != 0) {
            timer_error("timer_settime");
        }
    } else {
        if (kill(-timer.pgrp, SIGCONT) != 0) {
            timer_error("kill");
        }
        timer.pgrp_state = RUNNING;
        timer.timing.last_update =
            add_ms_to_time(&timer.timing.last_update,
                           timer.timing.interval);
        if (set_timer(timer.timing.interval - STOP_BEFORE) != 0) {
            timer_error("timer_settime");
        }
    }
}

// Starts the (process-global) timer to stop the given process group
// before each load-average update, and restart it afterward.
static void start_timer(const struct loadavg_timing *timing,
                        pid_t pgrp)
{
    timer.timing = *timing;
    timer.pgrp = pgrp;

    // Install the timer signal handler for SIGUSR1. We use SA_RESTART
    // so that the wait() call in the main thread of execution is not
    // interrupted by the timer firing.
    struct sigaction timer_action = {
        .sa_handler = &timer_handler,
        .sa_flags = SA_RESTART,
    };
    sigemptyset(&timer_action.sa_mask);
    if (sigaction(SIGUSR1, &timer_action, NULL) != 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Create an underlying POSIX timer that will send us SIGUSR1 when
    // it fires.
    struct sigevent timer_event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGUSR1,
    };
    if (timer_create(CLOCK_MONOTONIC,
                     &timer_event,
                     &timer.posix_timer) != 0)
    {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    // Arm the timer to perform the first stopping of the process group
    // before the next load-average update. All subsequent timer
    // processing will occur in the signal handler timer_handler().
    timer.pgrp_state = RUNNING;
    if (set_timer(timer.timing.interval - STOP_BEFORE) != 0) {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }
}

////////////////////////////////////////////////////////////////////////
// TERMINATION OF CHILD PROCESSES ON SIGINT OR SIGTERM                //
////////////////////////////////////////////////////////////////////////

// The process group to terminate.
static pid_t termination_pgrp;

// A signal-safe subroutine to print errors if the signal propagation
// handler fails.
static void termination_handler_error(const char *message) {
    write(STDOUT_FILENO, message, strlen(message));
    write(STDOUT_FILENO, "\n", 1);
}

// A signal handler to send SIGTERM to the target process group when we
// receive SIGINT or SIGTERM. This should be signal-safe (note that
// kill(), signal(), raise(), and termination_handler_error() all are)
//
// Why not just propagate the signal we receive (i.e. send SIGINT
// instead of SIGTERM when we receive SIGINT)? It turns out that
// non-interactive shells set the background processes they spawn to
// ignore SIGINT. It made sense in the era before job control (so that
// Ctrl+C would not kill background processes), but for our purposes we
// want to terminate everything. Ergo, we send SIGTERM in all cases.
//
// (See https://unix.stackexchange.com/a/356480)
static void termination_handler(int signal_num)
{
    // Note: ESRCH means that the group doesn't exist. We're okay with
    // that.
    if (kill(-termination_pgrp, SIGTERM) != 0
        && errno != ESRCH)
    {
        termination_handler_error(
            "kill failed in SIGINT/SIGTERM handler");
    }

    // In order to quit while still recording that we were terminated by
    // the signal, we reset the signal handler to the default and
    // re-raise the signal. (This is what the glibc documentation
    // recommends.)
    signal(signal_num, SIG_DFL);
    raise(signal_num);
}

// Installs the above signal handlers to terminate the specified process
// group when we receive SIGINT and SIGTERM. Note that this modifies
// global state!
static void terminate_pgrp_on_int_and_term(pid_t pgrp)
{
    termination_pgrp = pgrp;

    struct sigaction propagate_action = {
        .sa_handler = &termination_handler,
        .sa_flags = 0,
    };
    sigemptyset(&propagate_action.sa_mask);
    if (sigaction(SIGINT, &propagate_action, NULL) != 0
        || sigaction(SIGTERM, &propagate_action, NULL) != 0)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

// The following are used to block SIGINT and SIGTERM before the fork in
// main() until the signal handler is installed. See the comments there
// for why this is necessary.

static void set_sigset_to_int_and_term(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
}

static void block_int_and_term(void)
{
    sigset_t set;
    set_sigset_to_int_and_term(&set);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }
}

static void unblock_int_and_term(void)
{
    sigset_t set;
    set_sigset_to_int_and_term(&set);
    if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }
}

////////////////////////////////////////////////////////////////////////
// PROGRAM ENTRY POINT                                                //
////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fputs("exactly one argument (the command to run) is required\n",
              stderr);
        return EXIT_FAILURE;
    }

    struct loadavg_timing timing;
    measure_loadavg_timing(&timing);
    printf("found load-average update interval: %d ms\n",
           timing.interval);

    // We will install a SIGINT/SIGTERM handler to propagate those
    // signals to our children before we terminate, but we need to know
    // the PID of the child to set that up (so that we know which
    // process group to forward the signals to). Hence this must occur
    // after we fork. But if SIGINT or SIGTERM arrive between the fork
    // and the installation of the signal handler
    // (propogate_int_and_term()), the default signal handler will run,
    // quitting without trying to terminate the children. Therefore, we
    // block SIGINT and SIGTERM until the handler is installed.
    //
    // Because signal masks are inherited, these will need to be
    // unblocked in the child, too.
    block_int_and_term();

    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    } else if (child_pid == 0) {
        // We are the child process. We create a new process group (that
        // shares our PID) so that the parent process can easily send
        // SIGSTOP and SIGCONT to any and all processes that the shell
        // we execute may start.
        unblock_int_and_term();
        if (setpgid(0, 0) != 0) {
            perror("setpgid");
            return EXIT_FAILURE;
        }
        execl("/bin/sh", "sh", "-c", argv[1], NULL);
        perror("execl");
        return EXIT_FAILURE;
    } else {
        // We are the parent process. First, we install a signal handler
        // to terminate the child's process group when we receive SIGINT
        // or SIGTERM.
        terminate_pgrp_on_int_and_term(child_pid);
        unblock_int_and_term();

        // Configure the timer to start and stop the child's group based
        // on the timing information we found.
        start_timer(&timing, child_pid);

        // Wait for all children to exit.
        for (;;) {
            int wait_status;
            pid_t wait_result = wait(&wait_status);
            if (wait_result >= 0) {
                if (WIFEXITED(wait_status)
                    && WEXITSTATUS(wait_status) != 0)
                {
                    fprintf(stderr,
                            "warning: child %d exited with status %d\n",
                            (int) wait_result,
                            WEXITSTATUS(wait_status));
                } else if (WIFSIGNALED(wait_status)) {
                    fprintf(stderr,
                            "warning: child %d terminated by signal "
                            "%d\n",
                            (int) wait_result,
                            WTERMSIG(wait_status));
                }
            } else if (errno == ECHILD) {
                // No more children remain. We're done!
                return EXIT_SUCCESS;
            } else {
                perror("wait");
                return EXIT_FAILURE;
            }
        }
    }
}
