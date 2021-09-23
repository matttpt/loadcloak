# `loadcloak`

`loadcloak` is a UNIX utility to run shell commands without affecting the
load average.

## Compilation and usage

```shell
$ make
$ ./loadcloak '<shell command to run>'
```

## How?

`loadcloak` first determines when the load average is recalculated. Then
it launches the provided shell command in a new process group. It sends
`SIGSTOP` to this process group before load-average recalculations, and
sends `SIGCONT` afterward. Thus, the processes in that group are not
in the run queue when the load average is computed, so their activity
does not affect the load average.

A more complete description, with caveats, is provided at the beginning
of the source code.

## Why?

This software has no practical purpose. Even if it "cloaks" process
activity from appearing in the load average, it cannot prevent it from
appearing in CPU usage statistics.

Really, it's just a demonstration that UNIX load averages can be
manipulated. Isn't it amusing to see near-100% CPU usage with a
near-zero load average?

## License

`loadcloak` is available under the MIT license. See the `LICENSE` file
for details.
