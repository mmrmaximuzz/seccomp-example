# seccomp-example
Simple and stupid seccomp usage example

*DISCLAIMER*: please don't use this in your production code! It is just an example
and you should use the professional sandboxes if you really need it.

In this repo you can find the example of how to create a process, limit the
system call available and then run untrusted code with connected socket to
exchange data and some pre-allocated memory for the process needs.

The example is based on `seccomp` system call so it works on Linux only. For the
further details about `seccomp` and sandboxing please refer for the manual page.

```bash
man 2 seccomp
```
