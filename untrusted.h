/**
 * untrusted.h - the simple and stupid example of using `seccomp`
 *
 * Provides the simple wrappers for calling untrusted code in a pseudo-sandbox.
 * The sandboxing consists of limiting the number of system calls available for
 * the untrusted code to the following small subset:
 *
 * read, write, _exit, sigreturn
 *
 * Linux-specific `seccomp` system call is used to achieve that behavior. See
 * the corresponding man page for the description.
 *
 * NOTE: Do not use this example as a real sandbox because it is an _example_.
 * For the real sandboxes limiting the set of available system calls is not
 * enough - they should also protect the system against the side-channel
 * attacks.
 */

#ifndef UNTRUSTED_H
#define UNTRUSTED_H

#include <stddef.h>
#include <stdio.h>

#include <unistd.h>

#include <linux/seccomp.h>
#include <sys/syscall.h>

/**
 * struct untrusted - the structure to use for untrusted part of the execution
 *
 * This structure is used as an input argument for all the untrusted code
 * @fd: connected socket file descriptor for data exchange
 * @memory: the pointer to the memory pre-allocated for the untrusted process
 * @memsize: the amount of memory available (bytes)
 */
struct untrusted {
	int    fd;
	void   *memory;
	size_t memsize;
};
typedef int (*untrusted_f)(const struct untrusted *);

/**
 * run_untrusted - prepare the sandbox and run untrusted code
 *
 * The sandbox is prepared with linux's `seccomp` called with strict mode of
 * operation. Also the standard streams are closed here to limit the IO of
 * untrusted process to the single file descriptor.
 *
 * @resources: the resoures struct used as input for the untrusted code
 * @executor: the untrusted function being called
 */
static inline int run_untrusted(const struct untrusted *resources,
				untrusted_f executor)
{
	/*
	 * Use direct syscall here because there may be no wrapper in libc
	 */
	long err = syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
	if (err == -1) {
		perror("cannot enter strict seccomp mode");
		return err;
	}

	/* Additionally close the std{in,out,err} streams */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Now we are prepared to run the untrusted code */
	return executor(resources);
}

#endif
