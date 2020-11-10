/**
 * Simple seccomp example for linux. In this example the unix socket is created,
 * then it accepts connection and runs the untrusted code in the sandbox. The
 * sandboxing consists of limiting the number of system calls available for the
 * untrusted code to the following small subset:
 *
 * - read
 * - write
 * - _exit
 * - sigreturn
 *
 * Linux-specific `seccomp` system call is used to achieve that behavior. See
 * the corresponding man page for the description.
 *
 * NOTE: Do not use this example as a real sandbox because it is an _example_.
 * For the real sandboxes limiting the set of available system calls is not
 * enough - they should also protect the system against the side-channel
 * attacks.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
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

/**
 * Simple helper which is used to create a named unix streamsocket listening for
 * exactly one connection at a time and bind it to @path in the filesystem.
 *
 * Returns socket fd on success and -1 on failures.
 */
static inline int create_unix_socket(const char *path)
{
	int err = 0;
	int sock = -1;
	struct sockaddr_un name = { .sun_family = AF_UNIX };

	/* Check that path is not too long for `sockaddr` struct */
	if (strlen(path) >= sizeof(name.sun_path)) {
		fprintf(stderr, "unix socket: path is too long: %s", path);
		goto fail;
	}
	strncpy(name.sun_path, path, sizeof(name.sun_path) - 1);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("cannot open unix socket");
		goto fail;
	}

	unlink(path);
	err = bind(sock, (struct sockaddr *) &name, sizeof(name));
	if (err == -1) {
		perror("cannot bind socket");
		goto fail_sock;
	}

	err = listen(sock, 1);
	if (err == -1) {
		perror("cannot listen on socket");
		goto fail_sock;
	}

	return sock;

fail_sock:
	close(sock);
fail:
	return -1;
}
