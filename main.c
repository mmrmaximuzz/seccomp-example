/**
 * Simple `seccomp` example. In this example the unix socket is created, then it
 * accepts connection and runs the untrusted code in the sandbox.
 *
 * NOTE: Do not use this example as a real sandbox because it is an _example_.
 * For the real sandboxes limiting the set of available system calls is not
 * enough - they should also protect the system against the side-channel
 * attacks.
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "untrusted.h"

#define UNIX_SOCKET_PATHNAME "test"

/**
 * untrusted_ascii_stripper - the example of untrusted code
 *
 * Just reads and removes all non-printable ascii characters and writes the
 * purified stream back.
 */
static int untrusted_ascii_stripper(const struct untrusted *resources)
{
	int fd = resources->fd;
	unsigned char byte = 0;

	while (true) {
		ssize_t rres = read(fd, &byte, sizeof(byte));
		if (rres <= 0)
			return rres;

		/* Filter all non-printable characteres */
		if (!isprint(byte))
			continue;

		ssize_t wres = write(fd, &byte, sizeof(byte));
		if (wres == -1)
			return wres;
	}
}

/**
 * Simple helper which is used to create a named unix streamsocket listening for
 * exactly one connection at a time and bind it to @path in the filesystem. The
 * socket is used as interconnection between the untrusted code and the rest of
 * the system and the rest of the system.
 *
 * @path: path in the filesystem to place the unix socket
 *
 * Returns socket fd on success and -1 on failures.
 */
static int create_unix_socket(const char *path)
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

	/* unlink the previous file object under the path if exists */
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

int main(void)
{
	/*
	 * Create a unix socket to connect the untrusted code with the rest of
	 * the system.
	 */
	int sock = create_unix_socket(UNIX_SOCKET_PATHNAME);

	/* Wait for incoming connection. */
	int dsock = accept(sock, NULL, NULL);
	if (dsock == -1) {
		perror("cannot accept connection");
		return EXIT_FAILURE;
	}

	/* Prepare the resource structure for the untrusted code */
	struct untrusted resources = {
		.fd      = dsock,
		.memory  = NULL,
		.memsize = 0,
	};

	/* Run the untrusted code */
	int res = run_untrusted(&resources, untrusted_ascii_stripper);

	/*
	 * Note that after function return the current process may be already
	 * sandboxed so print nothing, and exit with `_exit` system call. Note
	 * that we cannot just return from main (because it calls `exit_group`
	 * which is forbidden) and we cannot call libc's `_exit` because it is
	 * just a wrapper for `exit_group`.
	 */
	syscall(SYS_exit, res);
}
