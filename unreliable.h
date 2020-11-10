/*
 * Simple seccomp example for linux. In this example the unix socket is created,
 * then it accepts connection and goes into the sandbox mode.
 *
 * Do not use this example as a real sandbox because it is _just_ an example.
 * For the real sandboxes limiting the set of available system calls is not
 * enough - they should also protect the system against the side-channel
 * attacks.
 */

#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
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
