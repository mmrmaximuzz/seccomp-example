#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "untrusted.h"

#define UNIX_SOCKET_PATHNAME "test"

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

	char buffer[1] = {0};
	while (true) {
		read(dsock, buffer, sizeof(buffer));
		write(dsock, buffer, sizeof(buffer));
	}

	return EXIT_SUCCESS;
}
