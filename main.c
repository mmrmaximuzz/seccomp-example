#include <error.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define UNIX_SOCKET_PATHNAME "test"

int main(void)
{
	unlink(UNIX_SOCKET_PATHNAME);

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("cannot open unix socket");
		return EXIT_FAILURE;
	}

	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path   = UNIX_SOCKET_PATHNAME,
	};

	int bindres = bind(sock,
			   (const struct sockaddr *)&name,
			   sizeof(struct sockaddr_un));
	if (bindres == -1) {
		perror("cannot bind socket");
		return EXIT_SUCCESS;
	}

	int listenres = listen(sock, 1);
	if (listenres == -1) {
		perror("cannot listen on socket");
		return EXIT_FAILURE;
	}

	/* Wait for incoming connection. */
	int dsock = accept(sock, NULL, NULL);
	if (dsock == -1) {
		perror("cannot accept connection");
		exit(EXIT_FAILURE);
	}

	char buffer[1] = {0};
	while (true) {
		read(dsock, buffer, sizeof(buffer));
		write(dsock, buffer, sizeof(buffer));
	}

	return EXIT_SUCCESS;
}
