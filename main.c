#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "untrusted.h"

#define UNIX_SOCKET_PATHNAME "test"

int main(void)
{
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
