// SPDX-License-Identifier: GPL-2.0
/*
 * netprobe - tiny TCP/UDP client and server used by the test script
 *
 *   netprobe tcp-listen PORT          accept one connection, print what it receives
 *   netprobe tcp-connect IP PORT SEC  connect, send "hello", exit 0 on success,
 *                                     2 if the connection timed out
 *   netprobe udp-listen PORT SEC      print the first datagram received within SEC
 *   netprobe udp-send IP PORT         send one datagram
 *
 * Exit codes: 0 success, 1 error, 2 timeout.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *what)
{
	perror(what);
	return 1;
}

static struct sockaddr_in make_addr(const char *ip, int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) };
	inet_pton(AF_INET, ip, &a.sin_addr);
	return a;
}

static int tcp_listen(int port)
{
	struct sockaddr_in addr = make_addr("127.0.0.1", port);
	char buf[64] = {0};
	int one = 1, s, c;
	ssize_t n;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return fail("socket");
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
		return fail("bind/listen");
	c = accept(s, NULL, NULL);
	if (c < 0)
		return fail("accept");
	n = read(c, buf, sizeof(buf) - 1);
	if (n > 0)
		printf("received: %s\n", buf);
	close(c);
	close(s);
	return 0;
}

static int tcp_connect(const char *ip, int port, int timeout_s)
{
	struct sockaddr_in addr = make_addr(ip, port);
	struct pollfd pfd;
	int s, err = 0;
	socklen_t len = sizeof(err);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return fail("socket");
	fcntl(s, F_SETFL, O_NONBLOCK);	/* so the timeout can be enforced with poll() */
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS)
		return fail("connect");

	pfd.fd = s;
	pfd.events = POLLOUT;
	if (poll(&pfd, 1, timeout_s * 1000) == 0) {
		printf("connect timed out after %d s\n", timeout_s);
		return 2;
	}
	getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err) {
		errno = err;
		return fail("connect");
	}
	fcntl(s, F_SETFL, 0);
	if (write(s, "hello", 5) != 5)
		return fail("write");
	printf("connected and sent hello\n");
	close(s);
	return 0;
}

static int udp_listen(int port, int timeout_s)
{
	struct sockaddr_in addr = make_addr("127.0.0.1", port);
	struct pollfd pfd;
	char buf[64] = {0};
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return fail("socket");
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return fail("bind");
	pfd.fd = s;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, timeout_s * 1000) == 0) {
		printf("no datagram within %d s\n", timeout_s);
		return 2;
	}
	if (recv(s, buf, sizeof(buf) - 1, 0) < 0)
		return fail("recv");
	printf("received: %s\n", buf);
	close(s);
	return 0;
}

static int udp_send(const char *ip, int port)
{
	struct sockaddr_in addr = make_addr(ip, port);
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s < 0)
		return fail("socket");
	if (sendto(s, "hello", 5, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return fail("sendto");	/* a dropped outbound packet gives EPERM here */
	printf("sent hello\n");
	close(s);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 3 && !strcmp(argv[1], "tcp-listen"))
		return tcp_listen(atoi(argv[2]));
	if (argc >= 5 && !strcmp(argv[1], "tcp-connect"))
		return tcp_connect(argv[2], atoi(argv[3]), atoi(argv[4]));
	if (argc >= 4 && !strcmp(argv[1], "udp-listen"))
		return udp_listen(atoi(argv[2]), atoi(argv[3]));
	if (argc >= 4 && !strcmp(argv[1], "udp-send"))
		return udp_send(argv[2], atoi(argv[3]));

	fprintf(stderr,
		"Usage: netprobe tcp-listen PORT | tcp-connect IP PORT SEC |\n"
		"       udp-listen PORT SEC | udp-send IP PORT\n");
	return 2;
}
