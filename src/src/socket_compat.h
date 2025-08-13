#pragma once
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET native_socket_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int native_socket_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

	void socket_startup();
	void socket_cleanup();

	// UDP helpers (existing)
	native_socket_t socket_udp_open_and_bind(int port);
	int send_udp_to(native_socket_t fd, uint32_t ipv4_nbo, uint16_t port, const void* data, int len);
	int recv_udp_with_timeout(native_socket_t fd, void* buf, int maxlen, int timeout_us); // returns bytes or -1
	void closesocket_native(native_socket_t fd);

	// TCP helpers (new)
	native_socket_t socket_tcp_create();
	int socket_tcp_bind(native_socket_t s, uint16_t port); // returns 0 ok, -1 error
	int socket_tcp_listen(native_socket_t s, int backlog); // returns 0 ok
	native_socket_t socket_tcp_accept(native_socket_t s, uint32_t* out_ip_nbo, uint16_t* out_port); // returns new socket or -1
	int socket_tcp_connect(native_socket_t s, uint32_t dest_ip_nbo, uint16_t port, int timeout_ms); // 0 ok, >0 in progress / non-blocking, -1 error
	int socket_send(native_socket_t s, const void* data, int len); // send(), returns bytes or -1
	int socket_recv(native_socket_t s, void* buf, int len, int flags); // recv()
	int set_socket_nonblocking(native_socket_t s, int nonblock); // 0 ok
	int socket_set_timeout(native_socket_t s, int which, int timeout_ms); // which: 0 recv, 1 send
	int socket_shutdown_recv(native_socket_t s);
	int socket_close(native_socket_t s);

	// socket error helper
	int socket_errno();

#ifdef __cplusplus
}
#endif
