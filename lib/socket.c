/*
   Copyright (C) 2010 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef AROS
#include "aros_compat.h"
#endif

#ifdef WIN32
#include "win32_compat.h"
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include "libnfs-zdr.h"
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "slist.h"

#ifdef WIN32
//has to be included after stdlib!!
#include "win32_errnowrapper.h"
#endif

static int rpc_reconnect_requeue(struct rpc_context *rpc);
static int rpc_connect_sockaddr_async(struct rpc_context *rpc, struct sockaddr_storage *s);

static void set_nonblocking(int fd)
{
	int v = 0;
#if defined(WIN32)
	long nonblocking=1;
	v = ioctl(fd, FIONBIO, &nonblocking);
#else
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
#endif //FIXME
}

static void set_nolinger(int fd)
{
	struct linger lng;
	lng.l_onoff = 1;
	lng.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng));
}

#ifdef HAVE_NETINET_TCP_H
int set_tcp_sockopt(int sockfd, int optname, int value)
{
	int level;

	#if defined(__FreeBSD__) || defined(__sun) || (defined(__APPLE__) && defined(__MACH__))
	struct protoent *buf;

	if ((buf = getprotobyname("tcp")) != NULL)
		level = buf->p_proto;
	else
		return -1;
	#else
		level = SOL_TCP;
	#endif

	return setsockopt(sockfd, level, optname, (char *)&value, sizeof(value));
}
#endif

int rpc_get_fd(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return rpc->fd;
}

static int rpc_has_queue(struct rpc_queue *q)
{
	return q->head != NULL;
}

int rpc_which_events(struct rpc_context *rpc)
{
	int events;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	events = rpc->is_connected ? POLLIN : POLLOUT;

	if (rpc->is_udp != 0) {
		/* for udp sockets we only wait for pollin */
		return POLLIN;
	}

	if (rpc_has_queue(&rpc->outqueue)) {
		events |= POLLOUT;
	}
	return events;
}

static int rpc_write_to_socket(struct rpc_context *rpc)
{
	int32_t count;
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->fd == -1) {
		rpc_set_error(rpc, "trying to write but not connected");
		return -1;
	}

	while ((pdu = rpc->outqueue.head) != NULL) {
		int64_t total;

		total = pdu->outdata.size;

		count = send(rpc->fd, pdu->outdata.data + pdu->written, total - pdu->written, 0);
		if (count == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			rpc_set_error(rpc, "Error when writing to socket :%s(%d)", strerror(errno), errno);
			return -1;
		}

		pdu->written += count;
		if (pdu->written == total) {
			unsigned int hash;

			rpc->outqueue.head = pdu->next;
			if (pdu->next == NULL)
				rpc->outqueue.tail = NULL;

			hash = rpc_hash_xid(pdu->xid);
			rpc_enqueue(&rpc->waitpdu[hash], pdu);
		}
	}
	return 0;
}

static int rpc_read_from_socket(struct rpc_context *rpc)
{
	int available;
	int size;
	int pdu_size;
	int32_t count;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (ioctl(rpc->fd, FIONREAD, &available) != 0) {
		rpc_set_error(rpc, "Ioctl FIONREAD returned error : %d. Closing socket.", errno);
		return -1;
	}

	if (available == 0) {
		rpc_set_error(rpc, "Socket has been closed");
		return -1;
	}

	if (rpc->is_udp) {
		char *buf;
		socklen_t socklen = sizeof(rpc->udp_src);

		buf = malloc(available);
		if (buf == NULL) {
			rpc_set_error(rpc, "Failed to malloc buffer for recvfrom");
			return -1;
		}
		count = recvfrom(rpc->fd, buf, available, MSG_DONTWAIT, (struct sockaddr *)&rpc->udp_src, &socklen);
		if (count < 0) {
			rpc_set_error(rpc, "Failed recvfrom: %s", strerror(errno));
			free(buf);
			return -1;
		}
		if (rpc_process_pdu(rpc, buf, count) != 0) {
			rpc_set_error(rpc, "Invalid/garbage pdu received from server. Ignoring PDU");
			free(buf);
			return -1;
		}
		free(buf);
		return 0;
	}

	/* read record marker, 4 bytes at the beginning of every pdu */
	if (rpc->inbuf == NULL) {
		rpc->insize = 4;
		rpc->inbuf = malloc(rpc->insize);
		if (rpc->inbuf == NULL) {
			rpc_set_error(rpc, "Failed to allocate buffer for record marker, errno:%d. Closing socket.", errno);
			return -1;
		}
	}
	if (rpc->inpos < 4) {
		size = 4 - rpc->inpos;

		count = recv(rpc->fd, rpc->inbuf + rpc->inpos, size, 0);
		if (count == -1) {
			if (errno == EINTR) {
				return 0;
			}
			rpc_set_error(rpc, "Read from socket failed, errno:%d. Closing socket.", errno);
			return -1;
		}
		available  -= count;
		rpc->inpos += count;
	}

	if (available == 0) {
		return 0;
	}

	pdu_size = rpc_get_pdu_size(rpc->inbuf);
	if (rpc->insize < pdu_size) {
		unsigned char *buf;

		buf = malloc(pdu_size);
		if (buf == NULL) {
			rpc_set_error(rpc, "Failed to allocate buffer of %d bytes for pdu, errno:%d. Closing socket.", pdu_size, errno);
			return -1;
		}
		memcpy(buf, rpc->inbuf, rpc->insize);
		free(rpc->inbuf);
		rpc->inbuf  = buf;
		rpc->insize = rpc_get_pdu_size(rpc->inbuf);
	}

	size = available;
	if (size > rpc->insize - rpc->inpos) {
		size = rpc->insize - rpc->inpos;
	}

	count = recv(rpc->fd, rpc->inbuf + rpc->inpos, size, 0);
	if (count == -1) {
		if (errno == EINTR) {
			return 0;
		}
		rpc_set_error(rpc, "Read from socket failed, errno:%d. Closing socket.", errno);
		return -1;
	}
	available  -= count;
	rpc->inpos += count;

	if (rpc->inpos == rpc->insize) {
		char *buf = rpc->inbuf;

		rpc->inbuf  = NULL;
		rpc->insize = 0;
		rpc->inpos  = 0;

		if (rpc_process_pdu(rpc, buf, pdu_size) != 0) {
			rpc_set_error(rpc, "Invalid/garbage pdu received from server. Closing socket");
			return -1;
		}
		free(buf);
	}

	return 0;
}



int rpc_service(struct rpc_context *rpc, int revents)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (revents & POLLERR) {
#ifdef WIN32
		char err = 0;
#else
		int err = 0;
#endif
		socklen_t err_size = sizeof(err);

		if (getsockopt(rpc->fd, SOL_SOCKET, SO_ERROR,
				(char *)&err, &err_size) != 0 || err != 0) {
			if (err == 0) {
				err = errno;
			}
			rpc_set_error(rpc, "rpc_service: socket error "
					       "%s(%d).",
					       strerror(err), err);
		} else {
			rpc_set_error(rpc, "rpc_service: POLLERR, "
						"Unknown socket error.");
		}
		if (rpc->connect_cb != NULL) {
			rpc->connect_cb(rpc, RPC_STATUS_ERROR, rpc->error_string, rpc->connect_data);
		}
		return -1;
	}
	if (revents & POLLHUP) {
		rpc_set_error(rpc, "Socket failed with POLLHUP");
		if (rpc->connect_cb != NULL) {
			rpc->connect_cb(rpc, RPC_STATUS_ERROR, rpc->error_string, rpc->connect_data);
		}
		return -1;
	}

	if (rpc->is_connected == 0 && rpc->fd != -1 && revents&POLLOUT) {
		int err = 0;
		socklen_t err_size = sizeof(err);

		if (getsockopt(rpc->fd, SOL_SOCKET, SO_ERROR,
				(char *)&err, &err_size) != 0 || err != 0) {
			if (err == 0) {
				err = errno;
			}
			rpc_set_error(rpc, "rpc_service: socket error "
				  	"%s(%d) while connecting.",
					strerror(err), err);
			if (rpc->connect_cb != NULL) {
				rpc->connect_cb(rpc, RPC_STATUS_ERROR,
					NULL, rpc->connect_data);
			}
			return -1;
		}

		rpc->is_connected = 1;
		if (rpc->connect_cb != NULL) {
			rpc->connect_cb(rpc, RPC_STATUS_SUCCESS, NULL, rpc->connect_data);
		}
		return 0;
	}

	if (revents & POLLIN) {
		if (rpc_read_from_socket(rpc) != 0) {
		  	rpc_reconnect_requeue(rpc);
			return 0;
		}
	}

	if (revents & POLLOUT && rpc_has_queue(&rpc->outqueue)) {
		if (rpc_write_to_socket(rpc) != 0) {
			rpc_set_error(rpc, "write to socket failed");
			return -1;
		}
	}

	return 0;
}

void rpc_set_autoreconnect(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->auto_reconnect = 1;
}

void rpc_unset_autoreconnect(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->auto_reconnect = 0;
}

void rpc_set_tcp_syncnt(struct rpc_context *rpc, int v)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->tcp_syncnt = v;
}

#ifndef TCP_SYNCNT
#define TCP_SYNCNT        7
#endif

static int rpc_connect_sockaddr_async(struct rpc_context *rpc, struct sockaddr_storage *s)
{
	int socksize;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	switch (s->ss_family) {
	case AF_INET:
		socksize = sizeof(struct sockaddr_in);
		rpc->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef HAVE_NETINET_TCP_H
		if (rpc->tcp_syncnt != RPC_PARAM_UNDEFINED) {
			set_tcp_sockopt(rpc->fd, TCP_SYNCNT, rpc->tcp_syncnt);
		}
#endif
		break;
	case AF_INET6:
		socksize = sizeof(struct sockaddr_in6);
		rpc->fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#ifdef HAVE_NETINET_TCP_H
		if (rpc->tcp_syncnt != RPC_PARAM_UNDEFINED) {
			set_tcp_sockopt(rpc->fd, TCP_SYNCNT, rpc->tcp_syncnt);
		}
#endif
		break;
	default:
		rpc_set_error(rpc, "Can not handle AF_FAMILY:%d", s->ss_family);
		return -1;
	}

	if (rpc->fd == -1) {
		rpc_set_error(rpc, "Failed to open socket");
		return -1;
	}

	/* Some systems allow you to set capabilities on an executable
	 * to allow the file to be executed with privilege to bind to
	 * privileged system ports, even if the user is not root.
	 *
	 * Opportunistically try to bind the socket to a low numbered
	 * system port in the hope that the user is either root or the
	 * executable has the CAP_NET_BIND_SERVICE.
	 *
	 * As soon as we fail the bind() with EACCES we know we will never
	 * be able to bind to a system port so we terminate the loop.
	 *
	 * On linux, use
	 *    sudo setcap 'cap_net_bind_service=+ep' /path/executable
	 * to make the executable able to bind to a system port.
	 *
	 * On Windows, there is no concept of privileged ports. Thus
	 * binding will usually succeed.
	 */
	{
		struct sockaddr_storage ss;
		static int portOfs = 0;
		const int firstPort = 512;	/* >= 512 according to Sun docs */
		const int portCount = IPPORT_RESERVED - firstPort;
		int startOfs, port, rc;

		if (portOfs == 0) {
			portOfs = time(NULL) % 400;
		}
		startOfs = portOfs;
		do {
			rc = -1;
			port = htons(firstPort + portOfs);
			portOfs = (portOfs + 1) % portCount;

			/* skip well-known ports */
			if (!getservbyport(port, "tcp")) {
				memset(&ss, 0, sizeof(ss));

				switch (s->ss_family) {
				case AF_INET:
					((struct sockaddr_in *)&ss)->sin_port = port;
					((struct sockaddr_in *)&ss)->sin_family      = AF_INET;
#ifdef HAVE_SOCKADDR_LEN
					((struct sockaddr_in *)&ss)->sin_len = sizeof(struct sockaddr_in);
#endif
					break;
				case AF_INET6:
					((struct sockaddr_in6 *)&ss)->sin6_port = port;
					((struct sockaddr_in6 *)&ss)->sin6_family      = AF_INET6;
#ifdef HAVE_SOCKADDR_LEN
					((struct sockaddr_in6 *)&ss)->sin6_len = sizeof(struct sockaddr_in6);
#endif
					break;
				}

				rc = bind(rpc->fd, (struct sockaddr *)&ss, socksize);
#if !defined(WIN32)
				/* we got EACCES, so don't try again */
				if (rc != 0 && errno == EACCES)
					break;
#endif
			}
		} while (rc != 0 && portOfs != startOfs);
	}

	set_nonblocking(rpc->fd);
	set_nolinger(rpc->fd);

	if (connect(rpc->fd, (struct sockaddr *)s, socksize) != 0 && errno != EINPROGRESS) {
		rpc_set_error(rpc, "connect() to server failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	return 0;
}

int rpc_connect_async(struct rpc_context *rpc, const char *server, int port, rpc_cb cb, void *private_data)
{
	struct addrinfo *ai = NULL;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->fd != -1) {
		rpc_set_error(rpc, "Trying to connect while already connected");
		return -1;
	}

	if (rpc->is_udp != 0) {
		rpc_set_error(rpc, "Trying to connect on UDP socket");
		return -1;
	}

	rpc->auto_reconnect = 0;

	if (getaddrinfo(server, NULL, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			      "Can not resolv into IPv4/v6 structure.", server);
		return -1;
 	}

	switch (ai->ai_family) {
	case AF_INET:
		((struct sockaddr_in *)&rpc->s)->sin_family = ai->ai_family;
		((struct sockaddr_in *)&rpc->s)->sin_port   = htons(port);
		((struct sockaddr_in *)&rpc->s)->sin_addr   = ((struct sockaddr_in *)(ai->ai_addr))->sin_addr;
#ifdef HAVE_SOCKADDR_LEN
		((struct sockaddr_in *)&rpc->s)->sin_len = sizeof(struct sockaddr_in);
#endif
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)&rpc->s)->sin6_family = ai->ai_family;
		((struct sockaddr_in6 *)&rpc->s)->sin6_port   = htons(port);
		((struct sockaddr_in6 *)&rpc->s)->sin6_addr   = ((struct sockaddr_in6 *)(ai->ai_addr))->sin6_addr;
#ifdef HAVE_SOCKADDR_LEN
		((struct sockaddr_in6 *)&rpc->s)->sin6_len = sizeof(struct sockaddr_in6);
#endif
		break;
	}

	rpc->connect_cb  = cb;
	rpc->connect_data = private_data;

	freeaddrinfo(ai);

	if (rpc_connect_sockaddr_async(rpc, &rpc->s) != 0) {
		return -1;
	}

	return 0;
}

int rpc_disconnect(struct rpc_context *rpc, char *error)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc_unset_autoreconnect(rpc);

	if (rpc->fd != -1) {
		close(rpc->fd);
	}
	rpc->fd  = -1;

	rpc->is_connected = 0;

	rpc_error_all_pdus(rpc, error);

	return 0;
}

static void reconnect_cb(struct rpc_context *rpc, int status, void *data _U_, void *private_data)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (status != RPC_STATUS_SUCCESS) {
		rpc_error_all_pdus(rpc, "RPC ERROR: Failed to reconnect async");
		return;
	}

	rpc->is_connected = 1;
	rpc->connect_cb   = NULL;
}

/* disconnect but do not error all PDUs, just move pdus in-flight back to the outqueue and reconnect */
static int rpc_reconnect_requeue(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu;
	unsigned int i;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->fd != -1) {
		close(rpc->fd);
	}
	rpc->fd  = -1;

	rpc->is_connected = 0;

	/* socket is closed so we will not get any replies to any commands
	 * in flight. Move them all over from the waitpdu queue back to the out queue
	 */
	for (i = 0; i < HASHES; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];

		for (pdu=q->head; pdu; pdu=pdu->next) {
			rpc_return_to_queue(&rpc->outqueue, pdu);
			/* we have to re-send the whole pdu again */
			pdu->written = 0;
		}
		rpc_reset_queue(q);
	}

	if (rpc->auto_reconnect != 0) {
		rpc->connect_cb  = reconnect_cb;

		if (rpc_connect_sockaddr_async(rpc, &rpc->s) != 0) {
			rpc_error_all_pdus(rpc, "RPC ERROR: Failed to reconnect async");
			return -1;
		}
	}

	return 0;
}


int rpc_bind_udp(struct rpc_context *rpc, char *addr, int port)
{
	struct addrinfo *ai = NULL;
	char service[6];

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->is_udp == 0) {
		rpc_set_error(rpc, "Cant not bind UDP. Not UDP context");
		return -1;
	}

	sprintf(service, "%d", port);
	if (getaddrinfo(addr, service, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			      "Can not resolv into IPv4/v6 structure.", addr);
		return -1;
 	}

	switch(ai->ai_family) {
	case AF_INET:
		rpc->fd = socket(ai->ai_family, SOCK_DGRAM, 0);
		if (rpc->fd == -1) {
			rpc_set_error(rpc, "Failed to create UDP socket: %s", strerror(errno));
			freeaddrinfo(ai);
			return -1;
		}

		if (bind(rpc->fd, (struct sockaddr *)ai->ai_addr, sizeof(struct sockaddr_in)) != 0) {
			rpc_set_error(rpc, "Failed to bind to UDP socket: %s",strerror(errno));
			freeaddrinfo(ai);
			return -1;
		}
		break;
	default:
		rpc_set_error(rpc, "Can not handle UPD sockets of family %d yet", ai->ai_family);
		freeaddrinfo(ai);
		return -1;
	}

	freeaddrinfo(ai);

	return 0;
}

int rpc_set_udp_destination(struct rpc_context *rpc, char *addr, int port, int is_broadcast)
{
	struct addrinfo *ai = NULL;
	char service[6];

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->is_udp == 0) {
		rpc_set_error(rpc, "Can not set destination sockaddr. Not UDP context");
		return -1;
	}

	sprintf(service, "%d", port);
	if (getaddrinfo(addr, service, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			      "Can not resolv into IPv4/v6 structure.", addr);
		return -1;
 	}

	if (rpc->udp_dest) {
		free(rpc->udp_dest);
		rpc->udp_dest = NULL;
	}
	rpc->udp_dest = malloc(ai->ai_addrlen);
	if (rpc->udp_dest == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate sockaddr structure");
		freeaddrinfo(ai);
		return -1;
	}
	memcpy(rpc->udp_dest, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

	rpc->is_broadcast = is_broadcast;
	setsockopt(rpc->fd, SOL_SOCKET, SO_BROADCAST, (char *)&is_broadcast, sizeof(is_broadcast));

	return 0;
}

struct sockaddr *rpc_get_recv_sockaddr(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return (struct sockaddr *)&rpc->udp_src;
}

int rpc_queue_length(struct rpc_context *rpc)
{
	int i=0;
	struct rpc_pdu *pdu;
	unsigned int n;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	for(pdu = rpc->outqueue.head; pdu; pdu = pdu->next) {
		i++;
	}

	for (n = 0; n < HASHES; n++) {
		struct rpc_queue *q = &rpc->waitpdu[n];

		for(pdu = q->head; pdu; pdu = pdu->next)
			i++;
	}
	return i;
}

void rpc_set_fd(struct rpc_context *rpc, int fd)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->fd = fd;
}
