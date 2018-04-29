/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
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
#include <win32/win32_compat.h>
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
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

static int
rpc_reconnect_requeue(struct rpc_context *rpc);

static int
create_socket(int domain, int type, int protocol)
{
#ifdef SOCK_CLOEXEC
	/* Linux-specific extension (since 2.6.27): set the
	   close-on-exec flag on all sockets to avoid leaking file
	   descriptors to child processes */
	int fd = socket(domain, type|SOCK_CLOEXEC, protocol);
	if (fd >= 0 || errno != EINVAL)
		return fd;
#endif

	return socket(domain, type, protocol);
}

static int
set_nonblocking(int fd)
{
	int v = 0;
#if defined(WIN32)
	u_long nonblocking=1;
	v = ioctl(fd, FIONBIO, &nonblocking);
#else
	v = fcntl(fd, F_GETFL, 0);
	v = fcntl(fd, F_SETFL, v | O_NONBLOCK);
#endif //FIXME
	return v;
}

static void
set_nolinger(int fd)
{
	struct linger lng;
	lng.l_onoff = 1;
	lng.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&lng, sizeof(lng));
}

static int
set_bind_device(int fd, char *ifname)
{
	int rc = 0;

#ifdef HAVE_SO_BINDTODEVICE
	if (*ifname) {
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
                                strlen(ifname));
	}

#endif
	return rc;
}

#ifdef HAVE_NETINET_TCP_H
static int
set_tcp_sockopt(int sockfd, int optname, int value)
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

	return setsockopt(sockfd, level, optname, (char *)&value,
                          sizeof(value));
}
#endif

int
rpc_get_fd(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->old_fd) {
		return rpc->old_fd;
	}

	return rpc->fd;
}

static int
rpc_has_queue(struct rpc_queue *q)
{
	return q->head != NULL;
}

int
rpc_which_events(struct rpc_context *rpc)
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

static int
rpc_write_to_socket(struct rpc_context *rpc)
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

		count = send(rpc->fd, pdu->outdata.data + pdu->written,
                             (int)(total - pdu->written), MSG_NOSIGNAL);
		if (count == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			rpc_set_error(rpc, "Error when writing to socket :%s"
                                      "(%d)", strerror(errno), errno);
			return -1;
		}

		pdu->written += count;
		if (pdu->written == total) {
			unsigned int hash;

			rpc->outqueue.head = pdu->next;
			if (pdu->next == NULL)
				rpc->outqueue.tail = NULL;

                        if (pdu->flags & PDU_DISCARD_AFTER_SENDING) {
                                rpc_free_pdu(rpc, pdu);
                                return 0;
                        }

			hash = rpc_hash_xid(pdu->xid);
			rpc_enqueue(&rpc->waitpdu[hash], pdu);
			rpc->waitpdu_len++;
		}
	}
	return 0;
}

#define MAX_UDP_SIZE 65536
static int
rpc_read_from_socket(struct rpc_context *rpc)
{
	uint32_t pdu_size;
	ssize_t count;
	char *buf;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->is_udp) {
		socklen_t socklen = sizeof(rpc->udp_src);

		buf = malloc(MAX_UDP_SIZE);
		if (buf == NULL) {
			rpc_set_error(rpc, "Failed to malloc buffer for "
                                      "recvfrom");
			return -1;
		}
		count = recvfrom(rpc->fd, buf, MAX_UDP_SIZE, MSG_DONTWAIT,
                                 (struct sockaddr *)&rpc->udp_src, &socklen);
		if (count == -1) {
			free(buf);
			if (errno == EINTR || errno == EAGAIN) {
				return 0;
			}
			rpc_set_error(rpc, "Failed recvfrom: %s",
                                      strerror(errno));
			return -1;
		}
		if (rpc_process_pdu(rpc, buf, count) != 0) {
			rpc_set_error(rpc, "Invalid/garbage pdu received from "
                                      "server. Ignoring PDU");
			free(buf);
			return -1;
		}
		free(buf);
		return 0;
	}

	do {
		/* Read record marker,
                 * 4 bytes at the beginning of every pdu.
                 */
		if (rpc->inpos < 4) {
			buf = (void *)rpc->rm_buf;
			pdu_size = 4;
		} else {
			pdu_size = rpc_get_pdu_size((void *)&rpc->rm_buf);
			if (rpc->inbuf == NULL) {
				if (pdu_size > NFS_MAX_XFER_SIZE + 4096) {
					rpc_set_error(rpc, "Incoming PDU "
                                                      "exceeds limit of %d "
                                                      "bytes.",
                                                      NFS_MAX_XFER_SIZE + 4096);
					return -1;
				}
				rpc->inbuf = malloc(pdu_size);
				if (rpc->inbuf == NULL) {
					rpc_set_error(rpc, "Failed to allocate "
                                                      "buffer of %d bytes for "
                                                      "pdu, errno:%d. Closing "
                                                      "socket.",
                                                      pdu_size, errno);
					return -1;
				}
				memcpy(rpc->inbuf, &rpc->rm_buf, 4);
			}
			buf = rpc->inbuf;
		}

		count = recv(rpc->fd, buf + rpc->inpos, pdu_size - rpc->inpos,
                             MSG_DONTWAIT);
		if (count < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				break;
			}
			rpc_set_error(rpc, "Read from socket failed, errno:%d. "
                                      "Closing socket.", errno);
			return -1;
		}
		if (count == 0) {
			/* remote side has closed the socket. Reconnect. */
			return -1;
		}
		rpc->inpos += count;

		if (rpc->inpos == 4) {
			/* We have just read the header and there is likely
                         * more data available */
			continue;
		}

		if (rpc->inpos == pdu_size) {
			rpc->inbuf  = NULL;
			rpc->inpos  = 0;

			if (rpc_process_pdu(rpc, buf, pdu_size) != 0) {
				rpc_set_error(rpc, "Invalid/garbage pdu "
                                              "received from server. Closing "
                                              "socket");
				free(buf);
				return -1;
			}
			free(buf);
		}
	} while (rpc->is_nonblocking && rpc->waitpdu_len > 0);

	return 0;
}

static void
maybe_call_connect_cb(struct rpc_context *rpc, int status)
{
	rpc_cb tmp_cb = rpc->connect_cb;

	if (rpc->connect_cb == NULL) {
		return;
	}

	rpc->connect_cb = NULL;
	tmp_cb(rpc, status, rpc->error_string, rpc->connect_data);
}

static void
rpc_timeout_scan(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu;
	struct rpc_pdu *next_pdu;
	uint64_t t = rpc_current_time();
	unsigned int i;

	for (pdu = rpc->outqueue.head; pdu; pdu = next_pdu) {
		next_pdu = pdu->next;

		if (pdu->timeout == 0) {
			/* no timeout for this pdu */
			continue;
		}
		if (t < pdu->timeout) {
			/* not expired yet */
			continue;
		}
		LIBNFS_LIST_REMOVE(&rpc->outqueue.head, pdu);
		if (!rpc->outqueue.head) {
			rpc->outqueue.tail = NULL;
		}
		rpc_set_error(rpc, "command timed out");
		pdu->cb(rpc, RPC_STATUS_TIMEOUT,
			NULL, pdu->private_data);
		rpc_free_pdu(rpc, pdu);
	}
	for (i = 0; i < HASHES; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];

		for (pdu = q->head; pdu; pdu = next_pdu) {
			next_pdu = pdu->next;

			if (pdu->timeout == 0) {
				/* no timeout for this pdu */
				continue;
			}
			if (t < pdu->timeout) {
				/* not expired yet */
				continue;
			}
			LIBNFS_LIST_REMOVE(&q->head, pdu);
			if (!q->head) {
				q->tail = NULL;
			}
			rpc_set_error(rpc, "command timed out");
			pdu->cb(rpc, RPC_STATUS_TIMEOUT,
				NULL, pdu->private_data);
			rpc_free_pdu(rpc, pdu);
		}
	}
}

int
rpc_service(struct rpc_context *rpc, int revents)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc_timeout_scan(rpc);

	if (revents == -1 || revents & (POLLERR|POLLHUP)) {
		if (revents != -1 && revents & POLLERR) {

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
		}
		if (revents != -1 && revents & POLLHUP) {
			rpc_set_error(rpc, "Socket failed with POLLHUP");
		}
		if (rpc->auto_reconnect) {
			return rpc_reconnect_requeue(rpc);
		}
		maybe_call_connect_cb(rpc, RPC_STATUS_ERROR);
		return -1;

	}

	if (rpc->is_connected == 0 && rpc->fd != -1 && (revents & POLLOUT)) {
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
			maybe_call_connect_cb(rpc, RPC_STATUS_ERROR);
			return -1;
		}

		rpc->is_connected = 1;
		RPC_LOG(rpc, 2, "connection established on fd %d", rpc->fd);
		maybe_call_connect_cb(rpc, RPC_STATUS_SUCCESS);
		return 0;
	}

	if (revents & POLLIN) {
		if (rpc_read_from_socket(rpc) != 0) {
                        if (rpc->is_server_context) {
                                return -1;
                        } else {
                                return rpc_reconnect_requeue(rpc);
                        }
		}
	}

	if (revents & POLLOUT && rpc_has_queue(&rpc->outqueue)) {
		if (rpc_write_to_socket(rpc) != 0) {
                        if (rpc->is_server_context) {
                                return -1;
                        } else {
                                return rpc_reconnect_requeue(rpc);
                        }
		}
	}

	return 0;
}

void
rpc_set_autoreconnect(struct rpc_context *rpc, int num_retries)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

        /* we can not connect and not reconnect on a server context. */
        if (rpc->is_server_context) {
                return;
        }

	rpc->auto_reconnect = num_retries;
}

void
rpc_set_tcp_syncnt(struct rpc_context *rpc, int v)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->tcp_syncnt = v;
}

#ifndef TCP_SYNCNT
#define TCP_SYNCNT        7
#endif

static int
rpc_connect_sockaddr_async(struct rpc_context *rpc)
{
        struct sockaddr_storage *s = &rpc->s;
        socklen_t socksize;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	switch (s->ss_family) {
	case AF_INET:
		socksize = sizeof(struct sockaddr_in);
		rpc->fd = create_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (set_bind_device(rpc->fd, rpc->ifname) != 0) {
			rpc_set_error (rpc, "Failed to bind to interface");
			return -1;
		}

#ifdef HAVE_NETINET_TCP_H
		if (rpc->tcp_syncnt != RPC_PARAM_UNDEFINED) {
			set_tcp_sockopt(rpc->fd, TCP_SYNCNT, rpc->tcp_syncnt);
		}
#endif
		break;
	case AF_INET6:
		socksize = sizeof(struct sockaddr_in6);
		rpc->fd = create_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (set_bind_device(rpc->fd, rpc->ifname) != 0) {
			rpc_set_error (rpc, "Failed to bind to interface");
			return -1;
		}

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

	if (rpc->old_fd) {
		if (dup2(rpc->fd, rpc->old_fd) == -1) {
			return -1;
		}
		close(rpc->fd);
		rpc->fd = rpc->old_fd;
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
                struct sockaddr_in *sin;
                struct sockaddr_in6 *sin6;
		static int portOfs = 0;
		const int firstPort = 512; /* >= 512 according to Sun docs */
		const int portCount = IPPORT_RESERVED - firstPort;
		int startOfs, port, rc;

                sin  = (struct sockaddr_in *)&ss;
                sin6 = (struct sockaddr_in6 *)&ss;

		if (portOfs == 0) {
			portOfs = rpc_current_time() % 400;
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
					sin->sin_port = port;
					sin->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_LEN
					sin->sin_len =
                                                sizeof(struct sockaddr_in);
#endif
					break;
				case AF_INET6:
					sin6->sin6_port = port;
					sin6->sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_LEN
					sin6->sin6_len =
                                                sizeof(struct sockaddr_in6);
#endif
					break;
				}

				rc = bind(rpc->fd, (struct sockaddr *)&ss,
                                          socksize);
#if !defined(WIN32)
				/* we got EACCES, so don't try again */
				if (rc != 0 && errno == EACCES)
					break;
#endif
			}
		} while (rc != 0 && portOfs != startOfs);
	}

	rpc->is_nonblocking = !set_nonblocking(rpc->fd);
	set_nolinger(rpc->fd);

	if (connect(rpc->fd, (struct sockaddr *)s, socksize) != 0 &&
            errno != EINPROGRESS) {
		rpc_set_error(rpc, "connect() to server failed. %s(%d)",
                              strerror(errno), errno);
		return -1;
	}

	return 0;
}

static int
rpc_set_sockaddr(struct rpc_context *rpc, const char *server, int port)
{
	struct addrinfo *ai = NULL;

	if (getaddrinfo(server, NULL, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			      "Can not resolv into IPv4/v6 structure.", server);
		return -1;
 	}

	switch (ai->ai_family) {
	case AF_INET:
		((struct sockaddr_in *)&rpc->s)->sin_family = ai->ai_family;
		((struct sockaddr_in *)&rpc->s)->sin_port = htons(port);
		((struct sockaddr_in *)&rpc->s)->sin_addr =
                        ((struct sockaddr_in *)(void *)(ai->ai_addr))->sin_addr;
#ifdef HAVE_SOCKADDR_LEN
		((struct sockaddr_in *)&rpc->s)->sin_len =
                        sizeof(struct sockaddr_in);
#endif
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)&rpc->s)->sin6_family = ai->ai_family;
		((struct sockaddr_in6 *)&rpc->s)->sin6_port = htons(port);
		((struct sockaddr_in6 *)&rpc->s)->sin6_addr =
                        ((struct sockaddr_in6 *)(void *)(ai->ai_addr))->sin6_addr;
#ifdef HAVE_SOCKADDR_LEN
		((struct sockaddr_in6 *)&rpc->s)->sin6_len =
                        sizeof(struct sockaddr_in6);
#endif
		break;
	}
	freeaddrinfo(ai);

        return 0;
}

int
rpc_connect_async(struct rpc_context *rpc, const char *server, int port,
                  rpc_cb cb, void *private_data)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

        if (rpc->is_server_context) {
		rpc_set_error(rpc, "Can not connect on a server context");
                return -1;
        }

	if (rpc->fd != -1) {
		rpc_set_error(rpc, "Trying to connect while already connected");
		return -1;
	}

	if (rpc->is_udp != 0) {
		rpc_set_error(rpc, "Trying to connect on UDP socket");
		return -1;
	}

	rpc->auto_reconnect = 0;

        if (rpc_set_sockaddr(rpc, server, port) != 0) {
                return -1;
        }

	rpc->connect_cb  = cb;
	rpc->connect_data = private_data;

	if (rpc_connect_sockaddr_async(rpc) != 0) {
		return -1;
	}

	return 0;
}

int
rpc_disconnect(struct rpc_context *rpc, const char *error)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	/* Do not re-disconnect if we are already disconnected */
	if (!rpc->is_connected) {
		return 0;
	}
	/* Disable autoreconnect */
	rpc_set_autoreconnect(rpc, 0);

	if (rpc->fd != -1) {
		close(rpc->fd);
	}
	rpc->fd  = -1;

	rpc->is_connected = 0;

        if (!rpc->is_server_context) {
                rpc_error_all_pdus(rpc, error);
        }

	return 0;
}

static void
reconnect_cb(struct rpc_context *rpc, int status, void *data _U_,
             void *private_data)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (status != RPC_STATUS_SUCCESS) {
		rpc_set_error(rpc, "Failed to reconnect async");
		rpc_reconnect_requeue(rpc);
		return;
	}

	rpc->is_connected = 1;
	rpc->connect_cb   = NULL;
	rpc->old_fd = 0;
}

/* Disconnect but do not error all PDUs, just move pdus in-flight back to the
 * outqueue and reconnect.
 */
static int
rpc_reconnect_requeue(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu, *next;
	unsigned int i;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->auto_reconnect == 0) {
		RPC_LOG(rpc, 1, "reconnect is disabled");
		rpc_error_all_pdus(rpc, "RPC ERROR: Failed to reconnect async");
		return -1;
	}

	if (rpc->is_connected) {
		rpc->num_retries = rpc->auto_reconnect;
	}

	if (rpc->fd != -1) {
		rpc->old_fd = rpc->fd;
	}
	rpc->fd  = -1;
	rpc->is_connected = 0;

	if (rpc->outqueue.head) {
		rpc->outqueue.head->written = 0;
	}

	/* Socket is closed so we will not get any replies to any commands
	 * in flight. Move them all over from the waitpdu queue back to the
         * out queue.
	 */
	for (i = 0; i < HASHES; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];
		for (pdu = q->head; pdu; pdu = next) {
			next = pdu->next;
			rpc_return_to_queue(&rpc->outqueue, pdu);
			/* we have to re-send the whole pdu again */
			pdu->written = 0;
		}
		rpc_reset_queue(q);
	}
	rpc->waitpdu_len = 0;

	if (rpc->auto_reconnect < 0 || rpc->num_retries > 0) {
		rpc->num_retries--;
		rpc->connect_cb  = reconnect_cb;
		RPC_LOG(rpc, 1, "reconnect initiated");
		if (rpc_connect_sockaddr_async(rpc) != 0) {
			rpc_error_all_pdus(rpc, "RPC ERROR: Failed to "
                                           "reconnect async");
			return -1;
		}
		return 0;
	}

	RPC_LOG(rpc, 1, "reconnect: all attempts failed.");
	rpc_error_all_pdus(rpc, "RPC ERROR: All attempts to reconnect failed.");
	return -1;
}


int
rpc_bind_udp(struct rpc_context *rpc, char *addr, int port)
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
		rpc->fd = create_socket(ai->ai_family, SOCK_DGRAM, 0);
		if (rpc->fd == -1) {
			rpc_set_error(rpc, "Failed to create UDP socket: %s",
                                      strerror(errno));
			freeaddrinfo(ai);
			return -1;
		}

		if (bind(rpc->fd, (struct sockaddr *)ai->ai_addr,
                         sizeof(struct sockaddr_in)) != 0) {
			rpc_set_error(rpc, "Failed to bind to UDP socket: %s",
                                      strerror(errno));
			freeaddrinfo(ai);
			return -1;
		}
		break;
	default:
		rpc_set_error(rpc, "Can not handle UPD sockets of family %d "
                              "yet", ai->ai_family);
		freeaddrinfo(ai);
		return -1;
	}

	freeaddrinfo(ai);

	return 0;
}

int
rpc_set_udp_destination(struct rpc_context *rpc, char *addr, int port,
                        int is_broadcast)
{
	struct addrinfo *ai = NULL;
	char service[6];

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->is_udp == 0) {
		rpc_set_error(rpc, "Can not set destination sockaddr. Not UDP "
                              "context");
		return -1;
	}

	sprintf(service, "%d", port);
	if (getaddrinfo(addr, service, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			      "Can not resolv into IPv4/v6 structure.", addr);
		return -1;
 	}

	memcpy(&rpc->udp_dest, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

	rpc->is_broadcast = is_broadcast;
	setsockopt(rpc->fd, SOL_SOCKET, SO_BROADCAST, (char *)&is_broadcast,
                   sizeof(is_broadcast));

	return 0;
}

struct sockaddr *
rpc_get_recv_sockaddr(struct rpc_context *rpc)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	return (struct sockaddr *)&rpc->udp_src;
}

int
rpc_queue_length(struct rpc_context *rpc)
{
	int i = 0;
	struct rpc_pdu *pdu;

	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	for(pdu = rpc->outqueue.head; pdu; pdu = pdu->next) {
		i++;
	}

	i += rpc->waitpdu_len;

	return i;
}

void
rpc_set_fd(struct rpc_context *rpc, int fd)
{
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	rpc->fd = fd;
}

int
rpc_is_udp_socket(struct rpc_context *rpc)
{
#ifdef WIN32
        char type = 0;
#else
        int type = 0;
#endif
        socklen_t len = sizeof(type);

        getsockopt(rpc->fd, SOL_SOCKET, SO_TYPE, &type, &len);
        return type == SOCK_DGRAM;
}
