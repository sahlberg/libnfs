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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-private.h"
#include "slist.h"

static void set_nonblocking(int fd)
{
	unsigned v;
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

int rpc_get_fd(struct rpc_context *rpc)
{
	return rpc->fd;
}

int rpc_which_events(struct rpc_context *rpc)
{
	int events = rpc->is_connected ? POLLIN : POLLOUT;

	if (rpc->is_udp != 0) {
		/* for udp sockets we only wait for pollin */
		return POLLIN;
	}

	if (rpc->outqueue) {
		events |= POLLOUT;
	}
	return events;
}

static int rpc_write_to_socket(struct rpc_context *rpc)
{
	ssize_t count;

	if (rpc == NULL) {
		return -1;
	}
	if (rpc->fd == -1) {
		rpc_set_error(rpc, "trying to write but not connected");
		return -1;
	}

	while (rpc->outqueue != NULL) {
		ssize_t total;

		total = rpc->outqueue->outdata.size;

		count = write(rpc->fd, rpc->outqueue->outdata.data + rpc->outqueue->written, total - rpc->outqueue->written);
		if (count == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			rpc_set_error(rpc, "Error when writing to socket :%s(%d)", strerror(errno), errno);
			return -1;
		}

		rpc->outqueue->written += count;
		if (rpc->outqueue->written == total) {
			struct rpc_pdu *pdu = rpc->outqueue;

	       	    	SLIST_REMOVE(&rpc->outqueue, pdu);
			SLIST_ADD_END(&rpc->waitpdu, pdu);
		}
	}
	return 0;
}

static int rpc_read_from_socket(struct rpc_context *rpc)
{
	int available;
	int size;
	int pdu_size;
	ssize_t count;

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

		count = read(rpc->fd, rpc->inbuf + rpc->inpos, size);
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

	count = read(rpc->fd, rpc->inbuf + rpc->inpos, size);
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
		if (rpc_process_pdu(rpc, rpc->inbuf, pdu_size) != 0) {
			rpc_set_error(rpc, "Invalid/garbage pdu received from server. Closing socket");
			return -1;
		}
		free(rpc->inbuf);
		rpc->inbuf  = NULL;
		rpc->insize = 0;
		rpc->inpos  = 0;
	}

	return 0;
}



int rpc_service(struct rpc_context *rpc, int revents)
{
	if (revents & POLLERR) {
		int err = 0;
		socklen_t err_size = sizeof(err);

		if (getsockopt(rpc->fd, SOL_SOCKET, SO_ERROR,
				&err, &err_size) != 0 || err != 0) {
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
		rpc->connect_cb(rpc, RPC_STATUS_ERROR, rpc->error_string, rpc->connect_data);
		return -1;
	}
	if (revents & POLLHUP) {
		rpc_set_error(rpc, "Socket failed with POLLHUP");
		rpc->connect_cb(rpc, RPC_STATUS_ERROR, rpc->error_string, rpc->connect_data);
		return -1;
	}

	if (rpc->is_connected == 0 && rpc->fd != -1 && revents&POLLOUT) {
		int err = 0;
		socklen_t err_size = sizeof(err);

		if (getsockopt(rpc->fd, SOL_SOCKET, SO_ERROR,
				&err, &err_size) != 0 || err != 0) {
			if (err == 0) {
				err = errno;
			}
			rpc_set_error(rpc, "rpc_service: socket error "
				  	"%s(%d) while connecting.",
					strerror(err), err);
			rpc->connect_cb(rpc, RPC_STATUS_ERROR,
					NULL, rpc->connect_data);
			return -1;
		}

		rpc->is_connected = 1;
		rpc->connect_cb(rpc, RPC_STATUS_SUCCESS, NULL, rpc->connect_data);
		return 0;
	}

	if (revents & POLLOUT && rpc->outqueue != NULL) {
		if (rpc_write_to_socket(rpc) != 0) {
			rpc_set_error(rpc, "write to socket failed");
			return -1;
		}
	}

	if (revents & POLLIN) {
		if (rpc_read_from_socket(rpc) != 0) {
			rpc_disconnect(rpc, rpc_get_error(rpc));
			return -1;
		}
	}

	return 0;
}


int rpc_connect_async(struct rpc_context *rpc, const char *server, int port, rpc_cb cb, void *private_data)
{
	struct sockaddr_storage s;
	struct sockaddr_in *sin = (struct sockaddr_in *)&s;
	int socksize;

	if (rpc->fd != -1) {
		rpc_set_error(rpc, "Trying to connect while already connected");
		return -1;
	}

	if (rpc->is_udp != 0) {
		rpc_set_error(rpc, "Trying to connect on UDP socket");
		return -1;
	}

	sin->sin_family = AF_INET;
	sin->sin_port   = htons(port);
	if (inet_pton(AF_INET, server, &sin->sin_addr) != 1) {
		rpc_set_error(rpc, "Not a valid server ip address");
		return -1;
	}

	switch (s.ss_family) {
	case AF_INET:
		socksize = sizeof(struct sockaddr_in);
#ifdef HAVE_SOCKADDR_LEN
		sin->sin_len = socksize;
#endif
		rpc->fd = socket(AF_INET, SOCK_STREAM, 0);
		break;
	}

	if (rpc->fd == -1) {
		rpc_set_error(rpc, "Failed to open socket");
		return -1;
	}

	rpc->connect_cb  = cb;
	rpc->connect_data = private_data;

	set_nonblocking(rpc->fd);

	if (connect(rpc->fd, (struct sockaddr *)&s, socksize) != 0 && errno != EINPROGRESS) {
		rpc_set_error(rpc, "connect() to server failed");
		return -1;
	}		

	return 0;
}	    

int rpc_disconnect(struct rpc_context *rpc, char *error)
{
	if (rpc->fd != -1) {
		close(rpc->fd);
	}
	rpc->fd  = -1;

	rpc->is_connected = 0;

	rpc_error_all_pdus(rpc, error);

	return 0;
}


int rpc_bind_udp(struct rpc_context *rpc, char *addr, int port)
{
	struct addrinfo *ai = NULL;
	char service[6];

	if (rpc->is_udp == 0) {
		rpc_set_error(rpc, "Cant not bind UDP. Not UDP context");
		return -1;
	}

	snprintf(service, 6, "%d", port);
	if (getaddrinfo(addr, service, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			"Can not resolv into IPv4/v6 structure.");
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

	if (rpc->is_udp == 0) {
		rpc_set_error(rpc, "Can not set destination sockaddr. Not UDP context");
		return -1;
	}

	snprintf(service, 6, "%d", port);
	if (getaddrinfo(addr, service, NULL, &ai) != 0) {
		rpc_set_error(rpc, "Invalid address:%s. "
			"Can not resolv into IPv4/v6 structure.");
		return -1;
 	}

	if (rpc->udp_dest) {
		free(rpc->udp_dest);
		rpc->udp_dest = NULL;
	}
	rpc->udp_dest = malloc(ai->ai_addrlen);
	if (rpc->udp_dest == NULL) {
		rpc_set_error(rpc, "Out of memory. Failed to allocate sockaddr structure");
		return -1;
	}
	memcpy(rpc->udp_dest, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

	rpc->is_broadcast = is_broadcast;
	setsockopt(rpc->fd, SOL_SOCKET, SO_BROADCAST, &is_broadcast, sizeof(is_broadcast));

	return 0;
}

struct sockaddr *rpc_get_recv_sockaddr(struct rpc_context *rpc)
{
	return (struct sockaddr *)&rpc->udp_src;
}
