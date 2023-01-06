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

#ifdef PS2_EE
#include "ps2_compat.h"
#endif

#ifdef PS3_PPU
#include "ps3_compat.h"
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

#if defined(HAVE_SYS_UIO_H) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/uio.h>
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

#ifndef MSG_NOSIGNAL
#if (defined(__APPLE__) && defined(__MACH__)) || defined(PS2_EE)
#define MSG_NOSIGNAL 0
#endif
#endif

static int
rpc_reconnect_requeue(struct rpc_context *rpc);

static int
create_socket(int domain, int type, int protocol)
{
#ifdef SOCK_CLOEXEC
#ifdef __linux__
    /* Linux-specific extension (since 2.6.27): set the
	   close-on-exec flag on all sockets to avoid leaking file
	   descriptors to child processes */
	int fd = socket(domain, type|SOCK_CLOEXEC, protocol);
	if (fd >= 0 || errno != EINVAL)
		return fd;
#endif
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
#endif
	return v;
}

static void
set_nolinger(int fd)
{
#if !defined(PS2_EE)        
	struct linger lng;
	lng.l_onoff = 1;
	lng.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&lng, sizeof(lng));
#endif
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

	#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__sun) || (defined(__APPLE__) && defined(__MACH__))
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

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	if (rpc_has_queue(&rpc->outqueue)) {
		events |= POLLOUT;
	}
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	return events;
}

int
rpc_write_to_socket(struct rpc_context *rpc)
{
	struct rpc_pdu *pdu;
	struct iovec iov[RPC_MAX_VECTORS];
        int ret = 0;
        
	assert(rpc->magic == RPC_CONTEXT_MAGIC);

	if (rpc->fd == -1) {
		rpc_set_error(rpc, "trying to write but not connected");
		return -1;
	}

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

        /* Write several pdus at once */
	while ((pdu = rpc->outqueue.head) != NULL) {
                int niov = 0;
                char *last_buf = NULL;
                ssize_t count;

                do {
                        size_t num_done = pdu->out.num_done;
                        int pdu_niov = pdu->out.niov;
                        int i;

                        for (i = 0; i < pdu_niov; i++) {
                                char *buf = pdu->out.iov[i].buf;
                                size_t len = pdu->out.iov[i].len;
                                if (num_done >= len) {
                                        num_done -= len;
                                        continue;
                                }
                                buf += num_done;
                                len -= num_done;

                                /* Concatenate continous blocks */
                                if (last_buf != buf) {
                                        iov[niov].iov_base = buf;
                                        iov[niov].iov_len = len;
                                        niov++;
                                        if (niov >= RPC_MAX_VECTORS)
                                                break;
                                        last_buf = (buf + len);
                                } else {
                                        iov[niov - 1].iov_len += len;
                                        last_buf += len;
                                }
                        }

                        pdu = pdu->next;
                } while (pdu != NULL && niov < RPC_MAX_VECTORS);

                count = writev(rpc->fd, iov, niov);
                if (count == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                ret = 0;
                                 goto finished;

                        }
                        rpc_set_error(rpc, "Error when writing to "
                                      "socket :%d %s", errno,
                                      rpc_get_error(rpc));
                        ret = -1;
                        goto finished;
                }

                /* Check how many pdu we completed */
                while (count > 0 && (pdu = rpc->outqueue.head) != NULL) {
                        size_t remaining = (pdu->out.total_size - pdu->out.num_done);
                        if (remaining <= count) {
                                unsigned int hash;

                                count -= remaining;

                                pdu->out.num_done = pdu->out.total_size;

                                rpc->outqueue.head = pdu->next;
                                if (pdu->next == NULL)
                                        rpc->outqueue.tail = NULL;

                                if (pdu->flags & PDU_DISCARD_AFTER_SENDING) {
                                        rpc_free_pdu(rpc, pdu);
                                        ret = 0;
                                        goto finished;
                                }

                                hash = rpc_hash_xid(rpc, pdu->xid);
                                rpc_enqueue(&rpc->waitpdu[hash], pdu);
                                rpc->waitpdu_len++;

                        } else {
                                pdu->out.num_done += count;
                                break;
                        }
                }
	}

 finished:
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	return ret;
}

static int adjust_inbuf(struct rpc_context *rpc, uint32_t pdu_size)
{
        char *buf;

        if (rpc->inbuf_size < pdu_size) {
                if (pdu_size > NFS_MAX_XFER_SIZE + 4096) {
                        rpc_set_error(rpc, "Incoming PDU exceeds limit of %d "
                                      "bytes.", NFS_MAX_XFER_SIZE + 4096);
                        return -1;
                }
                buf = realloc(rpc->inbuf, pdu_size);
                if (buf == NULL) {
                        rpc_set_error(rpc, "Failed to allocate buffer of %d "
                                      "bytes for pdu, errno:%d. Closing "
                                      "socket.", (int)pdu_size, errno);
                        return -1;
                }
                rpc->inbuf_size = pdu_size;
                rpc->inbuf = buf;
        }
        return 0;
}

static char *rpc_reassemble_pdu(struct rpc_context *rpc, uint32_t *pdu_size)
{
        struct rpc_fragment *fragment;
 	char *reasbuf = NULL, *ptr;
        uint32_t size;

        size = rpc->inpos;
        for (fragment = rpc->fragments; fragment; fragment = fragment->next) {
                size += fragment->size;
                if (size < fragment->size) {
                        rpc_set_error(rpc, "Fragments too large");
                        rpc_free_all_fragments(rpc);
                        return NULL;
                }
        }

        reasbuf = malloc(size);
        if (reasbuf == NULL) {
                rpc_set_error(rpc, "Failed to reassemble PDU");
                rpc_free_all_fragments(rpc);
                return NULL;
        }
        ptr = reasbuf;
        for (fragment = rpc->fragments; fragment; fragment = fragment->next) {
                memcpy(ptr, fragment->data, fragment->size);
                ptr += fragment->size;
        }
        memcpy(ptr, rpc->inbuf, rpc->inpos);

        *pdu_size = size;
        return reasbuf;
}

static void rpc_finished_pdu(struct rpc_context *rpc)
{
        if (rpc->pdu && rpc->pdu->free_pdu) {
                rpc->pdu->cb(rpc, RPC_STATUS_SUCCESS, rpc->pdu->zdr_decode_buf, rpc->pdu->private_data);
        }
        if (rpc->pdu && rpc->pdu->free_zdr) {
                zdr_destroy(&rpc->pdu->zdr);
        }
        rpc->state = READ_RM;
        rpc->inpos  = 0;
        if (rpc->is_udp == 0 || rpc->is_broadcast == 0) {
                rpc_free_pdu(rpc, rpc->pdu);
                rpc->pdu = NULL;
        }
}

#define MAX_UDP_SIZE 65536
#define MAX_FRAGMENT_SIZE 8*1024*1024
static int
rpc_read_from_socket(struct rpc_context *rpc)
{
	static uint32_t pdu_size = 0;
	static char *buf = NULL;
	ssize_t count;
        int pos;

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
                if (rpc->inpos == 0) {
                        switch (rpc->state) {
                        case READ_RM:
                                /*
                                 * Read record marker,
                                 * And if this is a cleint context read the next 4 bytes
                                 * i.e. the XID on a client
                                 */
                                pdu_size = 8;
                                buf = (char *)&rpc->rm_xid[0];
                                rpc->pdu = NULL;
                                break;
                        case READ_PAYLOAD:
                                /* we already read 4 bytes into the buffer */
                                rpc->inpos = 4;
                                pdu_size = rpc->rm_xid[0];
                                buf = rpc->inbuf + rpc->inpos;

                                /*
                                 * If it is a READ pdu, just read part of the data
                                 * to the buffer and read the remainder directly into
                                 * the application iovec. 1024 is big enough to
                                 * "guarantee" that we get the whole onc-rpc as well
                                 * as the read3res header into the buffer.
                                 * I don't want to have to deal with reading too
                                 * little here and having to increase the limit and
                                 * restart unmarshalling from scratch.
                                 */
                                /* We do not have rpc->pdu for server context */
                                if (rpc->pdu && rpc->pdu->in.buf && pdu_size > 1024) {
                                        pdu_size = 1024;
                                }
                                break;
                        case READ_UNKNOWN:
                        case READ_FRAGMENT:
                                /* we already read 4 bytes into the buffer */
                                rpc->inpos = 4;
                                pdu_size = rpc->rm_xid[0];
                                buf = rpc->inbuf + rpc->inpos;
                                break;
                        case READ_IOVEC:
                                buf = &rpc->pdu->in.buf[rpc->pdu->inpos];
                                pdu_size = rpc->pdu->read_count;
                                break;
                        case READ_PADDING:
                                pdu_size = rpc->rm_xid[0];
                                buf = rpc->inbuf;
                                break;
                        }
                }

                count = pdu_size - rpc->inpos;
		count = recv(rpc->fd, buf, count, MSG_DONTWAIT);
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
                buf += count;
                
                if (rpc->inpos == pdu_size) {
                        switch (rpc->state) {
                        case READ_RM:
                                /* We have just read the record marker */
                                rpc->rm_xid[0] = ntohl(rpc->rm_xid[0]);
                                if (rpc->rm_xid[0] & 0x80000000) {
                                        rpc->state = READ_PAYLOAD;
                                } else {
                                        rpc_set_error(rpc, "Fragment support not yet working");
                                        rpc->state = READ_FRAGMENT;
                                        return -1;
                                }
                                rpc->rm_xid[0] &= 0x7fffffff;
                                if (rpc->rm_xid[0] < 8 || rpc->rm_xid[0] > MAX_FRAGMENT_SIZE) {
                                        rpc_set_error(rpc, "Invalid recordmarker size");
                                        return -1;
                                }
                                adjust_inbuf(rpc, rpc->rm_xid[0]);
                                /* Copy the next 4 bytes into inbuf */
                                memcpy(rpc->inbuf, &rpc->rm_xid[1], 4);
                                /* but set inpos to 0, we will update it above
                                 * that we have already read these 4 bytes in
                                 * PAYLOAD and FRAGMENT
                                 */
                                rpc->inpos = 0;   
                                rpc->rm_xid[1] = ntohl(rpc->rm_xid[1]);
                                if (!rpc->is_server_context) {
                                        rpc->pdu = rpc_find_pdu(rpc, rpc->rm_xid[1]);
                                        /* Unknown xid, either unsolicited
                                         * or an xid we have cancelled
                                         */
                                        if (rpc->pdu == NULL) {
                                                rpc->state = READ_UNKNOWN;
                                                continue;
                                        }
                                }
                                continue;
                        case READ_FRAGMENT:
                                if (rpc_add_fragment(rpc, rpc->inbuf, rpc->inpos) != 0) {
                                        rpc_set_error(rpc, "Failed to queue fragment for reassembly.");
                                        return -1;
                                }
                                rpc->state = READ_RM;
                                rpc->inpos  = 0;
                                continue;
                        case READ_UNKNOWN:
                                rpc->state = READ_RM;
                                rpc->inpos  = 0;
                                continue;
                        case READ_PAYLOAD:
                                if (rpc->fragments) {
                                        buf = rpc_reassemble_pdu(rpc, &pdu_size);
                                        if (buf == NULL) {
                                                return -1;
                                        }
                                } else {
                                        buf = rpc->inbuf;
                                }
                                if (rpc_process_pdu(rpc, buf, pdu_size) != 0) {
                                        rpc_set_error(rpc, "Invalid/garbage pdu"
                                                      " received from server. "
                                                      "Closing socket");
                                        return -1;
                                }
                                /* We do not have rpc->pdu for server context */
                                if (rpc->pdu && rpc->pdu->free_zdr) {
                                        /* We have zero-copy read */
                                        if (!zdr_uint32_t(&rpc->pdu->zdr, &rpc->pdu->read_count))
                                                return -1;
                                        pos = zdr_getpos(&rpc->pdu->zdr);
                                        count = rpc->inpos - pos;
                                        if (count > rpc->pdu->read_count) {
                                                count = rpc->pdu->read_count;
                                        }
                                        if (rpc->pdu->in.len > rpc->pdu->read_count) {
                                                /* we got a short read */
                                                rpc->pdu->in.len = rpc->pdu->read_count;
                                        }
                                        if (rpc->pdu->in.len <= count) {
                                                memcpy(rpc->pdu->in.buf, &rpc->inbuf[pos], rpc->pdu->in.len);
                                        } else {
                                                memcpy(rpc->pdu->in.buf, &rpc->inbuf[pos], count);
                                                rpc->pdu->inpos = count;
                                                rpc->pdu->read_count -= count;
                                                rpc->state = READ_IOVEC;
                                                rpc->inpos  = 0;
                                                rpc->rm_xid[0] -= pos + count;
                                                continue;
                                        }
                                }
                                if (rpc->fragments) {
                                        free(buf);
                                        rpc_free_all_fragments(rpc);
                                }
                                rpc_finished_pdu(rpc);
                                break;
                        case READ_IOVEC:
                                rpc->pdu->inpos += pdu_size;
                                rpc->pdu->read_count -= pdu_size;
                                rpc->rm_xid[0] -= pdu_size;
                                if (!rpc->rm_xid[0]) {
                                        rpc_finished_pdu(rpc);
                                        break;
                                }
                                rpc->state = READ_PADDING;
                                rpc->inpos  = 0;
                                continue;
                        case READ_PADDING:
                                rpc_finished_pdu(rpc);
                                break;
                        }
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

        /*
         * Only scan once per second.
         */
        if (t <= rpc->last_timeout_scan + 1000) {
                return;
        }
        rpc->last_timeout_scan = t;

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
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
			rpc->outqueue.tail = NULL; //done
		}
		rpc_set_error(rpc, "command timed out");
		pdu->cb(rpc, RPC_STATUS_TIMEOUT,
			NULL, pdu->private_data);
		rpc_free_pdu(rpc, pdu);
	}
	for (i = 0; i < rpc->num_hashes; i++) {
		struct rpc_queue *q;

                q = &rpc->waitpdu[i];
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
                        // qqq move to a temporary queue and process after
                        // we drop the mutex
			rpc_set_error(rpc, "command timed out");
			pdu->cb(rpc, RPC_STATUS_TIMEOUT,
				NULL, pdu->private_data);
			rpc_free_pdu(rpc, pdu);
		}
	}
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
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
#if !defined(WIN32) && !defined(PS3_PPU) && !defined(PS2_EE)
		if (dup2(rpc->fd, rpc->old_fd) == -1) {
			return -1;
		}
		close(rpc->fd);
		rpc->fd = rpc->old_fd;
#else
		/* On Windows dup2 does not work on sockets
		 * instead just close the old socket */
		close(rpc->old_fd);
		rpc->old_fd = 0;
#endif
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
#if !defined(PS3_PPU) && !defined(PS2_EE)
				case AF_INET6:
					sin6->sin6_port = port;
					sin6->sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_LEN
					sin6->sin6_len =
                                                sizeof(struct sockaddr_in6);
#endif
					break;
#endif
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
#if !defined(PS3_PPU) && !defined(PS2_EE)
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
#endif
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

        maybe_call_connect_cb(rpc, RPC_STATUS_CANCEL);
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
		rpc->outqueue.head->out.num_done = 0;
	}

	/* Socket is closed so we will not get any replies to any commands
	 * in flight. Move them all over from the waitpdu queue back to the
         * out queue.
	 */
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	for (i = 0; i < rpc->num_hashes; i++) {
		struct rpc_queue *q = &rpc->waitpdu[i];
		for (pdu = q->head; pdu; pdu = next) {
			next = pdu->next;
			rpc_return_to_queue(&rpc->outqueue, pdu);
			/* we have to re-send the whole pdu again */
			pdu->out.num_done = 0;
		}
		rpc_reset_queue(q);
	}
	rpc->waitpdu_len = 0;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

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

	rpc->is_broadcast = is_broadcast;
	setsockopt(rpc->fd, SOL_SOCKET, SO_BROADCAST, (char *)&is_broadcast, sizeof(is_broadcast));

	memcpy(&rpc->udp_dest, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

        if (!is_broadcast) {
                if (connect(rpc->fd, (struct sockaddr *)&rpc->udp_dest, sizeof(rpc->udp_dest)) != 0 && errno != EINPROGRESS) {
                        rpc_set_error(rpc, "connect() to UDP address failed. %s(%d)", strerror(errno), errno);
                        return -1;
                }
        }

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

#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_lock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */
	i += rpc->waitpdu_len;
#ifdef HAVE_MULTITHREADING
        if (rpc->multithreading_enabled) {
                nfs_mt_mutex_unlock(&rpc->rpc_mutex);
        }
#endif /* HAVE_MULTITHREADING */

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
