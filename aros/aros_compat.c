
#ifdef AROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include "aros_compat.h"

#undef poll

int aros_getnameinfo(const struct sockaddr *sa, socklen_t salen,
char *host, size_t hostlen,
char *serv, size_t servlen, int flags)
{
  struct sockaddr_in *sin = (struct sockaddr_in *)sa;

  if (host) {
    snprintf(host, hostlen, Inet_NtoA(sin->sin_addr.s_addr));
  }

  return 0;
}

int aros_getaddrinfo(const char *node, const char*service,
const struct addrinfo *hints,
struct addrinfo **res)
{
  struct sockaddr_in *sin;

  sin = malloc(sizeof(struct sockaddr_in));
  sin->sin_len = sizeof(struct sockaddr_in);
  sin->sin_family=AF_INET;

  /* Some error checking would be nice */
  sin->sin_addr.s_addr = inet_addr(node);

  sin->sin_port=0;
  if (service) {
    sin->sin_port=atoi(service);
  } 

  *res = malloc(sizeof(struct addrinfo));

  (*res)->ai_family = AF_INET;
  (*res)->ai_addrlen = sizeof(struct sockaddr_in);
  (*res)->ai_addr = (struct sockaddr *)sin;

  return 0;
}

void aros_freeaddrinfo(struct addrinfo *res)
{
  free(res->ai_addr);
  free(res);
}

int aros_inet_pton(int af, char *src, void *dst)
{
  printf("No inet_pton yet");
  exit(10);
}


/* unix device numbers dont really make much sense on aros ... */
int major(int i)
{
  return 1;
}
int minor(int i)
{
  return 2;
}

struct Library * SocketBase = NULL;

void aros_init_socket(void)
{
  if (!(SocketBase = OpenLibrary("bsdsocket.library", 4))) {
    printf("NoTCP/IP Stack available");
    exit(10);
  }
}

int aros_poll(struct pollfd *fds, unsigned int nfds, int timo)
{
  struct timeval timeout, *toptr;
  fd_set ifds, ofds, efds, *ip, *op;
  unsigned int i;
  int  rc;

  // Set up the file-descriptor sets in ifds, ofds and efds. 
  FD_ZERO(&ifds);
  FD_ZERO(&ofds);
  FD_ZERO(&efds);
  for (i = 0, op = ip = 0; i < nfds; ++i) 
  {
    fds[i].revents = 0;
    if(fds[i].events & (POLLIN|POLLPRI)) 
    {
      ip = &ifds;
      FD_SET(fds[i].fd, ip);
    }
    if(fds[i].events & POLLOUT) 
    {
      op = &ofds;
      FD_SET(fds[i].fd, op);
    }
    FD_SET(fds[i].fd, &efds);
  } 

  // Set up the timeval structure for the timeout parameter
  if(timo < 0) 
  {
    toptr = 0;
  } 
  else 
  {
    toptr = &timeout;
    timeout.tv_sec = timo / 1000;
    timeout.tv_usec = (timo - timeout.tv_sec * 1000) * 1000;
  }

  rc = WaitSelect(0, ip, op, &efds, toptr, NULL);

  if(rc <= 0)
    return rc;

  if(rc > 0) 
  {
    for (i = 0; i < nfds; ++i) 
    {
      int fd = fds[i].fd;
      if(fds[i].events & (POLLIN|POLLPRI) && FD_ISSET(fd, &ifds))
        fds[i].revents |= POLLIN;
      if(fds[i].events & POLLOUT && FD_ISSET(fd, &ofds))
        fds[i].revents |= POLLOUT;
      if(FD_ISSET(fd, &efds)) // Some error was detected ... should be some way to know.
        fds[i].revents |= POLLHUP;
    }
  }
  return rc;
}

#endif

