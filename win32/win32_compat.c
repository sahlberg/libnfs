/*
Copyright (c) 2006 by Dan Kennedy.
Copyright (c) 2006 by Juliusz Chroboczek.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef WIN32

static int dummy ATTRIBUTE((unused));

#else
#include "win32_compat.h"
#include <errno.h>
#include <stdio.h>
#undef poll
#undef socket
#undef connect
#undef accept
#undef shutdown
#undef getpeername
#undef sleep
#undef inet_aton
#undef gettimeofday
#undef stat
#define bzero(a,b) memset((a),(0),(b))
#define assert(a)

/* Windows needs this header file for the implementation of inet_aton() */
#include <ctype.h>

int win32_inet_pton(int af, const char * src, void * dst)
{
   int temp = sizeof(struct sockaddr_in);
   char *srcNonConst = (char *)malloc(strlen(src)+1);
   strncpy(srcNonConst,src,strlen(src));
   WSAStringToAddress(srcNonConst,af,NULL,(LPSOCKADDR)dst,&temp);
   return temp;
}

/* 
 * Check whether "cp" is a valid ascii representation of an Internet address
 * and convert to a binary address.  Returns 1 if the address is valid, 0 if
 * not.  This replaces inet_addr, the return value from which cannot
 * distinguish between failure and a local broadcast address.
 *
 * This implementation of the standard inet_aton() function was copied 
 * (with trivial modifications) from the OpenBSD project.
 */
int
win32_inet_aton(const char *cp, struct in_addr *addr)
{
    register unsigned int val;
    register int base, n;
    register char c;
    unsigned int parts[4];
    register unsigned int *pp = parts;

    assert(sizeof(val) == 4);

    c = *cp;
    while(1) {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if(!isdigit(c))
            return (0);
        val = 0; base = 10;
        if(c == '0') {
            c = *++cp;
            if(c == 'x' || c == 'X')
                base = 16, c = *++cp;
            else
                base = 8;
        }
        while(1) {
            if(isascii(c) && isdigit(c)) {
                val = (val * base) + (c - '0');
                c = *++cp;
            } else if(base == 16 && isascii(c) && isxdigit(c)) {
                val = (val << 4) |
                    (c + 10 - (islower(c) ? 'a' : 'A'));
                c = *++cp;
            } else
                break;
        }
        if(c == '.') {
            /*
             * Internet format:
             *    a.b.c.d
             *    a.b.c    (with c treated as 16 bits)
             *    a.b    (with b treated as 24 bits)
             */
            if(pp >= parts + 3)
                return (0);
            *pp++ = val;
            c = *++cp;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if(c != '\0' && (!isascii(c) || !isspace(c)))
        return (0);
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    n = pp - parts + 1;
    switch(n) {

    case 0:
        return (0);        /* initial nondigit */

    case 1:                /* a -- 32 bits */
        break;

    case 2:                /* a.b -- 8.24 bits */
        if((val > 0xffffff) || (parts[0] > 0xff))
            return (0);
        val |= parts[0] << 24;
        break;

    case 3:                /* a.b.c -- 8.8.16 bits */
        if((val > 0xffff) || (parts[0] > 0xff) || (parts[1] > 0xff))
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4:                /* a.b.c.d -- 8.8.8.8 bits */
        if((val > 0xff) || (parts[0] > 0xff) ||
           (parts[1] > 0xff) || (parts[2] > 0xff))
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if(addr)
        addr->s_addr = htonl(val);
    return (1);
}

unsigned int
win32_sleep(unsigned int seconds)
{
    Sleep(seconds * 1000);
    return 0;
}

int win32_poll(struct pollfd *fds, int nfsd, int timeout)
{
  fd_set rfds, wfds, efds;
  int ret;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_ZERO(&efds);
  if (fds->events & POLLIN) 
  {
    FD_SET(fds->fd, &rfds);
  }
  if (fds->events & POLLOUT) 
  {
    FD_SET(fds->fd, &wfds);
  }
  FD_SET(fds->fd, &efds);
  ret = select(fds->fd + 1, &rfds, &wfds, &efds, NULL);
  fds->revents = 0;
  
  if (FD_ISSET(fds->fd, &rfds)) 
  {
    fds->revents |= POLLIN;
  }
  
  if (FD_ISSET(fds->fd, &wfds)) 
  {
    fds->revents |= POLLOUT;
  }
  
  if (FD_ISSET(fds->fd, &efds)) 
  {
    fds->revents |= POLLHUP;
  }
  return ret;
}

/*int win32_poll(struct pollfd *fds, unsigned int nfds, int timo)
{
    struct timeval timeout, *toptr;
    fd_set ifds, ofds, efds, *ip, *op;
    int i, rc;

    // Set up the file-descriptor sets in ifds, ofds and efds. 
    FD_ZERO(&ifds);
    FD_ZERO(&ofds);
    FD_ZERO(&efds);
    for (i = 0, op = ip = 0; i < nfds; ++i) {
	fds[i].revents = 0;
	if(fds[i].events & (POLLIN|POLLPRI)) {
		ip = &ifds;
		FD_SET(fds[i].fd, ip);
	}
	if(fds[i].events & POLLOUT) {
		op = &ofds;
		FD_SET(fds[i].fd, op);
	}
	FD_SET(fds[i].fd, &efds);
    } 

    // Set up the timeval structure for the timeout parameter
    if(timo < 0) {
	toptr = 0;
    } else {
	toptr = &timeout;
	timeout.tv_sec = timo / 1000;
	timeout.tv_usec = (timo - timeout.tv_sec * 1000) * 1000;
    }

#ifdef DEBUG_POLL
    printf("Entering select() sec=%ld usec=%ld ip=%lx op=%lx\n",
           (long)timeout.tv_sec, (long)timeout.tv_usec, (long)ip, (long)op);
#endif
    rc = select(0, ip, op, &efds, toptr);
#ifdef DEBUG_POLL
    printf("Exiting select rc=%d\n", rc);
#endif

    if(rc <= 0)
	return rc;

    if(rc > 0) {
        for (i = 0; i < nfds; ++i) {
            int fd = fds[i].fd;
    	if(fds[i].events & (POLLIN|POLLPRI) && FD_ISSET(fd, &ifds))
    		fds[i].revents |= POLLIN;
    	if(fds[i].events & POLLOUT && FD_ISSET(fd, &ofds))
    		fds[i].revents |= POLLOUT;
    	if(FD_ISSET(fd, &efds))
    		// Some error was detected ... should be some way to know.
    		fds[i].revents |= POLLHUP;
#ifdef DEBUG_POLL
        printf("%d %d %d revent = %x\n", 
                FD_ISSET(fd, &ifds), FD_ISSET(fd, &ofds), FD_ISSET(fd, &efds), 
                fds[i].revents
        );
#endif
        }
    }
    return rc;
}
*/
#endif
