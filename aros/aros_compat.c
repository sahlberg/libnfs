/*
   Copyright (C) 2013 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifdef AROS

#include <sys/types.h>
#include <sys/time.h>
#include "aros_compat.h"

#undef poll

/* unix device major/minor numbers dont make much sense on amiga */
int major(int i)
{
  return 1;
}
int minor(int i)
{
  return 2;
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

  rc = select(0, ip, op, &efds, toptr);

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
