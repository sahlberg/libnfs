/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
Copyright (c) 2014, Ronnie Sahlberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the FreeBSD Project.
*/

const PMAP_PORT = 111;      /* portmapper port number */

struct pmap2_mapping {
       unsigned int prog;
       unsigned int vers;
       unsigned int prot;
       unsigned int port;
};

struct pmap2_call_args {
       unsigned int prog;
       unsigned int vers;
       unsigned int proc;
       opaque args<>;
};

struct pmap2_call_result {
	unsigned int port;
	opaque res<>;
};

struct pmap2_mapping_list {
       pmap2_mapping map;
       pmap2_mapping_list *next;
};

struct pmap2_dump_result {
       struct pmap2_mapping_list *list;
};

struct pmap3_string_result {
       string addr<>;
};

struct pmap3_mapping {
       unsigned int prog;
       unsigned int vers;
       string netid<>;
       string addr<>;
       string owner<>;
};

struct pmap3_mapping_list {
       pmap3_mapping map;
       pmap3_mapping_list *next;
};

struct pmap3_dump_result {
       struct pmap3_mapping_list *list;
};

struct pmap3_call_args {
       unsigned int prog;
       unsigned int vers;
       unsigned int proc;
       opaque args<>;
};

struct pmap3_call_result {
	unsigned int port;
	opaque res<>;
};

struct pmap3_netbuf {
	unsigned int maxlen;
	/* This pretty much contains a sockaddr_storage.
	 * Beware differences in endianess for ss_family
	 * and whether or not ss_len exists.
	 */
	opaque buf<>;
};

typedef pmap2_mapping     PMAP2SETargs;
typedef pmap2_mapping     PMAP2UNSETargs;
typedef pmap2_mapping     PMAP2GETPORTargs;
typedef pmap2_call_args   PMAP2CALLITargs;
typedef pmap2_call_result PMAP2CALLITres;
typedef pmap2_dump_result PMAP2DUMPres;

typedef pmap3_mapping       PMAP3SETargs;
typedef pmap3_mapping       PMAP3UNSETargs;
typedef pmap3_mapping       PMAP3GETADDRargs;
typedef pmap3_string_result PMAP3GETADDRres;
typedef pmap3_dump_result   PMAP3DUMPres;
typedef pmap3_call_result   PMAP3CALLITargs;
typedef pmap3_call_result   PMAP3CALLITres;
typedef pmap3_netbuf        PMAP3UADDR2TADDRres;
typedef pmap3_netbuf        PMAP3TADDR2UADDRargs;
typedef pmap3_string_result PMAP3TADDR2UADDRres;

program PMAP_PROGRAM {
	version PMAP_V2 {
        	void
		PMAP2_NULL(void)              = 0;

		uint32_t
		PMAP2_SET(PMAP2SETargs)       = 1;

		uint32_t
		PMAP2_UNSET(PMAP2UNSETargs)   = 2;

		uint32_t
		PMAP2_GETPORT(PMAP2GETPORTargs) = 3;

		PMAP2DUMPres
		PMAP2_DUMP(void)               = 4;

		PMAP2CALLITres
		PMAP2_CALLIT(PMAP2CALLITargs)  = 5;
	} = 2;
	version PMAP_V3 {
        	void
		PMAP3_NULL(void)              = 0;

		uint32_t
		PMAP3_SET(PMAP3SETargs)       = 1;

		uint32_t
		PMAP3_UNSET(PMAP3UNSETargs)   = 2;

		PMAP3GETADDRres
		PMAP3_GETADDR(PMAP3GETADDRargs) = 3;

		PMAP3DUMPres
		PMAP3_DUMP(void)              = 4;

		PMAP3CALLITres
		PMAP3_CALLIT(PMAP3CALLITargs) = 5;

		uint32_t
		PMAP3_GETTIME(void)           = 6;

		PMAP3UADDR2TADDRres
		PMAP3_UADDR2TADDR(string)     = 7;

		PMAP3TADDR2UADDRres
		PMAP3_TADDR2UADDR(PMAP3TADDR2UADDRargs) = 8;
	} = 3;
} = 100000;

