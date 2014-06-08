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

program PMAP_PROGRAM {
	version PMAP_V2 {
        	void
		PMAP2_NULL(void)              = 0;

		bool
            	PMAP2_SET(pmap2_mapping)       = 1;

            	bool
            	PMAP2_UNSET(pmap2_mapping)     = 2;

            	unsigned int
            	PMAP2_GETPORT(pmap2_mapping)   = 3;

		pmap2_dump_result
		PMAP2_DUMP(void)               = 4;

		pmap2_call_result
		PMAP2_CALLIT(pmap2_call_args)  = 5;
	} = 2;
	version PMAP_V3 {
        	void
		PMAP3_NULL(void)              = 0;

		bool
		PMAP3_SET(pmap3_mapping)      = 1;

		bool
		PMAP3_UNSET(pmap3_mapping)    = 2;

		pmap3_string_result
		PMAP3_GETADDR(pmap3_mapping)  = 3;

		pmap3_dump_result
		PMAP3_DUMP(void)              = 4;

		pmap3_call_result
		PMAP3_CALLIT(pmap3_call_args) = 5;

		unsigned int
		PMAP3_GETTIME(void)           = 6;

		pmap3_netbuf
		PMAP3_UADDR2TADDR(string)     = 7;

		struct pmap3_string_result
		PMAP3_TADDR2UADDR(pmap3_netbuf) = 8;
	} = 3;
} = 100000;

