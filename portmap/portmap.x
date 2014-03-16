/*
 * From RFC1833
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

struct pmap3_getaddr_result {
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

		pmap3_getaddr_result
		PMAP3_GETADDR(pmap3_mapping)  = 3;

		pmap3_dump_result
		PMAP3_DUMP(void)              = 4;
	} = 3;
} = 100000;

