/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

struct mapping {
       struct mapping *next;
       unsigned int port;
       unsigned int prog;
       unsigned int vers;
       string netid<>;
       string addr<>;
       string owner<>;
};

typedef mapping *mapping_ptr;
