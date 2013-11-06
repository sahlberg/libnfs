/*
 * NSM definitions from:
 * Protocols for Interworking: XNFS, Version 3W
 * http://pubs.opengroup.org/onlinepubs/9629799/chap11.htm
 *
 * Symbols then massaged to avoid too much namespace pollution
 * and to bring more inline with convention in nlm.
 */

/*
 * This defines the maximum length of the string
 * identifying the caller.
 */
const NSM_MAXSTRLEN = 1024;

struct nsm_name {
    string mon_name<NSM_MAXSTRLEN>;
};

enum nsmstat1 {
    NSM_STAT_SUCC = 0,   /*  NSM agrees to monitor.  */
    NSM_STAT_FAIL = 1    /*  NSM cannot monitor.  */
};

struct nsm_stat_res {
    nsmstat1 res;
    int      state;
};

struct nsm_stat {
    int state;    /*  state number of NSM  */
};

struct nsm_my_id {
    string my_name<NSM_MAXSTRLEN>; /*  hostname  */
    int    my_prog;                /*  RPC program number  */
    int    my_vers;                /*  program version number  */
    int    my_proc;                /*  procedure number  */
};

struct nsm_mon_id {
    string mon_name<NSM_MAXSTRLEN>; /* name of the host to be monitored */
    struct nsm_my_id my_id;
};

struct nsm_mon {
    struct nsm_mon_id mon_id;
    opaque priv[16];        /*  private information  */
};

struct nsm_stat_chg {
    string mon_name<NSM_MAXSTRLEN>;
    int    state;
};

/*
 *  Protocol description for the NSM program.
 */
program NSM_PROGRAM {
    version NSM_V1 {
        void NSM1_NULL(void) = 0;
        struct nsm_stat_res NSM1_STAT(struct nsm_name) = 1;
        struct nsm_stat_res NSM1_MON(struct nsm_mon) = 2;
        struct nsm_stat NSM1_UNMON(struct nsm_mon_id) = 3;
        struct nsm_stat NSM1_UNMON_ALL(struct nsm_my_id) = 4;    
        void NSM1_SIMU_CRASH(void) = 5;
        void NSM1_NOTIFY(struct nsm_stat_chg) = 6;
    } = 1;
} = 100024;


