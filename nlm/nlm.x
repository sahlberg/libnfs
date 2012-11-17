/* based on rfc1813 and wireshark */

typedef unsigned hyper uint64;

struct nlm_fh4 {
	opaque       data<>;
};

typedef string nlm4_oh<>;

struct nlm_cookie {
	opaque       data<>;
};
	
enum nlmstat4 {
	NLM4_GRANTED = 0,
	NLM4_DENIED = 1,
	NLM4_DENIED_NOLOCKS = 2,
	NLM4_BLOCKED = 3,
	NLM4_DENIED_GRACE_PERIOD = 4,
	NLM4_DEADLCK = 5,
	NLM4_ROFS = 6,
	NLM4_STALE_FH = 7,
	NLM4_FBIG = 8,
	NLM4_FAILED = 9
};

struct nlm4_holder {
	bool           exclusive;
	unsigned int   svid;
	nlm4_oh        oh;
	uint64         l_offset;
	uint64         l_len;
};

const NLM_MAXNAME = 256;
struct nlm4_lock {
	string         caller_name<NLM_MAXNAME>;
	struct nlm_fh4 fh;
	nlm4_oh        oh;
	unsigned int   svid;
	uint64         l_offset;
	uint64         l_len;
};

struct nlm4_share {
	string         caller_name<NLM_MAXNAME>;
	struct nlm_fh4 fh;
	nlm4_oh        oh;
	unsigned int   mode;
	unsigned int   access;
};

struct nlm4_testres_denied {
	nlm4_holder holder;
};

union nlm4_testreply switch (nlmstat4 status) {
	case NLM4_DENIED:
		nlm4_testres_denied lock;
	default:
		void;
};

struct NLM4_TESTres {
	nlm_cookie cookie;
	nlm4_testreply reply;
};

struct NLM4_TESTargs {
	nlm_cookie cookie;
	bool       exclusive;
	nlm4_lock  lock;
};

struct NLM4_CANCres {
	nlm_cookie cookie;
	nlmstat4 status;
};

struct NLM4_CANCargs {
	nlm_cookie cookie;
	bool block;
	bool exclusive;
	nlm4_lock  lock;
};

struct NLM4_UNLOCKres {
	nlm_cookie cookie;
	nlmstat4 status;
};

struct NLM4_UNLOCKargs {
	nlm_cookie cookie;
	nlm4_lock  lock;
};

struct NLM4_LOCKres {
	nlm_cookie cookie;
	nlmstat4 status;
};

struct NLM4_LOCKargs {
	nlm_cookie cookie;
	bool block;
	bool exclusive;
	nlm4_lock  lock;
	bool reclaim;
	int state;
};

struct NLM4_GRANTEDargs {
	nlm_cookie cookie;
	bool       exclusive;
	nlm4_lock  lock;
};

struct NLM4_GRANTEDres {
	nlm_cookie cookie;
	nlmstat4 status;
};

program NLM_PROGRAM {
	version NLM_V4 {
		void
		NLM4_NULL(void)                  = 0;

		NLM4_TESTres
		NLM4_TEST(NLM4_TESTargs)         = 1;

		NLM4_LOCKres
		NLM4_LOCK(NLM4_LOCKargs)         = 2;

		NLM4_CANCres
		NLM4_CANCEL(NLM4_CANCargs)       = 3;

		NLM4_UNLOCKres
		NLM4_UNLOCK(NLM4_UNLOCKargs)     = 4;

		NLM4_GRANTEDres
		NLM4_GRANT(NLM4_GRANTEDargs)      = 5;

		void
		NLM4_TEST_MSG(NLM4_TESTargs)     = 6;

		void
		NLM4_LOCK_MSG(NLM4_LOCKargs)     = 7;

		void
		NLM4_CANCEL_MSG(NLM4_CANCargs)   = 8;

		void
		NLM4_UNLOCK_MSG(NLM4_UNLOCKargs) = 9;

		void
		NLM4_GRANT_MSG(NLM4_GRANTEDargs) = 10;

		void
		NLM4_TEST_RES(NLM4_TESTres)     = 11;

		void
		NLM4_LOCK_RES(NLM4_LOCKres)         = 12;

		void
		NLM4_CANCEL_RES(NLM4_CANCres)       = 13;

		void
		NLM4_UNLOCK_RES(NLM4_UNLOCKres)       = 14;

		void
		NLM4_GRANT_RES(NLM4_GRANTEDres)      = 15;

/*		nlm4_shareres			*/
/*		NLM4_SHARE(nlm4_shareargs)      = 20;	*/

/*		nlm4_shareres			*/
/*		NLM4_UNSHARE(nlm4_shareargs)    = 21;	*/

/*		nlm4_res			*/
/*		NLM4_NM_LOCK(nlm4_lockargs)     = 22;	*/

/*		void				*/
/*		NLM4_FREE_ALL(nlm4_notify)      = 23;	*/
	} = 4;
} = 100021;
