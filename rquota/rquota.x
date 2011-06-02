/* implementation based on wireshark c-code */

const RQUOTAPATHLEN = 1024; /* Guess this is max. It is max for mount so probably rquota too */

enum rquotastat {
     RQUOTA_OK		= 1,
     RQUOTA_NOQUOTA	= 2,
     RQUOTA_EPERM	= 3
};

typedef string exportpath<RQUOTAPATHLEN>;

struct GETQUOTA1args {
       exportpath export;
       int uid;
};

struct GETQUOTA1res_ok {
       int bsize;
       int active;
       int bhardlimit;
       int bsoftlimit;
       int curblocks;
       int fhardlimit;
       int fsoftlimit;
       int curfiles;
       int btimeleft;
       int ftimeleft;
};

union GETQUOTA1res switch (rquotastat status) {
      case RQUOTA_OK:
            GETQUOTA1res_ok quota;
      default:
            void;
};

program RQUOTA_PROGRAM {
	version RQUOTA_V1 {
		void
		RQUOTA1_NULL(void)                 = 0;

		GETQUOTA1res
		RQUOTA1_GETQUOTA(GETQUOTA1args)    = 1;

		GETQUOTA1res
		RQUOTA1_GETACTIVEQUOTA(GETQUOTA1args)    = 2;
	} = 1;
} = 100011;

