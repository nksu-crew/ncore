#include <stdint.h>
struct nksu_profile_data {
  unsigned int uid;
  uint64_t caps;
  char selinux_domain[64];
  int namespace;
};

struct fmac_sepolicy_rule {
  char src[64];
  char tgt[64];
  char cls[64];
  char perm[64];
  int effect;
  int invert;
};

struct fmac_uid_cap {
  unsigned int uid;
  uint64_t caps;
};