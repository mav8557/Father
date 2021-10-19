#include "father.h"


int (*o_pam_authenticate)(pam_handle_t *, int);
int pam_authenticate(pam_handle_t * pamh, int flags)
{
  if(!o_pam_authenticate) {
    o_pam_authenticate = dlsym(RTLD_NEXT, "pam_autheticate");
  }
  return o_pam_authenticate(pamh, flags);
}
