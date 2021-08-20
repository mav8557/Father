#include "father.h"

/* long int (*o_ptrace1)(enum __ptrace_request, ...); */
/* long ptrace(enum __ptrace_request request, ...) { */
/*   errno = EPERM; */
/*   return -1; */
/* } */

/* long (*o_ptrace2)(enum __ptrace_request request, pid_t pid, void * addr, void * data); */
/* long ptrace(enum __ptrace_request request, pid_t pid, void * addr, void * data) { */
/*   errno = EPERM; */
/*   return -1; */
/* } */
