/********************************
 * IP Checker                   *
 * arman pagilagan              *
 * arman.jay@gmail.com          *
 * 10.10.2013                   *
 ********************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <regex.h>
#include <ctype.h>

#define IPSIZE         16
#define IPCHECKER      "http://ipecho.net/plain"
#define IPHISTORY_FILE "iphistory.txt"
#define CERT_FILE      "certificate_equifax.pem"
#define CERT_FILE_LINE 19
#define REGEX_IP       "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

/* Public Certficate used for authenticating in GMAIL */
static const char *certificate_equifax[] = {
"-----BEGIN CERTIFICATE-----\r\n",
"MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV\r\n",
"UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy\r\n",
"dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1\r\n",
"MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx\r\n",
"dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B\r\n",
"AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f\r\n",
"BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A\r\n",
"cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC\r\n",
"AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ\r\n",
"MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm\r\n",
"aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw\r\n",
"ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj\r\n",
"IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF\r\n",
"MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA\r\n",
"A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y\r\n",
"7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh\r\n",
"1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4\r\n",
"-----END CERTIFICATE-----" };

/* Email Body */
static const char *email[] = {
  "Subject: IP Address Changed\n" ,
  "\n",
  "IP Address has changed to:\n",
  NULL
};

/* Program arguments */
struct arg {
  char ip_check_url[255];
  char smtp_to[255];
  char smtp_user[255];
  char smtp_pass[255];
  char smtp_server[255];
  char smtp_ca_cert[255];
  char proxy[255];
  long proxy_port;
  int  debug;
  int  force;
};

struct callback_write_data {
  char   ip[IPSIZE];
  size_t size;
  size_t read;
};

struct callback_read_data {
  char ip[IPSIZE];
  int  read;
  int  footer;
};

/* Function signatures */
void   parse_arguments(int *argc, char **argv, struct arg *args);
void   write_certificate(char *smtp_ca_cert);
char   *get_last_saved_ip(char *last_saved_ip, size_t size, char *file_name);
char   *get_current_ip(char *current_ip, size_t size, struct arg *args);
size_t callback_write(char *ptr, size_t size, size_t nmemb, void *userdata);
int    validate_ip(char *ip);
size_t save_ip_to_file(char *save_ip, size_t size, char *file_name);
void   send_email(char *ip, struct arg *args);
size_t callback_read(void *ptr, size_t size, size_t nmemb, void *userp);
void   show_help(void);

/* Main function */
int main(int argc, char **argv) {

  struct arg args;
  struct ip {
    char last[IPSIZE];
    char curr[IPSIZE];
  } ip;

  /* Check arguments */
  parse_arguments(&argc,argv,&args);

  /* Write Certificate */
  write_certificate(args.smtp_ca_cert);

  /* Get last saved IP */
  get_last_saved_ip(ip.last, IPSIZE, IPHISTORY_FILE);

  /* Get current IP */
  get_current_ip(ip.curr, IPSIZE, &args);

  /* Validate Current IP Address */
  if(validate_ip(ip.curr))
    exit(1);

  /* Check if called with Force Update */
  if(args.force) {

    /* Force Update IP */
    printf("Force updating IP address to %s\n",ip.curr);
    save_ip_to_file(ip.curr, IPSIZE, IPHISTORY_FILE);
    send_email(ip.curr, &args);

  }else{

    /* IP Address did not changed */
    if(strcmp(ip.last,ip.curr) == 0) {
      printf("IP Address has not changed. Current IP: %s\n", ip.curr);

    /* IP Address changed */
    }else{
      printf("IP Address has changed to %s\n", ip.curr);
      printf("Updating IP Address to %s\n", IPHISTORY_FILE);
      save_ip_to_file(ip.curr, IPSIZE, IPHISTORY_FILE);
      send_email(ip.curr, &args);
    }

  }

  return 0;

}

/* Parse Program Arguments */
void parse_arguments(int *argc, char **argv, struct arg *args) {

  int cnt;

  /* Initialize Argument Structure */
  memset(args,0,sizeof(*args));

  /* Loop through the arguments */
  for(cnt = 1; cnt < *argc; cnt++) {

    /* Arguments with pair */
    if(cnt < (*argc - 1)) {

      if(strcmp("-ip_check_url",argv[cnt]) == 0) {
        sprintf(args->ip_check_url,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-smtp_to",argv[cnt]) == 0) {
        sprintf(args->smtp_to,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-proxy",argv[cnt]) == 0) {
        sprintf(args->proxy,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-proxy_port",argv[cnt]) == 0) {
        args->proxy_port = atol(argv[cnt + 1]);
        continue;
      }

      if(strcmp("-smtp_user",argv[cnt]) == 0) {
        sprintf(args->smtp_user,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-smtp_pass",argv[cnt]) == 0) {
        sprintf(args->smtp_pass,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-smtp_server",argv[cnt]) == 0) {
        sprintf(args->smtp_server,"%s",argv[cnt + 1]);
        continue;
      }

      if(strcmp("-smtp_ca_cert",argv[cnt]) == 0) {
        sprintf(args->smtp_ca_cert,"%s",argv[cnt + 1]);
        continue;
      }

    }

    /* Arguments with no pair value */
    if(strcmp("-debug",argv[cnt]) == 0) {
      args->debug = 1;
      continue;
    }

    if(strcmp("-force",argv[cnt]) == 0) {
      args->force = 1;
      continue;
    }

    if(strcmp("--help",argv[cnt]) == 0) {
      show_help();
      exit(0);
    }

    if(strcmp("-h",argv[cnt]) == 0) {
      show_help();
      exit(0);
    }

  }

  /* Set Defaults */
  if(strlen(args->ip_check_url) == 0)
    sprintf(args->ip_check_url,"%s",IPCHECKER);

  if(strlen(args->smtp_ca_cert) == 0)
    sprintf(args->smtp_ca_cert,"%s",CERT_FILE);

  /* Validate Arguments */
  if(strlen(args->smtp_to) == 0) {
    fprintf(stderr,"-smtp_to parameter is required. Ex.: -smtp_to email@domain.com\n");
    exit(1);
  }

  if(strlen(args->smtp_server) == 0) {
    fprintf(stderr,"-smtp_server parameter is required. Ex.: -smtp_server smtp://smtp.gmail.com:587\n");
    fprintf(stderr,"If SMTP server requires authentication specify -smtp_user and -smtp_pass as well\n");
    exit(1);
  }

}

/* Write Certificate Authority (CA) Certificates */
void write_certificate(char *smtp_ca_cert) {

  FILE *file;
  int cnt;

  /* Check first if the certificate exists */
  file = fopen(smtp_ca_cert, "r");

  /* Exit function */
  if(file != NULL) {
    printf("Certificate %s found, no need to generate\n",smtp_ca_cert);
    fclose(file);
    return;
  }

  printf("Certificate not found, generating %s\n",smtp_ca_cert);

  /* Create certificate */
  file = fopen(smtp_ca_cert, "w");

  if(file == NULL) {
    fprintf(stderr,"Error creating certificate %s\n", smtp_ca_cert);
    exit(1);
  }

  /* Write the certificate */
  for(cnt = 0; cnt < CERT_FILE_LINE; cnt++) {
    fputs(certificate_equifax[cnt], file);
  }

  /* Close the file */
  fclose(file);

  return;

}


/* Read the last saved IP address*/
char *get_last_saved_ip(char *last_saved_ip, size_t size, char *file_name) {

  FILE *file;

  /* Nullify the buffer */
  memset(last_saved_ip,0,size);
  
  /* Try to open the file */
  file = fopen(file_name, "r");
  if(file == NULL)
    return NULL;

  /* Read the file */
  fread(last_saved_ip, sizeof(char), size - 1, file);

  /* Close the file */
  fclose(file);

  return last_saved_ip;

}

/* Retrieve current IP Address */
char *get_current_ip(char *current_ip, size_t size, struct arg *args) {

  CURL *curl;
  CURLcode rc;
  struct callback_write_data write_data;

  /* Initialize CURL */
  curl = curl_easy_init();

  if(curl) {

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, args->ip_check_url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* Set Proxy */
    if(args->proxy != NULL)
      curl_easy_setopt(curl, CURLOPT_PROXY, args->proxy);

    /* Set Proxy Port */
    if(args->proxy_port > 0)
      curl_easy_setopt(curl, CURLOPT_PROXYPORT, args->proxy_port);

    /* Set Callback write function */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback_write);

    /* Initialize Write Data Structure */
    memset(&write_data,0,sizeof(write_data));
    write_data.size = size;
    write_data.read = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_data);
    
    /* Debug Mode */
    if(args->debug == 1)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Execute CURL */
    rc = curl_easy_perform(curl);
    if(rc != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed %s\n",curl_easy_strerror(rc));

    /* Clean-up CURL */
    curl_easy_cleanup(curl);

    /* Return Current IP */
    sprintf(current_ip,"%s",write_data.ip);
    return current_ip;

  }

}

/* Callback function for receiving data */
size_t callback_write(char *ptr, size_t size, size_t nmemb, void *userdata) {

  struct callback_write_data *write_data = (struct callback_write_data *) userdata;

  
  /* Copy IP to buffer */
  for(; write_data->read < write_data->size; write_data->read++) {

    /* Consider only numbers and dots */
    if(isdigit(ptr[write_data->read]) || ptr[write_data->read] == '.') {
      write_data->ip[write_data->read] = ptr[write_data->read];

    /* If anything else is found, null terminate it and exit the loop */
    }else{
      write_data->ip[write_data->read] = '\0';
      break;
    }

    /* If we reach the end of the array, null terminate it */
    if(write_data->read+1 == write_data->size)
      write_data->ip[write_data->read] = '\0';
  }

  return nmemb;

}

/* Validates if an IP Address is a valid IP */
int validate_ip(char *ip) {

  regex_t regex;
  int rc;

  /* Compile REGEX */
  rc = regcomp(&regex, REGEX_IP, REG_EXTENDED);
  if(rc) {
    fprintf(stderr,"Error compiling regex %s",REGEX_IP);
    return 1;
  }

  /* Check if REGEX matches */
  rc = regexec(&regex, ip, 0, NULL, 0);
  if(rc == REG_NOMATCH) {
    fprintf(stderr,"Invalid IP Address %s",ip);
    return 1;
  }

  /* Free REGEX */
  regfree(&regex);
  return 0;

}

/* Save IP Address to history file */
size_t save_ip_to_file(char *save_ip, size_t size, char *file_name) {

  FILE *file;
  size_t write_bytes;
  char buffer[size];

  /* Try to open the file */
  file = fopen(file_name, "w");
  if(file == NULL)
    return -1;

  /* Nullify the buffer */
  memset(buffer,0,size);

  /* Copy IP to buffer */
  sprintf(buffer, "%s", save_ip);

  /* Write IP to file */
  write_bytes = fwrite(buffer, sizeof(char), size, file);

  /* Close the file */
  fclose(file);

  return write_bytes;

}

/* Sends IP via email */
void send_email(char *ip, struct arg *args) {

  CURL *curl;
  CURLcode rc;

  struct curl_slist *recipients = NULL;
  struct callback_read_data read_data;

  /* Initialize CURL */
  curl = curl_easy_init();
  if(curl) {

    /* Setup CURL */
    curl_easy_setopt(curl, CURLOPT_URL, args->smtp_server);
    if(strlen(args->smtp_ca_cert) > 0 ) {
      curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
      curl_easy_setopt(curl, CURLOPT_CAINFO, args->smtp_ca_cert);
    }
    if(strlen(args->smtp_user) > 0) {
      curl_easy_setopt(curl, CURLOPT_USERNAME, args->smtp_user);
      curl_easy_setopt(curl, CURLOPT_MAIL_FROM, args->smtp_user);
    }
    if(strlen(args->smtp_pass) > 0)
      curl_easy_setopt(curl, CURLOPT_PASSWORD, args->smtp_pass);
    recipients = curl_slist_append(recipients, args->smtp_to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, &callback_read);

    /* Initialize Read Data Structure */
    read_data.read = 0;
    read_data.footer = 0;
    sprintf(read_data.ip, "%s", ip);

    curl_easy_setopt(curl, CURLOPT_READDATA, &read_data);

    /* Debug Mode */
    if(args->debug == 1)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Set Proxy */
    if(strlen(args->proxy) > 0)
      curl_easy_setopt(curl, CURLOPT_PROXY, args->proxy);

    /* Set Proxy Port */
    if(args->proxy_port > 0)
      curl_easy_setopt(curl, CURLOPT_PROXYPORT, args->proxy_port);

    rc = curl_easy_perform(curl);
    if(rc != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(rc));
    }else{
      printf("E-mail sent to %s\n",args->smtp_to);
    }

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

  }

  return;

}

/* Callback Read Function */
size_t callback_read(void *ptr, size_t size, size_t nmemb, void *userp)
{

  struct callback_read_data *read_data = (struct callback_read_data *) userp;
  const char *data;
 
  /* Check if there are data to send */
  if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }

  /* Get Line to read */
  data = email[read_data->read];
 
  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    read_data->read++;
    return len;
  }

  /* Write Footer */
  if(read_data->footer == 0) {
    size_t len = strlen(read_data->ip);
    memcpy(ptr, read_data->ip, len);
    strcat(ptr, "\n\n");

    read_data->footer = 1;
    return len;

  /* Footer has been written */
  }else{
    return 0;
  }

  return 0;

}

/* Help Documentation */
void show_help(void) {

const char* help[] = {

"\n",
"IP Checker v.1.0\n",
"Arman Pagilagan\n",
"\n",
"HELP\n",
"----\n",
"\n",
"  IP Checker is a small utility that checks your external IP using an External IP website and sends you via e-mail your current IP. Every time ipcheck is executed it will save your current IP Address to a text file. This text file is being checked by ipcheck so it can compare your current IP address against the last saved IP address. If there are no changes ipcheck will not send any email.\n",
"\n",
"  USAGE: ipcheck [arguments]\n",
"\n",
"  ARGUMENTS\n",
"  ---------\n",
"\n",
"   [REQUIRED]\n",
"\n",
"   -smtp_to      E-mail address that will receive the IP update (Ex. email@gmail.com)\n",
"   -smtp_server  SMTP Server to be used for sending (Ex. smtp://smtp.gmail.com:587)\n",
"\n",
"   [OPTIONAL]\n",
"\n",
"   -smtp_user    SMTP User when using SMTP Server with authentication (Ex. email@gmail.com)\n",
"   -smtp_pass    SMTP Password of the SMTP user\n",
"   -smtp_ca_cert Certificate Authority Certificate file used for secured SMTP connections\n",
"   -proxy        Proxy to use when connecting (Ex. proxy.com)\n",
"   -proxy_port   Port of proxy (Ex. 8080)\n",
"   -ip_check_url URL of an external IP checker. (Ex. http://wtfismyip.com/text)\n",
"   -debug        Enables cURL debugging\n",
"   -force        Sends IP update even the last IP address saved did not change\n",
"   --help or -h  This help documentation\n",
"\n",
" EXAMPLE\n",
" -------\n",
"\n",
"   ipcheck -smtp_to email@gmail.com -smtp_sever smtp://smtp.gmail.com:587 -smtp_user ip@gmail.com -smtp_pass ippass123\n",
"\n"

};

  int cnt;
  for(cnt = 0; cnt < 35; cnt++)
    printf("%s",help[cnt]);

}
