#IPCheck
A small IP checker utility that alerts you through email when your IP changes. It is designed to be scheduled in a cron job to alert you once your IP has changed. For more information, you can refer to the readme.pdf file.

#Compile
```
./build.sh
```

#Usage
Example:
```
ipcheck -smtp_to email@gmail.com -smtp_sever smtp://smtp.gmail.com:587 -smtp_user ip@gmail.com -smtp_pass ippass123
```

#Other Parameters
```
   [REQUIRED]

   -smtp_to      E-mail address that will receive the IP update (Ex. email@gmail.com)
   -smtp_server  SMTP Server to be used for sending (Ex. smtp://smtp.gmail.com:587)

   [OPTIONAL]

   -smtp_user    SMTP User when using SMTP Server with authentication (Ex. email@gmail.com)
   -smtp_pass    SMTP Password of the SMTP user
   -smtp_ca_cert Certificate Authority Certificate file used for secured SMTP connections
   -proxy        Proxy to use when connecting (Ex. proxy.com)
   -proxy_port   Port of proxy (Ex. 8080)
   -ip_check_url URL of an external IP checker. (Ex. http://wtfismyip.com/text)
   -debug        Enables cURL debugging
   -force        Sends IP update even the last IP address saved did not change
   --help or -h  This help documentation
```
