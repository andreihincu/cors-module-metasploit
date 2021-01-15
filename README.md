test
test
test
test

# CORS auxiliary module for Metasploit

This is a private (not included in the official list) Metasploit auxiliary module for scanning a website against insecure CORS configurations

## Usage

### Kali

1. On a Kali box, clone this repo and rename it to  `.msf4` and put it in your home directory (eg. `/home/kali/.msf4`).
If the `.msf` directory already exists, then just merge this directory with the existing one.

2. Then, start `msfconsole` and you should be able to load the cors module in the **auxiliary/scanner/http/cors** path.

3. Set the `RHOSTS` and `VHOST` to your desired target website (eg. target.com).

4. Run the scanner.

```
$ cd ~
$ git clone https://github.com/andreihincu/cors-module-metasploit.git .msf4
$ msfconsole
...
msf6 > use auxiliary/scanner/http/cors
msf6 auxiliary(scanner/http/cors) > options

Module options (auxiliary/scanner/http/cors):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   HTTP_METHOD  OPTIONS          yes       HTTP Request Method (Accepted: OPTIONS, GET, POST, PUT, PATCH, DELETE)
   PATH         /                yes       Vulnerable path. Ex: /foo/resource/add
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        443              yes       The target port (TCP)
   SSL          true             yes       Use HTTPS
   THREADS      1                yes       The number of concurrent threads (max one per host)
   VHOST                         yes       HTTP server virtual host (eg. example.com)

msf6 auxiliary(scanner/http/cors) > set RHOSTS target.com
RHOSTS => target.com
msf6 auxiliary(scanner/http/cors) > set VHOST target.com
VHOST => target.com
msf6 auxiliary(scanner/http/cors) > run
etc...
```

**NOTE**
If your module does not appear that means you most likely have a syntax error. Metasploit will not throw errors, but instead fail silently.

### Docker

If you don't want to go through the hassle of setting up a full Kali environment, you can execute the scanner using Docker:

```
$ docker pull metasploitframework/metasploit-framework # fetch the docker image for metasploit
$ git clone https://github.com/andreihincu/cors-module-metasploit.git
$ cd cors-module-metasploit
$ docker run  --rm -it -v ${path}:/home/msf/.msf4 --name metasploit metasploitframework/metasploit-framework /usr/src/metasploit-framework/msfconsole'
...
msf6 > use auxiliary/scanner/http/cors
msf6 auxiliary(scanner/http/cors) > options

Module options (auxiliary/scanner/http/cors):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   HTTP_METHOD  OPTIONS          yes       HTTP Request Method (Accepted: OPTIONS, GET, POST, PUT, PATCH, DELETE)
   PATH         /                yes       Vulnerable path. Ex: /foo/resource/add
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        443              yes       The target port (TCP)
   SSL          true             yes       Use HTTPS
   THREADS      1                yes       The number of concurrent threads (max one per host)
   VHOST                         yes       HTTP server virtual host (eg. example.com)

msf6 auxiliary(scanner/http/cors) > set RHOSTS target.com
RHOSTS => target.com
msf6 auxiliary(scanner/http/cors) > set VHOST target.com
VHOST => target.com
msf6 auxiliary(scanner/http/cors) > run
etc...
```

If you're like me and prefer one-liners:
```
git clone https://github.com/andreihincu/cors-module-metasploit.git && cd cors-module-metasploit && docker run --rm -it -v $(pwd):/home/msf/.msf4 --name metasploit metasploitframework/metasploit-framework /usr/src/metasploit-framework/msfconsole -q -x 'use scanner/http/cors;set SSL true;set RPORT 443;set RHOSTS target.com;set VHOST target.com;run;exit'

# example:
git clone https://github.com/andreihincu/cors-module-metasploit.git && cd cors-module-metasploit && docker run --rm -it -v $(pwd):/home/msf/.msf4 --name metasploit metasploitframework/metasploit-framework /usr/src/metasploit-framework/msfconsole -q -x 'use scanner/http/cors;set SSL true;set RPORT 443;set RHOSTS yandex.ru;set VHOST yandex.ru;run;exit'
```

For more information about loading private modules see the [Official guide for loading third-party modules](https://github.com/rapid7/metasploit-framework/wiki/Running-Private-Modules)