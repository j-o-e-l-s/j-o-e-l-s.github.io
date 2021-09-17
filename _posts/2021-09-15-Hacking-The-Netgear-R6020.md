## Hacking the Netgear R6020

### 1. Getting the Firmware

Firmware for this router can be found at <https://www.netgear.com/support/product/R6020.aspx#download>

The version in this blog is `1.0.0.48`

***

### 2. Extracting the Root Filesystem
Use binwalk to extract firmware files.

```console
j-o-e-l-s@machine:~/Downloads$ binwalk -e R6020_V1.0.0.48.zip 
j-o-e-l-s@machine:~/Downloads$ cd _R6020_V1.0.0.48.zip.extracted
j-o-e-l-s@machine:~/Downloads/_R6020_V1.0.0.48.zip.extracted$ binwalk -e R6020_V1.0.0.48.img 
j-o-e-l-s@machine:~/Downloads/_R6020_V1.0.0.48.zip.extracted$ cd _R6020_V1.0.0.48.img.extracted/
j-o-e-l-s@machine:~/Downloads/_R6020_V1.0.0.48.zip.extracted/_R6020_V1.0.0.48.img.extracted$ binwalk -e R6020.bin 
```

We can now look at the root filesystem files.
```console
j-o-e-l-s@machine:~/Downloads/_R6020_V1.0.0.48.zip.extracted/_R6020_V1.0.0.48.img.extracted/_R6020.bin.extracted/squashfs-root$ ls
bin   dev  etc_ro  init  media  proc  sys  usr  www
data  etc  home    lib   mnt    sbin  tmp  var  www.eng
```

***

### 3. Identifying Files of Interest
This router uses `.cgi` files to handle web requests and input sanitization so any of these file are available for analysis.
```sh
j-o-e-l-s@machine:~/squashfs-root$ find -name "*.cgi*"
./usr/etc/htpwd_recovery.cgi
./usr/etc/restore_config.cgi
./usr/etc/upgrade_stringTbl.cgi
./usr/etc/upgrade_flash.cgi
./usr/etc/setup.cgi
./usr/sbin/htpwd_recovery.cgi
./usr/sbin/restore_config.cgi
./usr/sbin/upgrade_flash.cgi
./usr/sbin/setupwizard.cgi
./usr/sbin/setup.cgi
```

Setup.cgi will be the main file of interest.

***
 
### 4. Finding a Vulnerability in the Web App
There are several places for the user to enter input.

![image](https://user-images.githubusercontent.com/90354476/133454942-524edbd5-579a-4183-838e-e250f20abc5f.png)

This one in particular is able to be exploited to inject shell commands.

Let's take a look at what happens when we try to set the NTP server.

Using BurpSuite we can see what happens when the `Apply` button is clicked.

![image](https://user-images.githubusercontent.com/90354476/133455930-9417eb46-0b6c-46f2-9a06-9f5b0d3a2f33.png)

A POST request is made to Setup.cgi with variables in the body.

| POST Body Variable     | Description |
| ---------------------- | ---------------------------- |
|   ntp_server=          |  Value that can be controlled by the user                 |
|   todo=save            |  `todo` will control the function that setup.cgi executes |
| this_file=FW_ntp.htm   |  `FW_ntp.htm` is relevant within the `save` function of setup.cgi |

***

### 5. Analyzing setup.cgi


In this POST request the `todo=save` corresponds to the `save` function in setup.cgi.


![image](https://user-images.githubusercontent.com/90354476/133480008-03268f33-f59c-4930-97ff-bfaa98f197d7.png) 

Within this function `ntp_server` will be saved to non-volatile RAM.

![image](https://user-images.githubusercontent.com/90354476/133482249-4ccf4002-a010-4519-8cf9-885537bd0348.png)

And there is a check for `FW_ntp.htm` that will perform a system call to `/usr/sbin/rc ntp restart`

![image](https://user-images.githubusercontent.com/90354476/133485320-36292c85-8ce1-4c4f-bf5a-98b1da77879b.png)
![image](https://user-images.githubusercontent.com/90354476/133485861-f345fda8-be36-4084-9cfa-6e61c89e7893.png)

Since there is a call to `/usr/sbin/rc ntp restart` we need to look at `/usr/sbin/rc`

***

### 6. Analyzing rc

Within the main function of `/usr/sbin/rc` there is a write of `/usr/sbin/rc_app/rc_ntp restart` to  `/var/cmd_a`.

![image](https://user-images.githubusercontent.com/90354476/133497783-365a5f4f-e37a-4a4c-b773-e870426eb30f.png)

This will result in the execution of `/usr/sbin/rc_app/rc_ntp restart`

![image](https://user-images.githubusercontent.com/90354476/133498802-32098501-6ca9-432b-a1c0-5b6773c5b508.png)

`rc_ntp` is a symbolic link to `rc_apps` so that will be the next file to analyze.


***

### 7. Analyzing rc_apps

Within the main function of `rc_apps` argv[0] is parsed for the substring after the last `/`.

In this case the `rc_ntp` is parsed from `/usr/sbin/rc_app/rc_ntp`. Then this value is checked against a list of key value pairs in the form of `char* function_name: void* function_ptr`

![image](https://user-images.githubusercontent.com/90354476/133505883-381bb7d3-5efe-4673-8b7d-b70534ce8e29.png)

`rc_ntp` is found at location `0x4bf098` in the list and the strcmp condition is satisfied.

![image](https://user-images.githubusercontent.com/90354476/133506166-c1da21d3-5ce6-4f3b-914c-c6020e4168bb.png)

Then in this line `(*((index << 3) + 0x4bf034))(argc, argv)` `rc_ntp` is called.

Now we need to analyze `rc_ntp` within `rc_apps`

***

### 8. Analyzing rc_ntp in rc_apps 

Within rc_ntp `argv[1]` is checked against `start` `stop` `restart`

Since `argv[1]` is equal to restart. `stop_ntp` and `start_ntp` are called.

![image](https://user-images.githubusercontent.com/90354476/133508636-b386c2b1-a8a0-4cd0-98f8-cc72d07bb2a5.png)

Within `ntp_start` the value `ntp_server` is retrieved from non-volatile RAM. (We control this value with the POST request).

This value is used in this system call `/usr/sbin/netgear_ntp -h %s&` as the `%s` format string.

![image](https://user-images.githubusercontent.com/90354476/133509743-3690abe2-80b1-4aab-a8f6-1ad6d6109641.png)

This is where we can perform the command injection.

***

### 9. Injecting Shell Code

Now using BurpSuite we can inject our own shell code.

In this case I'll inject `& echo hello `.

![image](https://user-images.githubusercontent.com/90354476/133516407-3aa9ee3b-778c-45c9-93a7-0fd4bcacf3e4.png)

This is the serial output from the router when the command is executed.

![image](https://user-images.githubusercontent.com/90354476/133516462-28a7d516-76ad-4393-9863-a3b54ed6f0b3.png)

So we can now execute remote shell commands.
