
A common practice for hackers is to point automated userid/password
guessing programs at sshd servers. A human scanning sshd syslog output
can instantly spot such an attack. Blocker is a program that can also
instantly spot an attack. When blocker identifies an attack, blocker
adds an entry to its host's IP routing table that severs contact with
the attacking host.

-------------------------------------------------------------------------------

Blocker compiles on linux with:

cc -o blocker blocker.c

I like autotools, but that seems like a lot of baggage for this program.

-------------------------------------------------------------------------------

Blocker has numerous flags, some have defaults, but you must supply
at least one set of "grep tokens" with -t and a log file to monitor
with -l.

-------------------------------------------------------------------------------

-t ail," for "," from " 

A human might scan a log file with:

 * grep -i ail /var/log/secure | grep " for " | grep " from "
 *                         ...
 * sshd[3336]: error: PAM: Authentication failure for root from x.y.zz.y
 *                         ...
 * sshd[21338]: Failed keyboard-interactive/pam for invalid user oracle
 *   from blah.blah.blah.blah port 37841 ssh2

Feed similar "grep tokens" to this program with -t.

You can have multiple -t's on the command line in case there
are several kinds of suspicious lines in your log file...

There's not much point in being suspicious of lines that don't
have hostnames or ip addresses in them <g>...

-------------------------------------------------------------------------------

-l /var/log/secure

Need to tell this program what log file to monitor.

-------------------------------------------------------------------------------

-f facilityname

Where facilityname is one of the c_names from the facilitynames CODE structure
in the syslog header file(s) from /usr/include.

We'll default to local1.

-------------------------------------------------------------------------------

-m 5

Time threshold in minutes. We'll default to 5.

-------------------------------------------------------------------------------

-n 10

Fail threshold. If we see N fails in M minutes, BLOCK 'EM DANNO!

-------------------------------------------------------------------------------

This file enables blocker to be controlled with systemctl.

$ cat /usr/lib/systemd/system/blocker.service
[Unit]
Description=block brute force attacks

[Service]
ExecStart=/some/directory/blocker -t ail, for , from  -l /var/log/secure
Restart=on-abort

[Install]
WantedBy=multi-user.target

-------------------------------------------------------------------------------

Feeding a command line to systemd with a service file isn't the same
as feeding a command line to the shell. If you ran blocker as above from
the shell you'd need quotes around those spaces...

/some/directory/blocker -t ail," for "," from " -l /var/log/secure

-------------------------------------------------------------------------------

Blocker opens the to-be-monitored file and reads from it, ignoring EOF
and continuously retrying to read on the assumption that if the
end of the log file is ever reached, more logs will evenutally show
up as a result of future activity. Imagine "tail -f" ...

Log files are generally not allowed to grow without bounds until
the compter crashes for lack of disk space. In all likelyhood, the
files being monitored are managed by logrotate.

When a new log file is created, by whatever means, we don't want to
leave blocker sitting there like a lump waiting for activity on the
old log file.

If logrotate is your logfile manager, you could add something like this
to /etc/logrotate.conf to keep things flowing:

```
sharedscripts
postrotate
	/bin/systemctl restart blocker.service
endscript
```

-------------------------------------------------------------------------------

