# Bandit 

## Level 0
Login to bandit0 and view the readme file
### Solution
`cat readme`

## Level 1
The password is in a file with a single dash `-` as the filename. On Linux `-` is an argument for `stdin` and will be interpreted such in a command like `cat -`, which will print whatever is input at the command line. Instead, the full or relative path to the file is needed so that the dash is interpreted as a filename. 
### Solution
`cat ./-`

## Level 2
The password is in a file that has spaces in the filename. Trying `cat spaces in this file name` will result in a number of 'No such file or directory' errors because the cat command treats each word as a seperate argument. Using backslashes will cause the terminal to treat the space characters as part of the filename rather than a seperator. These can be input manually, but many shells will insert the slashes automatically when doing command completion with the Tab key. Surrounding the filename with double quotes will also work. 
###Solution
`cat spaces\ in\ this\ filename`\
`cat "spaces in this filename"`

## Level 3
The clue for level 3 is very explicit, the password for the next level is in a hidden file in the **inhere** directory. Using the -a flag with the ls command we can see the hidden files in the **inhere** directory. There is only one file, so we know this contains the solution. 
### Solution
```
cd inhere
ls -a
cat ...Hiding-From-You
```

## Level 4
As with level 3, the file with the password for the next level is in the **inhere** directory. The clue tells us that the file is the only human-readable file in the directory. The `file` utility uses different methods to deduce what type of file a file is based on its contents. Using the `file` utility we can find out which of the 10 files in the directory is an ASCII text file. As promised there is only one file which contains the next password. 
### Solution
```
cd inhere
file ./-file00 ./-file01 ./-file02 ./-file03 ./-file04 ./-file05 ./-file06 ./-file07 ./-file08 ./-file09
cat ./-file07
```

## Level 5
While it was conceivable to brute-force level 5 by inspecting the 10 files in the **inhere** directory, there's too many files in level 5 for this to be feasible. However, the clue for level 5 gives enough information to narrow down the search. The `find` utility will be useful with the following arguments. `-size 1033c` will look for files exactly 1033 bytes in size. `-type f` will limit the search to regular files. `! -executable` will look for files that aren't executable (! being the operator to negate the argument after it, so here it means **not executable** files). As it turns out, there is only one file that fits the description. 
### Solution
```
cd inhere
find -size 1033c -type f ! -executable
cat ./maybehere07/.file2
```

## Level 6
Once again we need to use the `find` utility to locate the password file. The clue gives us a hint on how to narrow down the search. The `-user` and `-group` arguments will limit the search to files owned by specific user and group names. However, there is nothing in the bandit6 home directory, so the file must be somewhere else on the server. We can cheat a bit by starting the search from the root directory of the server. The following solution will almost get us there:
```
cd /
find -size 33c -type f -user bandit7 -group bandit6 -readable
```
We get a list of files returned, but most we don't have permission to read. There might be other ways to filter out these files, but the way I ignored those files was to add the following to end of the `find` command: `2> /dev/null/`. 2 is file descriptor 2, which by convention is `stderr` on Linux (0 is `stdin` and 1 is `stdout`), and `/dev/null` is a null device, and together this redirects `stderr` to this device. Essentially we are outputting errors to a blackhole that will absorb them, rather than having them printed to the terminal. The result is that a single file is output to the terminal which contains the password. 
### Solution 
```
cd /
find -size 33c -type f -user bandit7 -group bandit6 -readable 2> /dev/null
cat ./var/lib/dpkg/info/bandit7.password
```

## Level 7
The password is in **data.txt** but the file is huge, far too big to parse just by scrolling through it. The hint for level 7 tells us that the password is next to the word **millionth**. This suggests that we can find the password using a utility like `awk` or `grep`. By piping the content of the data file to `grep` we can find the password quite easily. 
### Solution
```
cat data.txt | grep millionth
```

## Level 8
As with level 7 **data.txt** is too big to parse just by looking at it. The clue tells us that the password is a line of text that appears just once in the file. We can find this line with the help of `sort`, `uniq` and `grep`. `sort` will organise the file so that all instances of each duplicate string are grouped together. The output of `sort` can then be piped to `uniq`. We can't just use `uniq` as-is, doing so will output all the unique lines of text in the data file and it won't be obvious which one the password is. By using the `-c` flag we tell `uniq` to count the number of times the duplicate lines appear, and the count will be prefixed to the output, so it will look like `5 YbfaJNckJrgh9TvEBScUaEUCRhDJcgIL`. Now all we need to do is find the line whose count is **1**, which we can do with `grep` (note that we search for "1 " which is 1 and a space character, that way we don't find a whole lot of 1 characters that we don't care about). 
### Solution
```
sort data.txt | uniq -c | grep "1 "
```

## Level 9
At first this seems like it would be similar to level 8, but the hint specifically mentions _human readable_ strings. `cat`ing data.txt reveals a bunch of weird looking characters, and if we run `file` on data.txt we see that the file is actually interpreted as data, not ASCII text, so what we are seeing is binary data. This is where the `strings` utility comes in handy, it prints sequences of human readable characters in files. As we know that the password is preceeded by _several_ **=** characters (which I take to mean at least 2) we can use `grep` to filter the output from `strings`. The solution below doesn't narrow down the specific string containing the password, but the terminal output makes it obvious what the password is. 
### Solution 
```
strings data.txt | grep "=="
```

## Level 10
If you run `file` on **data.txt** you'll see that the file is listed as having plaintext content, but if you `cat` the file the output is too long to be one of the usual bandit game passwords. The clue says that the file is base64 encoded, and base64 encoded text is made up of human readabl characters, so `file` isn't wrong. To get the password all we need to do is decode the data file using the `base64` utility with the `-d` flag. 
### Solution
`base64 -d data.txt`

## Level 11
The password is in **data.txt**, but as the clue tells us, the letter characters have been *rotated* by 13 positions. It would be possible to work out by hand what the password is with the help of an ASCII chart. For example, A is character 65, and when rotated by 13 positions it will become character 78, which is N. We also know that the first part of the data file content probably reads *The password is* when all characters are rotated back. Of course though, there is always an easier way.\
The `tr` can be used to translate characters. It takes as input some text and two arrays of strings, `SET1` and `SET2` which map the characters in the input to characters in the output. We know that we need to convert upper and lower case characters, so our `SET` array is [A-Za-z].\
We need to come up with an output range where each uppercase and lowercase letter is rotated 13 places. So A->N, B->O...Y->L, Z->N, a->n, b->o...y->l, z->n. We can construct `SET2` with the following array of characters: [N-ZA-Mn-za-m], this has the same number of characters as `SET1` and correctly rotates each character by 13 places.
### Solution
`cat data.txt | tr "A-Za-z" "N-Za-mN-Za-m"`

## Level 12
Details on how to create a temporary directory and copy **data.txt** to it are ommitted. \
\
The clue states that **data.txt** is a hexdump of a file that has been repeatedly compressed. From this we can deduce that we need to convert the file back into a compressed archive and then start decompressing it to find its contents.\
\
To convert the file we can use `xxd` with the `-r` flag which *reverts* a hexdump back into a file. The command `xxd -r data.txt data.zip` will suffice.\
\
Now that we have our archive we need to know what type of archive it is. Using the `file` command we find out that is is *gzip compressed data*. We can rename the archive and extract it with the following commands:
```
mv data.zip gata.gz
gzip -d gata.gz
```
Running `file` on the extracted file reveals that it is a `bzip2` compressed file. From here the process repeats numerous times, each time we extract a file we need to know what type of compressed archive it is, extract it with the correct utility, and continue until we end up with a plaintext ASCII file.\
\
As we progress we will encounter `gzip`, `bzip2` and `POSIX tar` archives. I found that `gzip` would complain when the input file did not have the `.gz` extension, so you'll see a few renamings in the solution. `bzip2` and `tar` don't seem to care as much. \
\
In general the following commands can be used to extract the archives: 
```
gzip -d file.gz
bzip2 -d file
tar -xvf file
```
The `-d` flag for `gzip` and `bzip2` means *decompress*. For `tar`, `-x` means *extract*, `-v` means verbose output, and `-f` means that the file type is an archive. It is worth reviewing the man pages for tar to see the historical reason for why the `-f` flag is needed. \
\
The solution goes through all the extraction steps until finally reaching the file **data8**, which contains the password.
### Solution
```
mktemp -d
cd <temp directory>
cp ~/data.txt .
xxd -r data.txt data.zip
file data.zip
rm data.txt
mv data.zip data.gz
gzip -d data.gz
file data
bzip2 -d data
file data.out
mv data.out data.gz
gzip -d data.gz
file data
tar xvf data
file data5.bin
tar xvf data5.bin
file data6.bin
bzip2 -d data6.bin
file data6.bin.out
tar xvf data6.bin.out
file data8.bin
mv data8.bin data8.gz
gzip -d data8.gz
file data8
cat data8
```

## Level 13
As stated in the level goal the password for the next level is in a file that is owned by bandit14. To read the file we need to be logged in as bandit14, which we can do with a SSH private key that is in bandit13's home directory. Using the `ssh` utility we can pass in the private key file using the `-i` switch which indicates that we are providing an 'identity file', another name for a private key. As we are trying to login to an account that exists on the machine we are already logged into we use localhost as the server address, and as with all challenges so far we use port 2220 to login. Once logged in it is trivial to get the password from the file mentioned in the level outline. 
### Solution 
```
ssh -i ./sshkey.private bandit14@localhost -p 2220 
cat etc/bandit_pass/bandit14
```

## Level 14
The outline for this level suggests that we need to send the password for bandit14 to a server program listening for incoming connections on port 30000 on the system we are logged into. This can be done with Netcat. The usage of Netcat here is simple, all we need to do is connect to the server program and then send the data. If all goes as it should, the server will respond with the password for the next level. 
### Solution
```
nc localhost 30000
*paste the password for bandit14 and press Enter*
*ctrl+c to disconnect from the server*
```

## Level 15
This level is similar to the previous one except that we are required to establish an encrypted connection to the server program running on localhost at port 30001. Of the utilities listed in the level description, `openssl` stands out as the obvious one to provide SSL/TLS encrypted connections. Reviewing the man page for `openssl` it looks like the `s_client` command will be of use as it implements a simple SSL/TLS client that can establish connection to a remote server that expects encrypted connections. Checking the man pages for `openssl s_client` reveals that the easiest way to estbalish a connection is to use the `connect` switch with a hostname and port. 
### Solution
```
openssl s_client -connect localhost:30001
*paste the password for bandit15*
```

## Level 16
The first thing we need to do for this challenge is to find out which ports in the range 31000-32000 on the bandit server are listening for connections. We can do a quick portscan with netcat: `nc localhost 31000-32000 -z`. The `-z` flag tells netcat to scan for listening daemons without sending data to them. The comman returns 5 results, with daemons listening on ports 31046, 31518, 31691, 31790 and 31960. \
\
Next we need to know which services are listening for encrypted connections. I didn't find a command that does this, rather I just attempted to connect to each port directly using `s_client`, those that don't understand SSL/TLS will return an error message. There are only two ports that accept encrypted connections, 31518 and 31790, with the latter being the service that we want (we know this because the server listening on 31518 echoes back our input, while 31790 tells us if we have entered the correct password). We can use a command similar to the one we used in level 15 to connect to the listening server: `openssl s_client -connect localhost:31790 -quiet`. Note that we have to add the `-quiet` flag, otherwise the server responds with `KEYUPDATE` when the correct password is entered (for some inputs it correctly responds with an 'incorrect password' message). \
\
Although we provide the correct password to the daemon it won't directly give us the password for level 17. Instead it gives us an RSA private key, which we can use like we did in level 13. Create a new temporary directory with `mktemp -d` and then a new file, the name doesn't matter. Copy and paste the private key into the file and save it. If we try to use the credentials to connect login as bandit17 we get the following error message: 
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for './privkey' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
``` 
The error message is pretty explicit, the permissions for the key file are not allowed. 0664 corresponds to a file that is read/write enabled for the file *owner* and file *group*, and readable by *other*s. We need a permission that only lets the *owner* access the private key file, which would be 600 (for more on Unix file permissions, see [this link](https://www.redhat.com/en/blog/linux-file-permissions-explained)). We can use `chmod` to adjust the permissions. \ 
\ 
Once the file permissions have been adjusted we can login to the server as bandit17 and output the password for that level. 
### Solution 
```
nc localhost 31000-32000 -z
openssl s_client -connect localhost:31790 -quiet 
mktemp -d
cd <temp directory>
touch privkey
nano privkey
<paste in private key text and save the file>
chmod 600 ./privkey 
ssh -i ./privkey bandit17@localhost -p 2220 
cat /etc/bandit_pass/bandit17 
```

## Level 17
This level is pretty trivial. All we need to do is find the one line changed between the two password files, which we can do with the `diff` utility. In the output lines prefixed with '< ' are lines from file 1, and lines prefixed with '> ' are lines from file 2. If we compare the new password file with the old password file then the line from file 1 is the password for bandit18. 

### Solution
```
diff passwords.new passwords.old 
```

## Level 18
As the level description says, as soon as you login to bandit18, you get logged back out. This is because *.bashrc* has been modified. It's worth knowing a little bit about *.bashrc* to understand what is happening. When we login to the server a Bash shell session starts, and as part of this, it executes *.bashrc* as a script.  Something in the script is killing our session before we can do anything. \
\
Conveniently, we can add a command onto the end of our ssh login command, and that command will execute before Bash does. For example, if we want to list the files in the home directory we can run the following: `ssh bandit18@bandit.labs.overthewire.org -p 2220 "ls"`. We see that there is a single file, *readme*, just like the level outline says. \ 
\ 
Well, with that knowledge, we can just `cat` the contents of the readme file to get the password for bandit19. You can also see exactly why we are being logged out by running the following: `ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat .bashrc"`. Right at the very end of the script is `exit 0`, which is responsible for kicking us out. 
### Solution
```
ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
```
## Level 19
There is a binary in the home directory, `bandit20-do`, that we must use for this level. As the level outline states, it is a special kind of binary, as it has the *setuid* flag set. The Wikipedia link in the level outline explains what this means, but to summarise: having the *setuid* flag set means that this binary executes with the permissions of its owner, rather than the permissions of the user that executes it. It stands for 'set user id'. This is required by some programs so that they can perform operations that the current user cannot. An example of *setuid* program would be `sudo`, which executes with root privileges. There have been a number of exploits that take advantage of *setuid* programs to escalate privileges. \
\
If we run `ls-al` in the home directory we see that the owner of `bandit20-do` is bandit20, and it belongs to the bandit19 group. 
```
-rwsr-x---  1 bandit20 bandit19 14880 Sep 19 07:08 bandit20-do
```
And if we run `file` on the binary the output also tells us that it is a *setuid* binary. 
```
bandit20-do: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=368cd8ac4633fabdf3f4fb1c47a250634d6a8347, for GNU/Linux 3.2.0, not stripped
```
Running the binary without any input, as we are told to do, produces the following output: 
```
Run a command as another user.
  Example: ./bandit20-do id
```
Well, that pretty much tells us everything we want to know. If we execute the binary we can add pass commands to it and they will be run as if we were bandit20. All we need to do is `cat` the password file for bandit20. 
### Solution
```
./bandit20-do cat /etc/bandit_pass/bandit20
```

## Level 20
The `suconnect` binary for level 20 is another setuid binary. Its owner is bandit21, and its group is bandit20. From the level description we can deduce that it uses these permissions to read the passwords in /etc/bandit_pass for bandit20 and bandit21. The way that the `suconnect` binary works is that when run it makes a connection to a daemon on the local system at the port specified as a command line argument. It will then listen for a single input from the other end of the connection, and if the input is the correct password for bandit20 `suconnect` will send back the password for bandit21. \
\
There are ways to automate the process, but the way that I approached the problem was to use `screen` to manage both ends of the connection. Job control could also have been used to put the end of the connection that we create (the one that sends the bandit20 password) into the background while we run the `suconnect` binary. `screen` is a terminal multiplexer that allows us to run programs in individual teminals and then switch between them. `screen` starts the multiplexer session, **Ctrl-A** is used to initiate commands to the window manager, **Ctrl-A + '** prompts for the window to switch to, and **Ctrl-A + "** displays a list of running windows from which one can be selected, and **Ctrl-A + c** creates a new shell window and switches to it immediately. These commands are enough to complete this level. \
\
We've seen `nc` in the past. This time we use it as a server, rather than a client. The `-l` switch starts `nc` in listen mode. We need to start `nc` in listen mode because the `suconnect` binary will immediately terminate if it can't connect to a daemon, so we need to give it something to listen to. So we start `nc` with the following command: `nc -l 45678`. Then we start `suconnect` with `suconnect 45678`. `suconnect` will now listen for input from the other end of the connection, and if it receives the bandit20 password, it will send back the bandit21 password, otherwise it sends back 'FAIL!'. \
\
However, we can't just run `nc` in listen mode and then run `suconnect` in one terminal window. This is where `screen` comes in handy. We first run `screen` to begin a shell multiplexing session and run `nc -l 45678`. Next, we create a second window with **Ctrl-A + c** and run `./suconnect 45678`. We then switch back to our listening connection with `Ctrl-A + "` and select window 0, where we input the password for bandit20. If everything worked correctly we will see the bandit21 password in the terminal. Now we can exit the session by typing `exit` twice to terminate the two sessions and drop us back into our original shell. 
### Solution 
```
screen
# return to bypass welcome message
nc -l 45678
# Ctrl-A + C to create new window
./suconnect 45678
# Ctrl-A + 0 to switch to nc window
# Paste bandit20 password
exit
exit
```

### Alternative Solution
Commands can be run in the background by appending `&` to the end. The job system will then display the following: `[1] 1430950` with `[1]` being the job ID and `1430950` being the process id. `fg` can be used to bring a running job to the foreground, and `bg` can be used to send the current job to the background. 

```
nc -l 45678 &
./suconnect 45678 &
fg 1
# Paste bandit20 password
# Both ends of the connection will terminate on their own
```

We can also automate the process a little by piping input to `nc`. The `-n` switch to echo isn't strictly necessary, but is useful to know as it drops a training newline in the input (possible from pressing return to send the command?). The piped input will be sent automatically when a connection is made to our `nc` instance, reducing the solution two just two commands. 
```
echo -n <bandit20_password> | nc -l 45678 &
./suconnect 45678
```

## Level 21
`cron` (apparently named after the Greek word for time, Chronos) is the job scheduling system on Unix-like systems. Jobs, also known as cron jobs, are run on a fixed schedule as defined in a `crontab` (cron table) file. For this task we need to investigate a specific cron job figure out what it does. Listing the files in `/etc/cron.d` we find `cronjob_bandit22` which is the cron tab that we are most likely interested in. \
\
There are only two lines in the file. The second is actually the more interesting of the two, so we start there. 
```
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```
As explained in the man pages for cron(5), the first 5 entries on the line are time and date values in the order minute, hour, day of month, month, day of week. * is a wildcard for all valid values, so this cron tab runs every 60 times per minutes, every day of the year. The next part of the line is a username to run the following command as. This is specific to crontabs in `/etc/cron.d` and `/etc/crontab`, crontabs in other directories will be run as the user that owns the file. The rest of the line is the command to run, which executes a shell script and redirects both `stdout` and `stderr` to the `null` device so that any output messages are invisible. (The `&>` construct is explained in more details in the `bash` man pages). Returning to the first line, @reboot is just a 'nickname' to specify that a cron job should be run once after reboot. \
\
Inspecting the shell script at `/usr/bin/cronjob_bandit22.sh` we see that it first changes the permissions for a temporary file to 644, which gives read/write access to the file owner, and read access to the file group and to others. As the script is executed as bandit22 only that user can write to the file, but anyone else can read it. The script then writes the contents of the bandit22 password file to the file in the temporary directory. All we need to do is read the contents of the file to get the password for bandit22. 

### Solution
```
cd /etc/cron.d
cat cronjob_bandit22
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

## Level 22
Level 22 follows on nicely from level 21. Once again we find a cron job in `/etc/cron.d`, this time named `cronjob_bandit23`, which runs the shell scipt `/usr/bin/cronjob_bandit23.sh`. As with level 21 the job is scheduled to run every minute. \
\
The shell script is fairly easy to understand, but is worth going through line by line. 
```
#!/bin/bash
```
This is the conventional 'hash-bang' used by Unix-like shells so that they know which interpreter to use to execute a script. 

```
myname=$(whoami)
```
This creates a variable in the script, named `myname`, whose value is set as the result of executing the `whoami` utility, which returns the username of the user that is currently executing a program. When the script runs it will be executed as bandit23. 

```
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
```
This creates another variable, `mytarget`. The value will be the result of piping 'I am user bandit23' (note that $myname in the command will be expanded to be the value stored in the `myname` variable, which we know will be bandit23), to the `md5sum` utility. `md5sum` will take the input and produce a MD5 message digest. The output from `md5sum` is then piped to the `cut` utility. `cut` removes sections from lines of text and is a bit like a string split operation in C# or Python. The `-d` switch changes the default tab delimiter, in this case a single space will be used instead. The `-f` switch tells `cut` which fields to select from the results, here we are selecting the first field. The result is that only the md5sum is output to the terminal, and the trailing ' -' is cut off. So `mytarget` will be set to some MD5 message digest produced from the text piped to `md5sum`.

```
echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"
```
This line will write a message to the terminal and lets the user know that the password stored in `/etc/bandit_pass/bandit23` will be copied to a temporary file whose name will be set as the value written previously to `mytarget`. However, because `stdout` and `stderr` were redirected to a null device in the cron job file the output will never be visible. For this reason, we need to run the above command manually so that we know where the password will be written to. 

```
cat /etc/bandit_pass/$myname > /tmp/$mytarget
```
This line is where the bandit23 password is written to the temporary file. We are able to read this file because it was originally create with read permissions for 'others', which we can see by running `ls -l` on the temporary file. 

### Solution 
```
cd /etc/cron.d
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```
## Level 23
The first few steps of this level are the same as the previous two levels where we find out what cron job is executed as the next level's user. In this case that will be `/usr/bin/cronjob_bandit24.sh`. Once again, it is worth going through the script to understand what it does. 

```
#!/bin/bash
myname=$(whoami)
```
As we saw previously, this indicates which interpreter to execute the script as and sets the variable `myname` to bandit24. 

```
cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
```
The script changes its working directory to `/var/spool/bandit24/foo` and writes some text to the terminal (which again, nobody will see as it is written to a null device). 

```
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```
The first line creates a for loop that iterates over all regular files (\*) all dotted files (.*) in the working directory. The if statement checks each file to ensure that the file isn't ".", which corresponds to the current directory, or ".." **what does this correspond to?**. The `-a` in the if statement corresponds ot logical AND. `stat` returns information about a file, and here it is used to get the user name of the owner of the current file (see the man pages for `stat` or other format specifiers and the information they return) and assign it to a variable named `owner`. If the owner of the current file is bandit23 then it is executed. To protect the system `timeout` is used to execute each script. The `-s` flag is used to sent a signal to the running script after 60 seconds, and signal 9 corresponds to `SIGKILL`. This ensures that any script that runs for longer than 60 seconds is killed to prevent malicious scripts from performing long running tasks. Finally, once each file is executed, it is deleted to ensure that it only runs once. \
\
We need a script that copies the bandit24 password to a directory that we control. We already saw a command to do a very similar task in the previous level, and with only a small modification we can make it do what we want. But first, we need somewhere to write the password to. First, we create a new directory with `mktemp -d` and change to that directory. Next, we need to create our script. The following will suffice for what we need to achieve: 
```
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp.pzoOsl22a6/bandit24_password
```
Save this file as myscript.sh

We need to set some permissions for our temporary directory and our script. This is probably not the best way to set the permissions, but for the purpose of the challenge, it will work. `chmod 0777 -R /tmp/tmp.pzoOsl22a6/` will set the read, write, and execute permissions for our temporary directory and all files within it. As a quick side note, the execute permission on a directory is a little misleading in Unix-like systems. The executable permission doesn't make a directory executable (that makes no sense), what it does is allow a user, group, or other, to search the directory. Without the execute permission it is not possible to perform common operations like opening a directory, renaming a directory, or descending into subdirectories. As our shell script will create a new file in our temporary directory it needs to be able to perform operations on the directory, such as creating the new password file within it. So while it seems like just the read and write permissions would be suitable, it turns out that we also need the execute permission to allow the shell script to get into our temporary directory in the first place. With that out of the way, we can move onto the execute permission for the script. This makes sense for the script as it needs to be executed by an interpreter. You can easily confirm that a file is executable by running `ls`, if the filename is dispalyed in a green font, it is executable. (This might be different in other shells, but it is true for the bandit challenges). Now all we have to do is copy out script to `/var/spool/bandit24/foo` and wait for it to be executed! If all goes well, the password for bandit24 will be written to our temporary directory. 

### Solution
```
cat /etc/cron.d/cronjob_bandit24
cat /usr/bin/cronjob_bandit24.sh
mktemp -d
cd /tmp/tmp.pzoOsl22a6
touch myscript.sh
```
Paste script into myscript.sh, change directory names as required
```
chmod 0777 -R /tmp/tmp.pzoOsl22a6
cp myscript.sh /var/spool/bandit24/foo/
```
Wait up to 60 seconds
```
cat bandit24_password
```

## Level 24
The level description is pretty explicit in telling us that we will need a brute-force solution to the problem, so it's best to not get too clever and to follow the instructions. As with some earlier challenges we need to use a utility like `nc` to talk to the daemon on port 30002. Starting with a simple test we see than running `nc localhost 30002` results in a successful connection to the daemon where it asks for the bandit24 password and a pincode. Crucially, if we enter an incorrect value, the daemon responds with a message to let us know and waits for more input. So we know the daemon runs in a loop until we disconnect from it, which will make it easier to brute-force the solution. \
\
To get the bandit25 password we will need to loop through all the possible pin code values until we get the right answer. The next step is to see if the daemon will keep responding if we pipe it input from a file. Adding a few lines to a text file will suffice for testing purposes: 
```
<bandit24 password> 1234
<bandit24 password> 5678
```
If we pipe the file to the daemon with `cat passwords.txt | nc localhost 30002` we see that indeed the daemon accepts the input line by line and responds accordingly. \
\
Writing out all the combinations will take too long, so we may as well create a simple shell script to do it for us. We can do this with a `for` loop similar to the one we saw in bandit23. The script needs to loop through all the possible pin code combinations and write them to our passwords file. The for loop can be constructed as follows: 
```
#!/bin/bash

for i in {0..10000}
do
    echo "<bandit_password> $i" >> passwords.txt
done
```
If we make this script executable with `chmod +x` then we can run it and generate our brute-force list of inputs for the daemon. \
\
The last thing to do is simply pipe the input to the daemon and wait until we send the right pin code so that we get the password for bandit25. 

### Solution
Start by creating a temporary directory and a file for our brute-force input to the daemon. 
```
mktemp -d
cd /tmp/tmp.directoryname
touch passwords.txt
```
Next, create the shell script. 
```
touch script.sh
chmod+x script.sh
```
Add the for loop to the script with a utility like `nano` and save it. 
```
#!/bin/bash

for i in {0..10000}
do
    echo "<bandit_password> $i" >> passwords.txt
done
```
And finally, connect to the daemon and send it the list of inputs. 
```
cat passwords.txt | nc localhost 30002
```

## Level 25
ssh -i ./bandit26.sshkey bandit26@localhost -p 2220 