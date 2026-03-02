## Introduction to Active Directory
* **AD** is Microsoft's directory service for managing authentication, authorization, and access to Windows domain networks. It acts as a single point of control for admins to manage users, computers, and other devices.
  * Main objective of attacking AD is to gain **Domain Admin** (DA) access to a **Domain Controller** (DC).
* **Domain Controller** is the center of the network domain and is responsible for all interactions concerning the domain, including user logins, resources access, and more.
  * When a user logs into a domain-joined computer, the DC verifies the login credentials and grants appropriate access and privileges based on the stored user profiles and group policies.
* By default, active directory includes several groups, including **domain users** and **domain admins**. Members of the DA group hold significant levels of control, as they have admin access over the domain and are also assigned to the local administrator group of each domain-joined computer. This gives them unrestricted control over all domain computers.
  * Gaining access to the DC via DA credentials gives you ultimate control over an entire network domain. It facilitates moving through a network and performing administrative tasks unrestricted to exploit the system while appearing as a legitimate user.
<div align="center"><img width="551" height="516" alt="image" src="https://github.com/user-attachments/assets/97552527-d8aa-4aa6-b158-bd044d07af72" /></div>

## Introduction to Active Directory Attacks Overview
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

## Local Passwords
* When landing on a Windows system as a result of initial access, your next steps will involve some sort of privilege escalation or lateral movement. Often, both of these techniques will rely on harvesting passwords from your target environment to accomplish this.
* Passwords can be found on your target host in various locations, including common places, such as the Windows registry, and uncommon places such as files and folders, the Security Account Manager (SAM), SYSTEM, SECURITY, and LSASS.

### Common Places
* **PowerUp**: Common local escalation tool is PowerUp.ps1 which searches for passwords in common places, including the Windows registry and unattended files. To use PowerUp, you'll first need to transfer it onto the target host and import the module in PS with `Import-Module .\PowerUp.ps1`. You can then execute it with `Invoke-AllChecks`. PowerUp will then search for the host for any passwords.
   * One specific location PowerUp checks is the registry. For example, it queries the following key to check for autologon credentials: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CUrrentversion\Winlogon`. Without PowerUp, you can check this manually by running the following command from a terminal: `reg query "HKLM\Software\Microsoft\Windows NT\Currentversion\Winlogon"`.
   * Another place where PowerUp will check for is an adminstrator pass in either of these two paths: `C:\Windows\Panter\Unattend.xml` and `C:\Windows\Panther\Unattend\Unattend.xml`. In large scale deployments, unattended installations of Windows operating systems are necessary. System admins can set up admin passwords in these files. If improperly cleaned up at the end of installation, they can provide malicious users with the means to gain admin privileges over the target host.  
