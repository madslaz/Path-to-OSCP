## Introduction to Active Directory
* **AD** is Microsoft's directory service for managing authentication, authorization, and access to Windows domain networks. It acts as a single point of control for admins to manage users, computers, and other devices.
  * Main objective of attacking AD is to gain **Domain Admin** (DA) access to a **Domain Controller** (DC).
* **Domain Controller** is the center of the network domain and is responsible for all interactions concerning the domain, including user logins, resources access, and more.
  * When a user logs into a domain-joined computer, the DC verifies the login credentials and grants appropriate access and privileges based on the stored user profiles and group policies.
* By default, active directory includes several groups, including **domain users** and **domain admins**. Members of the DA group hold significant levels of control, as they have admin access over the domain and are also assigned to the local administrator group of each domain-joined computer. This gives them unrestricted control over all domain computers.
  * Gaining access to the DC via DA credentials gives you ultimate control over an entire network domain. It facilitates moving through a network and performing administrative tasks unrestricted to exploit the system while appearing as a legitimate user.
<div align="center"><img width="551" height="516" alt="image" src="https://github.com/user-attachments/assets/97552527-d8aa-4aa6-b158-bd044d07af72" /></div>

## Introduction to Active Directory Attack Techniques
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

#### LAB: Introduction to Mimikatz
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
   * `kerberos`: Used to manipulate Kerberos tickets, which are essential for authentication in Windows networks. Attackers can use commands like `kerberos::golden` to create golden tickets or `kerberos::list` to display available Kerberos tickets.
   * `lsadump`: Extracts sensitive information, such as credentials and security policies, from the Local Security Authority (LSA). A common command is `lsadump::sam` for dumping password hashes from the Security Account Manager (SAM).
   * `privilege`: Crucial for elevating permissions within Mimikatz. Running `privilege::debug` grants the tool the necessary privileges to access restricted memory areas and perform many of its core functions. 
