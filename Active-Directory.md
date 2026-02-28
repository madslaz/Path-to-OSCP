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
