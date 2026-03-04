## Phase 1: The "Shell Dropper" (Web → Foothold)
**Objective:** Learn to upload/inject code to gain your first interactive system access via a Web Shell.

| Machine | Difficulty | OS | Key Learning Objective | Completed? |
| :--- | :--- | :--- | :--- | :--- | 
| **Bashed** | Easy | Linux | Transitioning from a browser-based shell to a real reverse shell. |
| **Nibbles** | Easy | Linux | Exploiting a CMS file upload to "drop" a PHP shell and gain a foothold. |
| **Devel** | Easy | Windows | Uploading an `.aspx` web shell via FTP to gain a Windows service account. |
| **Curling** | Medium | Linux | Modifying CMS templates (Joomla) to inject and execute system commands. |

---

## Phase 2: Windows Internals & Local Escalation
**Objective:** Learn how to move from a "Web User" or "Service Account" to "SYSTEM."

| Machine | Difficulty | OS | Key Learning Objective | Completed? |
| :--- | :--- | :--- | :--- |:--- | 
| **Blue** | Easy | Windows | Exploiting a system service (SMB) to land directly in a SYSTEM shell. |
| **Bastard** | Medium | Windows | Exploiting a Drupal RCE and performing Windows privilege escalation. |
| **Snip3r** | Medium | Windows | Using RCE to gain access, then exploring Windows file structures and tokens. |
| **Legacy** | Easy | Windows | Foundational "Internals" logic; older Windows service vulnerabilities. |

---

## Phase 3: Active Directory "Assumed Breach"
**Objective:** These labs focus on lateral movement and attacking the **Domain Controller (DC)**.

| Machine | Difficulty | OS | Key Learning Objective | Completed?| 
| :--- | :--- | :--- | :--- |:--- | 
| **Active** | Medium | Windows | Extracting passwords from Group Policy Preferences (GPP) XML files. |
| **Forest** | Medium | Windows | First true AD machine. **AS-REP Roasting** and mapping with BloodHound. |
| **Cascade** | Medium | Windows | Advanced enumeration of LDAP and log files to find "hidden" AD credentials. |
| **Sauna** | Medium | Windows | Enumerating users via LDAP and performing **DCSync** attacks. |

---

## Phase 4: Chaining the Attack (Web → Internal Pivot)
**Objective:** The "Exam Simulator." Breach a web server, then "tunnel" your traffic through it to attack the hidden internal AD network.

| Machine | Difficulty | OS | Key Learning Objective | Completed? |
| :--- | :--- | :--- | :--- |:--- | 
| **Search** | Hard | Windows | Breach via a web app, then **Pivot** (tunnel) to reach the internal DC. |
| **Intelligence** | Medium | Windows | Web-based discovery leading to AD service accounts and Kerberos exploitation. |
| **Blackfield** | Hard | Windows | A "target-rich" AD environment requiring credential harvesting across users. |

---

## Essential Toolset for the Roadmap

* **For Shells:** `Pentestmonkey PHP Reverse Shell`, `msfvenom`, `rlwrap`.
* **For AD/Internals:** `BloodHound`, `Impacket-Suite`, `PowerView`, `mimikatz`.
* **For Pivoting:** `Ligolo-ng` (highly recommended for the exam), `Chisel`.
