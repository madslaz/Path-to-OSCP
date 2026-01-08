## Introduction to Active Directory
* **AD** is Microsoft's directory service for managing authentication, authorization, and access to Windows domain networks. It acts as a single point of control for admins to manage users, computers, and other devices.
  * Main objective of attacking AD is to gain **Domain Admin** (DA) access to a **Domain Controller** (DC).
* **Domain Controller** is the center of the network domain and is responsible for all interactions concerning the domain, including user logins, resources access, and more.
  * When a user logs into a domain-joined computer, the DC verifies the login credentials and grants appropriate access and privileges based on the stored user profiles and group policies.
* By default, active directory includes several groups, including **domain users** and **domain admins**. Members of the DA group hold significant levels of control, as they have admin access over the domain and are also assigned to the local administrator group of each domain-joined computer. This gives them unrestricted control over all domain computers.
  * Gaining access to the DC via DA credentials gives you ultimate control over an entire network domain. It facilitates moving through a network and performing administrative tasks unrestricted to exploit the system while appearing as a legitimate user.
