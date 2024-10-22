# Active Directory Lab 🏢💻

## Table of Contents
1. [Tools Used 🔧](#tools-used)
2. [Diagram Creation 🖼️](#1-diagram-creation)
3. [Installation of All Virtual Machines ⚙️](#2-installation-of-all-virtual-machines)
4. [Setting Up Splunk Server and Sysmon 🔍](#3-setting-up-splunk-server-and-sysmon)
5. [Installing and Configuring Active Directory 📜](#4-installing-and-configuring-active-directory)
6. [Conducting a Brute Force Attack 🔓🔍](#5-conducting-a-brute-force-attack)
7. [Installing Atomic Red Team 🧪](#6-installing-atomic-red-team)
8. [Summary 📝](#summary)

---

## Tools Used 🔧
- **Virtual Machines:** Kali Linux, Windows 10, Windows Server, Ubuntu (Splunk)
- **Splunk:** For log analysis and monitoring
- **Splunk Universal Forwarder:** To forward logs to the Splunk server
- **Sysmon:** For capturing Windows system events
- **Active Directory:** For domain management and user authentication
- **Hydra:** For brute-force attack simulations
- **Atomic Red Team:** For simulating attack techniques and testing defenses

## 1. Diagram Creation 🖼️
I started by creating a network diagram to visualize the lab setup.

![obraz](https://github.com/user-attachments/assets/20c73387-0c7c-4d1c-b0b2-72d719a2c67f)

---

## 2. Installation of All Virtual Machines ⚙️
![obraz](https://github.com/user-attachments/assets/83eefbdc-0aa1-4aa9-b5aa-4ec1ff502204)

We have here 4 machines. The first one is Kali Linux which will be used for conducting a brute-force attack.
The second one is our Target Windows Machine.
The third one is Windows Server Machine.
The last one is Splunk.

---

## 3. Setting Up Splunk Server and Sysmon 🔍

1. **Configuring Network on the Splunk Server:**
Displayed the IP address and adjusted it to match the IP on the diagram.

![obraz](https://github.com/user-attachments/assets/2f33a756-801e-4c1e-8271-9003b687fa7a)


Confiugred the network on Splunk.

![obraz](https://github.com/user-attachments/assets/537a2123-6d20-4c87-a5fc-c5b9a045c71f)

Changed the IP address to `192.168.10.10`.

![obraz](https://github.com/user-attachments/assets/3e7853f4-7f28-4f8b-88e4-bf8e9cc7ac68)

2. **Downloading Splunk:**
Downloaded Splunk on my host machine for later transfer to the Splunk server.

![obraz](https://github.com/user-attachments/assets/87b67c70-55d6-4ca0-9a89-c88b05338a59)

Added myself to the shared folder to transport Splunk from the host to the Ubuntu machine.

![obraz](https://github.com/user-attachments/assets/0d729a16-c6fb-43ab-bf53-0644f4388903)

Getting my shared folder to the shared directory on Ubuntu:

![obraz](https://github.com/user-attachments/assets/bbfbd2e6-0002-49ff-ac78-bef4aaf28be5)

3. **Installing Splunk:**
Installed Splunk and made sure it starts automatically as the `splunk` user on every reboot.

![obraz](https://github.com/user-attachments/assets/134de2a1-438f-473b-af0f-427f2dea2a55)

That's where Splunk is located:

![obraz](https://github.com/user-attachments/assets/4c2ead76-6b5d-4b3d-aafa-8162321463c2)

Making sure it reboots as 'splunk' on every reboot:

![obraz](https://github.com/user-attachments/assets/4e194b61-c06d-46b5-a8be-93ac883096b0)


4. **Configuring the Windows 10 Machine:**
Renamed the machine:

![obraz](https://github.com/user-attachments/assets/73e85ec8-f110-44dc-bc04-ac5edb972ad9)

Made sure it matches the IP on our diagram:

![obraz](https://github.com/user-attachments/assets/767c2c9f-434b-4e9e-96c2-fd62c0d7195e)

Verified connectivity to the Splunk server from the Windows 10 machine.

![obraz](https://github.com/user-attachments/assets/03edcd9c-03cf-472c-b214-c596238e14c3)

5. **Installing the Splunk Universal Forwarder:**
Installed the Universal Forwarder on the Windows 10 machine.

![obraz](https://github.com/user-attachments/assets/587b2f98-3616-4e27-9b8b-86763467c3e5)

Created a configuration file in the Splunk Forwarder folder to forward logs to the Splunk server.

![obraz](https://github.com/user-attachments/assets/0acfbc6e-5de8-48a5-9c93-a5b279fa637f)

Restarted the Splunk Forwarder.

![obraz](https://github.com/user-attachments/assets/18f99d68-a143-40af-ba0b-5ad6b69a8ca1)

6. **Finalizing Splunk Server Configuration:**
Starting:

![obraz](https://github.com/user-attachments/assets/ebf1092b-985a-4170-89a7-e4c5145d2c9e)

Added a new index in Splunk.

![obraz](https://github.com/user-attachments/assets/6a8bc706-4352-4793-8880-64f8bf71d2b2)

Configured Splunk to listen on port `9997`.

![obraz](https://github.com/user-attachments/assets/c099d5fd-6193-4f40-a296-837739d3f2a8)


Verified that Splunk was listening on the endpoint.

![obraz](https://github.com/user-attachments/assets/5abdfe2c-369c-4ca9-a927-4f5db5d3fb4c)

Events were divided and displayed in the Splunk interface.

![obraz](https://github.com/user-attachments/assets/21fbb328-c802-4be8-9d93-274734c79011)


7. **Repeating Steps for the Active Directory Server:**
The process was similar, so details are skipped.
Verified that Splunk now recognized two hosts: the target machine and the Active Directory server.

![obraz](https://github.com/user-attachments/assets/2ff0ddc3-2cb3-48a1-8a78-ef38a8c0d3fb)

---

## 4. Installing and Configuring Active Directory 📜

1. **Setting Up the Domain:**
Installed and configured Active Directory, promoted the Domain Controller, and added the Windows PC to the domain.

![obraz](https://github.com/user-attachments/assets/d0ba50af-8ff0-4a80-8114-d2053d7a7431)

Adding our domain:

![obraz](https://github.com/user-attachments/assets/c9fe1c2d-f6a3-42ed-8288-f6df6f439c02)

Further configuring the Active Directory. Attackers like to attack Domain Controller as it contains various information and files for example database. It also stores passwords hashes there.

![obraz](https://github.com/user-attachments/assets/362e49d7-d7c6-4617-bd09-dc40115db1b8)

Adding users to Active Directory:

![obraz](https://github.com/user-attachments/assets/271fc24c-a71f-4507-b01c-1702b8134664)

2. **Adding Users and Organizational Units:**
Created an Organizational Unit named "IT" and added a user.

![obraz](https://github.com/user-attachments/assets/65d55b97-9b59-4381-9942-b7d3e16b1662)

3. **Adding the Windows Target Machine to Active Directory:**
Successfully connected the Windows machine to the domain.

![obraz](https://github.com/user-attachments/assets/590e5016-dc2b-4707-b608-c40c9e484956)

Changed DNS to my active directory to make the connection possible:

![obraz](https://github.com/user-attachments/assets/d042524f-c96d-481c-9444-33906c300c4a)

Success!

![obraz](https://github.com/user-attachments/assets/e5f1b425-7a5e-4823-be51-bb7fb41f6ae3)

Loggin in as a domain user:

![obraz](https://github.com/user-attachments/assets/f74f2d2e-e264-46de-b911-7a0bd4c45a2a)


---

## 5. Conducting a Brute Force Attack 🔓🔍

1. **Installing Crowbar for Brute-Force Attack (I finally used Hydra as Crowbar didn't work):**

![obraz](https://github.com/user-attachments/assets/701ad9f2-7752-4a67-b710-c50bb1f0f299)

Allowed remote connections on the target PC.

![obraz](https://github.com/user-attachments/assets/c39cc386-d936-46c2-92ca-2f2026bbcdc4)

Performed a brute-force attack.

![obraz](https://github.com/user-attachments/assets/e6aaac0e-07a0-4219-9a5a-326b194eb0cb)

Detected various events in Splunk:
     - **Event 5379:** Occurs when a user performs a read operation in the Credential Manager.
     - **Event 4625:** Indicates a failed login attempt.
     
![obraz](https://github.com/user-attachments/assets/4aff2b69-eaf3-4bb5-99c2-1825a6375fd3)

**Event 4624:** Successful login; details about the machine used were also available.

![obraz](https://github.com/user-attachments/assets/c0f3eadc-a6e8-4f67-808b-e665583292af)
    

---

## 6. Installing Atomic Red Team 🧪

1. **Setting Up Atomic Red Team:**

![obraz](https://github.com/user-attachments/assets/933f3fa9-4400-42bf-a2b2-647b878d19c5)

Added the `C:` drive to exclusions.

![obraz](https://github.com/user-attachments/assets/1a5193e8-c6e9-484c-8a5e-5c5bd6c7b35e)

Installed Atomic Red Team.

![obraz](https://github.com/user-attachments/assets/ab42028f-2558-4fca-a1aa-7a30645ee5b0)


2. **Running Telemetry:**
Checked for local account creation. It wasn’t detected by Splunk because it was a local account.

![obraz](https://github.com/user-attachments/assets/ffc348e6-9182-40be-a0c8-42d961f76267)


3. **Testing Command and Scripting Interpreter Techniques:**
Even the Windows Defender detected suspicious activity.

![obraz](https://github.com/user-attachments/assets/6e6a939f-bd9f-4bbf-84e0-bfbe8d3e15ca)

The events were successfully logged in Splunk.

![obraz](https://github.com/user-attachments/assets/ea049028-0777-4f38-bc22-41074e1d7055)


---
## Summary 📝
The Active Directory Lab setup aimed to simulate a typical enterprise environment, complete with security monitoring using Splunk. The simulated attacks and monitoring configurations provided insights into the detection and prevention of various threats. 🚀
Project made with help of MYDFIR on YouTube.
