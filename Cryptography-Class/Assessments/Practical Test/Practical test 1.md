
# Practical Test: SSH Configuration Between Kali Linux and Windows Server 2022

This document details the step-by-step process of configuring and testing SSH connectivity from Kali Linux to Windows Server 2022 and vice versa.

---

## 🐱‍💻 Objective

1. Enable and configure the SSH server on Kali Linux.
2. SSH into Kali from Windows using PowerShell.
3. Set up SSH key-based authentication.
4. Install and configure OpenSSH Server on Windows Server 2022.
5. SSH into Windows Server from Kali Linux.

---

## 🛠️ Part 1: Configure SSH Server on Kali Linux

### Step 1: Update the Kali package list
If you're experiencing GPG key issues, manually download and install the Kali archive keyring.

```bash
sudo apt update
```

If GPG error occurs:
```bash
sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
sudo apt update
```

### Step 2: Install and Enable OpenSSH Server

```bash
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

Confirm SSH service is running.

---

## 🖥️ Part 2: SSH from Windows to Kali

### Step 1: SSH to Kali from PowerShell

Replace the IP with your Kali's actual IP address:

```powershell
ssh ha1qal@192.168.106.130
```

If successful, you’ll be prompted for your Kali user password.

---

## 🔐 Part 3: Enable SSH Key Authentication from Windows to Kali

### Step 1: Generate SSH key in Windows

Run in PowerShell:

```powershell
ssh-keygen
```

This will generate an SSH key pair (`id_ed25519` and `id_ed25519.pub`) in `C:\Users\<Username>\.ssh\`.

### Step 2: Copy the Public Key to Kali

Use PowerShell to append your public key to Kali's `authorized_keys`:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh ha1qal@192.168.106.130 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

Now you can SSH into Kali without entering a password.

---

## 🧑‍💼 Part 4: Configure SSH Server on Windows Server 2022

### Step 1: Install OpenSSH Server

Open **PowerShell as Administrator** and run:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

### Step 2: Enable and Start the SSH Service

```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

### Step 3: Allow SSH Through Windows Firewall

```powershell
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### Step 4: Confirm SSH Server is Running

```powershell
Get-Service sshd
```

Output should show:
```
Status   Name               DisplayName
------   ----               -----------
Running  sshd               OpenSSH SSH Server
```

### Step 5: Check Windows Server IP Address

```powershell
ipconfig
```

Example IP used: `192.168.106.143`

---

## 🧪 Part 5: Test SSH from Kali to Windows

Now on your Kali machine:

```bash
ssh administrator@192.168.106.143
```

You’ll be prompted to accept the fingerprint and provide the Windows password for the administrator account.

---

## ✅ Conclusion

At the end of this test, the following setups are confirmed:

- SSH server is correctly configured on **Kali Linux**.
- SSH client and key-based authentication from **Windows to Kali** works.
- **Windows Server 2022** is configured with OpenSSH Server, accepting SSH connections.
- Successful SSH connection from **Kali to Windows Server 2022** using the default `administrator` account.

This setup provides a secure and efficient way to manage both Linux and Windows systems over SSH.

---
