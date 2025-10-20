# 🛡️ TraceForge

**TraceForge – Your All-in-One Cybersecurity Toolkit**
Modular, interactive PowerShell project to collect, analyze, and secure system data.

## 🌟 Overview

TraceForge is a **PowerShell-based toolkit** for:

* Collecting system information
* Analyzing logs
* Auditing firewall rules
* Detecting hidden data (steganography)
* Securely storing files

It is **interactive, beginner-friendly**, and offers a **modern hacker-style CLI experience**.

## 🔧 Features / Modules

| Module                  | Description                                                             |
| ----------------------- | ----------------------------------------------------------------------- |
| **Log Collector**       | Collects running processes, services, startup entries, and network info |
| **Log Analyzer**        | Analyzes logs: offline and AI-assisted                                  |
| **Firewall Auditor**    | Audits firewall rules and provides remediation suggestions              |
| **Stega Tool**          | Detects and embeds hidden data (steganography) in files                 |
| **Secure File Storage** | Encrypts, decrypts, and securely stores files                           |

## 📂 Project Structure

```
TraceForge/
│
├─ TraceForge.ps1           # Main launcher
├─ LogCollector/
├─ LogAnalyzer/
├─ FirewallAuditor/
├─ StegaTool/
├─ SecureFileStorage/
├─ Configs/
│   └─ trusted_config.json
└─ Output/
```

Each module folder contains its **scripts** and **core functions**.
The `Output/` folder stores all **scan results**.

## ⚙️ Installation

1. Ensure **PowerShell 5.1 or newer** is installed.
2. Download or clone the `TraceForge` folder.
3. Set execution policy if required:

   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
4. Keep the folder structure intact.

## 🚀 Usage

1. Open PowerShell.
2. Navigate to the `TraceForge` folder:

   ```powershell
   cd path\to\TraceForge
   ```
3. Launch TraceForge:

   ```powershell
   .\TraceForge.ps1
   ```
4. The interactive menu shows all modules.

   * Enter the **number** of the module you want to run.
   * Modules present on disk are marked with `*`.

## 📝 Configuration

* The `Configs/trusted_config.json` file stores **trusted items**.
* Some modules read this file to **skip trusted processes or files**.

## 📊 Output

* All scan results are saved in **timestamped folders** in `Output/`.
* Example:

```
Output/
├─ scan_2025-10-12_19-25-05/
│   ├─ file.txt.enc
│   ├─ file.txt.meta.json
│   └─ operation_log.json
└─ Decrypted/
    ├─ file.txt
    └─ cover_image.png
```

* Each module saves **raw and analyzed results** in JSON.

## 🤝 Contributing

* Add new modules by creating a **folder with scripts and core functions**.
* Update `TraceForge.ps1` to include it in the main menu if needed.

## ⚠️ Disclaimer

* **For educational and lab use only.**
* Do not use TraceForge on systems without **explicit permission**.
* Author is not responsible for misuse.


## 📄 License

This project is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

* You are free to **use, share, and modify** this project for **educational, research, or personal learning purposes**.
* You **cannot use it for commercial purposes** without explicit permission from the author.
* Attribution to the author (**Chanakya Marode**) is required when sharing or modifying the project.



