
# Simulated Ransomware Decryption Guide

## 📌 1. Test Esok @ 10, datang kul 9
Single binary file: **gmi.exe** ✅

## 🔧 2. Steps

### 2.1. Identify the binary
- ✅ Get hash of binary
- ✅ Use DIE (Detect It Easy) to identify language

#### 2.1.1. DIE
Download: https://github.com/horsicq/DIE-engine/releases  
- Detected: Python + PyInstaller

### 2.2. Find PyInstaller Decompiler
Google: `pyinstaller Decompiler`

### 2.3. Install pyinstxtractor-ng
- Repo: https://github.com/pyinstxtractor/pyinstxtractor-ng  
- Direct EXE: https://github.com/pyinstxtractor/pyinstxtractor-ng/releases/download/2025.01.05/pyinstxtractor-ng.exe

### 2.4. Decompile

#### 2.4.1. Convert .exe to .pyc
```powershell
.\pyinstxtractor-ng.exe gmi.exe
```

Sample output shows extracted `.pyc` file like `gmi2025.pyc`.

#### 2.4.2. Find .pyc decompiler
Google: `decompile .pyc`  
Reference: https://stackoverflow.com/questions/5287253

#### 2.4.3. Install uncompyle6
```powershell
pip install uncompyle6
```  
More info: https://pypi.org/project/uncompyle6/

#### 2.4.4. Convert .pyc to .py
```powershell
uncompyle6.exe -o . .\gmi2025.pyc
```

## 🧰 3. Tools
- Python 3.8
- DIE (Detect It Easy)
- pyinstxtractor-ng
- uncompyle6

### 3.1. Good to have
- Everything app
- 7-Zip
- Git
- File manager: https://www.zabkat.com/x2lite.htm
