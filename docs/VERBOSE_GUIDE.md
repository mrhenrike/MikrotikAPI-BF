# 📢 Verbosity Guide - MikrotikAPI-BF v2.0

## 🎯 Verbosity Levels

MikrotikAPI-BF v2.0 has **3 verbosity levels** to control the amount of information displayed.

---

## 📊 Available Levels

### **Level 0: Normal (Default)**
**Command**: `python mikrotikapi-bf.py -t TARGET -d examples/combos.txt`

**What it shows**:
- ✅ CHECKING TARGET SERVICES (port scan)
- ✅ Port Scan Results
- ✅ ATTACK CONFIGURATION (attack config)
- ✅ First 3 attempts (to show it's working)
- ✅ Successes (credentials found)
- ✅ ATTACK STATISTICS (final statistics)
- ✅ Final results
- ✅ SERVICE SUMMARY

**What it does NOT show**:
- ❌ All attempts
- ❌ Individual failures
- ❌ Connection warnings
- ❌ Internal debug

**Ideal for**: Quick executions, when you only want the results.

---

### **Level 1: Verbose (`-v`)**
**Command**: `python mikrotikapi-bf.py -t TARGET -d examples/combos.txt -v`

**What it shows** (in addition to Level 0):
- ✅ **ALL attempts** being tested
- ✅ **Failures** of authentication (`[FAIL]`)
- ✅ **Warnings** general (`[WARN]`)
- ✅ Connection errors summarized

**Example output**:
```
[10:30:15] [TEST] admin:admin
[10:30:15] [FAIL] [API] admin:admin
[10:30:16] [TEST] admin:password
[10:30:16] [SUCC] [API] admin:password ← FOUND!
[10:30:17] [TEST] admin:123456
[10:30:17] [FAIL] [API] admin:123456
```

**Ideal for**: Monitor progress in real time, see what's being tested.

---

### **Level 2: Very Verbose / Debug (`-vv`)**
**Command**: `python mikrotikapi-bf.py -t TARGET -d examples/combos.txt -vv`

**What it shows** (in addition to Level 1):
- ✅ **Internal debug** from each module
- ✅ **Complete errors** with stack trace
- ✅ Socket connection details
- ✅ Skip messages
- ✅ Timeout details
- ✅ Proxy connection details
- ✅ Thread execution info

**Example output**:
```
[10:30:15] [DEBB] Worker thread #1 started
[10:30:15] [DEBB] Testing proxy connection...
[10:30:15] [DEBB] Trying -> admin:admin
[10:30:15] [DEBB] Connecting to 192.168.88.1:8728
[10:30:15] [FAIL] [API] admin:admin
[10:30:15] [WARN] [API] Connection error: [Errno 10061] No connection could be made...
[10:30:16] [DEBB] Trying -> admin:password
[10:30:16] [SUCC] [API] admin:password
[10:30:16] [DEBB] Testing FTP for admin:password on port 21
```

**Ideal for**: Troubleshooting, debugging, development.

---

## 🔍 Visual Comparison

### Scenario: 5 attempts, 1 success

#### **Normal (no flags)**
```
============================================================
CHECKING TARGET SERVICES
============================================================
Target: 192.168.88.1
Scanning ports...

Port Scan Results:
  API (8728):  ✓ OPEN
  HTTP (80): ✓ OPEN
============================================================

============================================================
ATTACK CONFIGURATION
============================================================
Target         : 192.168.88.1
API Port       : 8728
Total Attempts : 5
============================================================

[10:30:15] [TEST] admin:***
[10:30:16] [TEST] admin:********
[10:30:17] [TEST] root:****

[SUCC] [10:30:16] [API] admin:password

============================================================
ATTACK STATISTICS
============================================================
Total Tested    : 5
Successful      : 1
Failed          : 4
Success Rate    : 20.0%
============================================================
```

#### **Verbose (`-v`)**
```
(everything from Normal, PLUS:)

[FAIL] [10:30:15] [API] admin:admin
[FAIL] [10:30:15] [REST] admin:admin
[FAIL] [10:30:16] [API] root:root
[SUCC] [10:30:16] [API] admin:password
[SUCC] [10:30:16] [REST] admin:password
[FAIL] [10:30:17] [API] manager:manager
```

#### **Very Verbose (`-vv`)**
```
(everything from Verbose, PLUS:)

[DEBB] [10:30:15] Worker thread #1 initialized
[DEBB] [10:30:15] Testing admin:admin
[DEBB] [10:30:15] Connecting to 192.168.88.1:8728
[WARN] [10:30:15] Connection timeout after 5s
[ERROR] [10:30:15] Socket error: Connection refused
[DEBB] [10:30:16] Trying next combination
[SKIP] [10:30:17] FTP test skipped due to port check
```

---

## 🎯 When to Use Each Level

### **Normal** (Default)
✅ Production / Official audits  
✅ When you already know it works  
✅ Clean output for reports  
✅ Don't want to clutter terminal  

### **Verbose** (`-v`)
✅ Development / Testing  
✅ Want to see real-time progress  
✅ Basic troubleshooting  
✅ Verify if specific credentials were tested  

### **Very Verbose** (`-vv`)
✅ Deep debugging  
✅ Report bugs  
✅ Understand connection errors  
✅ Feature development  
✅ Forensic analysis of behavior  

---

## 💡 Pro Tips

### Combine with Progress Bar
```powershell
# Normal with progress = Clean UI
python mikrotikapi-bf.py -t 192.168.88.1 -d examples/combos.txt --progress

# Verbose with progress = Best of both worlds
python mikrotikapi-bf.py -t 192.168.88.1 -d examples/combos.txt --progress -v
```

### Save Output to File
```powershell
# Capture everything
python mikrotikapi-bf.py -t 192.168.88.1 -d examples/combos.txt -vv > output.log 2>&1

# View later
type output.log
```

### Filter Output
```powershell
# Only successes
python mikrotikapi-bf.py -t 192.168.88.1 -d examples/combos.txt -v | Select-String "SUCC"

# Only errors
python mikrotikapi-bf.py -t 192.168.88.1 -d examples/combos.txt -vv | Select-String "ERROR|WARN"
```

---

## 📋 Troubleshooting Checklist

If something doesn't work, follow this verbose order:

1. **First**: Execute without verbose
   ```powershell
   python mikrotikapi-bf.py -t TARGET -d examples/combos.txt
   ```
   - See if ports are open
   - See final statistics

2. **If nothing is found**: Add `-v`
   ```powershell
   python mikrotikapi-bf.py -t TARGET -d examples/combos.txt -v
   ```
   - See all attempts
   - Identify failure patterns

3. **If there are errors**: Add `-vv`
   ```powershell
   python mikrotikapi-bf.py -t TARGET -d examples/combos.txt -vv
   ```
   - See technical details
   - Identify root cause

---

## 🔍 Message Examples

### Success
```
[SUCC] [10:30:16] [API] admin:password123
[SUCC] [10:30:16] [REST] admin:password123
[SUCC] [10:30:16] [FTP] admin:password123
```

### Failure
```
[FAIL] [10:30:15] [API] admin:wrongpass
[FAIL] [10:30:15] [REST] admin:wrongpass
```

### Warning
```
[WARN] [10:30:15] [API] Connection error: Connection refused
[WARN] [10:30:15] [REST] HTTP error 401 - Hint: check if 'api' policy is enabled
```

### Debug
```
[DEBB] [10:30:15] Trying -> admin:password
[DEBB] [10:30:15] Testing FTP for admin:password on port 21
[DEBB] [10:30:15] TELNET login success for admin:password
```

### Skip
```
[SKIP] [10:30:15] FTP test skipped due to port check
[SKIP] [10:30:15] REST-API test skipped due to port check
```

---

## 📊 Expected Output with Improvements

### Now you will see this:

```
============================================================
CHECKING TARGET SERVICES
============================================================
Target: 192.168.88.1
Scanning ports...

Port Scan Results:
  API (8728):  ✗ CLOSED/FILTERED ← Alerta de problema!
  HTTP (80): ✗ CLOSED/FILTERED
============================================================

============================================================
ATTACK CONFIGURATION
============================================================
Target         : 192.168.88.1
API Port       : 8728
HTTP Port      : 80
SSL Enabled    : False
Threads        : 2
Delay          : 5s between attempts
Total Attempts : 15
Max Retries    : 1
Export         : JSON, CSV, XML, TXT
============================================================

[INFO] [10:30:15] [*] Starting brute force attack...
[INFO] [10:30:15] [*] Testing 15 credential combinations...

[TEST] [10:30:15] admin:****** ← Shows what's being tested!
[FAIL] [10:30:15] [API] admin:admin
[TEST] [10:30:16] admin:********
[FAIL] [10:30:16] [API] admin:password

============================================================
ATTACK STATISTICS
============================================================
Total Tested    : 15
Successful      : 0
Failed          : 15
Success Rate    : 0.0%
============================================================

## NO CREDENTIALS FOUND ##
============================================================
No valid credentials were discovered.
Total attempts: 15

⚠ Warning: 15 connection errors occurred ← Diagnosis!
Possible causes:
  - Target is unreachable or offline
  - Firewall blocking connections
  - Wrong port number
  - Target is not a Mikrotik device

Troubleshooting:
  1. Verify target is reachable: ping 192.168.88.1
  2. Check if API port is open: telnet 192.168.88.1 8728
  3. Try with verbose mode: -vv
============================================================
```

---

## 🚀 Test Now with the New Verbose

```powershell
# Execute directly with examples
python mikrotikapi-bf.py -t 192.168.88.1 -d examples\combos.txt --export-all -v

# Or use the example scripts
cd examples
.\example_basic.sh
```

You will see **much more information** now! 📊

---

## 📝 Verbose Improvements Summary

| Feature | Before | Now |
|---------|--------|-----|
| **Port Scan** | ❌ Didn't show | ✅ Shows before attacking |
| **Config** | ❌ Didn't show | ✅ Shows complete configuration |
| **First attempts** | ❌ Nothing | ✅ Shows first 3 attempts |
| **Statistics** | ❌ Didn't show | ✅ Shows complete summary |
| **Troubleshooting** | ❌ Nothing | ✅ Resolution tips |
| **Error count** | ❌ Didn't count | ✅ Shows total errors |
| **Progress** | ❌ No feedback | ✅ Shows progress |

---

**Now it's IMPOSSIBLE not to know what's happening!** 🎉

Test the examples in the `examples/` directory to see everything working!




