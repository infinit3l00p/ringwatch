# MITRE ATT&CK Surface Mapping: Ring -3 (Intel ME/CSME) Attack Techniques

## Document Classification: Academic Research — TLP:WHITE

**Date:** August 4, 2026  
**Author:** Dan Vladoiu — RingWatch Research Division  
**Scope:** Mapping known Ring -3 (Intel Management Engine / Converged Security and Management Engine) attack techniques to the MITRE ATT&CK for Enterprise framework, including tactic IDs, technique IDs, sub-technique IDs, and known threat actor usage.

---

## 1. Executive Summary

Intel's Management Engine (ME/CSME) operates at Ring -3 — a privilege level below the operating system kernel (Ring 0), below the hypervisor (Ring -1), and below the SMM (Ring -2). It is a separate processor (the "ME coprocessor") embedded in the Platform Controller Hub (PCH) with its own firmware, its own OS (MINIX-based until ME 11, then a proprietary RTOS), its own memory, and direct access to system hardware via the Direct Media Interface (DMI) and the Network Controller Sideband Interface (NC-SI).

This document maps all known Ring -3 attack vectors to the MITRE ATT&CK for Enterprise framework. MITRE ATT&CK does not currently have Ring -3-specific technique IDs, but Ring -3 attacks map to existing techniques in the **Persistence**, **Privilege Escalation**, **Defense Evasion**, and **Credential Access** tactics, particularly under:

- **T1542 — Pre-OS Boot** (System Firmware, Component Firmware, Bootkit)
- **T1693 — Modify Firmware** (ICS)
- **T1068 — Exploitation for Privilege Escalation**
- **T1555 — Credentials from Password Stores** (via ME access to OS telemetry)

---

## 2. MITRE ATT&CK Technique Mapping

### 2.1 T1542.001 — Pre-OS Boot: System Firmware

**Description:** Adversaries may modify system firmware to persist on systems. The BIOS/UEFI operates as the software interface between the OS and hardware.

**Ring -3 Relevance:** The Intel ME can modify system firmware (BIOS/UEFI) without OS knowledge. The ME has direct read/write access to the SPI flash via the SPI Proxy MEI client (UUID: 309dcde8-ccb1-4062-8f78-600115a34327). A compromised ME can:
- Patch UEFI bootloaders to inject malicious code before the OS loads
- Modify BIOS settings to disable Secure Boot
- Inject Option ROM malware during PCIe enumeration
- Alter the Boot Guard configuration (if ME is compromised before Boot Guard verification)

**Known CVEs enabling this path:**
- CVE-2017-5705: Buffer overflow in ME kernel (ME 11.0–11.7) — enables arbitrary code execution in ME, which can then write to SPI flash
- CVE-2018-3659: CSME Delayed Authentication Mode (DAM) — allows bypassing Boot Guard on some platforms
- CVE-2020-8705: ME privilege escalation via Red Unlock (SA-00241)
- CVE-2023-40067: Unchecked return value in CSME firmware — privilege escalation via physical access

**Threat Actors:** APT28 (Fancy Bear) — LoJax UEFI rootkit (ESET, 2018) demonstrated that ME-accessible SPI flash can be rewritten to persist UEFI implants. While LoJax used OS-level SPI flash writes, the same attack path is trivially achievable from Ring -3.

### 2.2 T1542.002 — Pre-OS Boot: Component Firmware

**Description:** Adversaries may modify component firmware to persist on systems. This includes firmware on network cards, graphics cards, storage controllers, and — critically — the Management Engine itself.

**Ring -3 Relevance:** This is the *defining* technique for Ring -3 attacks. The ME firmware itself IS component firmware:
- ME firmware resides in a dedicated 8.4 MB region of the SPI flash (0x00004000 – 0x0086A000)
- ME firmware updates (NFTP protocol, MEI client dd17041c-09ea-4b17-a271-5b989867ec65) can be triggered from the OS but execute within the ME
- A compromised ME firmware update persists across OS reinstalls, hard drive replacements, and even BIOS reflashes (if the ME region is not wiped)
- ME firmware modification is the *deepest* persistence mechanism available on Intel platforms

**Known Attack Vectors:**
- **Intel-SA-00086 (CVE-2017-5705, CVE-2017-5712):** Positive Technologies (Goryachy & Ermolov) discovered a buffer overflow in the ME 11.x kernel that allows arbitrary code execution via a crafted MEI message. This enables full ME compromise from the OS level without physical access. PoC code released (IntelTXE-PoC, 545 GitHub stars). Presented at Black Hat USA 2017 and 34C3 (Chaos Communication Congress, Hamburg, December 2017).
- **Intel-SA-00213 (CVE-2019-0090):** CSME IOMMU hardware issue. Enables an attacker to bypass the ME's own IOMMU protection, gaining DMA access to host memory from the ME. Intel white paper published June 2020.
- **Intel-SA-00241 (CVE-2020-8705):** Red Unlock mechanism allows enabling Intel ME debugging features via a physical resistor on the PCH, giving JTAG access to the ME core. Positive Technologies.
- **Intel Boot Guard bypass (CVE-2019-11098):** Peter Bosch (@peterbjornx) demonstrated a TOCTOU (Time-of-Check-Time-of-Use) vulnerability in Boot Guard verification. Presented at multiple conferences. PoC exploit generator released (me_sa86_exploit, 33 GitHub stars).
- **Intel x86 Root of Trust: loss of trust (2020):** Positive Technologies discovered a vulnerability in the ROM (not firmware) of the Intel CSME — the boot ROM that verifies the ME firmware itself. This is *unfixable* by firmware updates because it's in masked ROM (burned into silicon). Reported as "utter chaos for DRM, file encryption" (The Register, March 2020).

**Threat Actors:** Conti ransomware — leaked communications (February 2022) revealed active interest in firmware-level persistence, including ME exploitation. Eclypsium analysis confirmed Conti's firmware attack capabilities.

### 2.3 T1542.003 — Pre-OS Boot: Bootkit

**Description:** Adversaries may use bootkits to persist on systems. Bootkits operate at a level below the OS kernel.

**Ring -3 Relevance:** A Ring -3 bootkit would be ME firmware that modifies the boot process. The ME has the capability to:
- Intercept the BIOS boot flow via the ME-BIOS sync mechanism (HMRFPO MEI client, UUID: 6861ec7b-d07a-4673-856c-7f22b4d55769)
- Modify the Option ROM loading sequence
- Inject code into the UEFI Secure Boot chain via the BIOS Integration MEI client (UUID: 42b3ce2f-bd9f-485a-96ae-26406230b1ff)
- Alter power/thermal/boot state via the Extended Boot MEI client (UUID: 082ee5a7-7c25-470a-9643-0c06f0466ea1)

**Academic/Conference Research:**
- **LONGKIT (2017):** Rauchberger, Luh, & Schrittwieser presented "LONGKIT — A Universal Framework for BIOS/UEFI Rootkits in System Management Mode" at SICHERHEIT 2017. Demonstrated SMM-based persistence that survives OS reinstalls. The ME can inject SMM handlers, making this a Ring -3 → Ring -2 persistence chain.
- **Helltrap (2026):** "Transforming physical machines into UEFI rootkit traps" — presented at EuroS&P 2026. Demonstrated a defensive approach: deliberately installing UEFI rootkit traps to catch attackers. Relevant because the ME could serve as an out-of-band trap deployment mechanism.
- **Peacock (2026):** "UEFI Firmware Runtime Observability Layer for Detection and Response" (arXiv:2601.07402) — Cochavi Gorelik et al. proposed a runtime UEFI monitoring layer. The ME is the ideal host for such monitoring because it operates independently of the OS.

### 2.4 T1693 — Modify Firmware (ICS)

**Description:** Adversaries may modify the firmware of devices to compromise device behavior. While this technique is categorized under ICS ATT&CK, the concept applies directly to Ring -3.

**Ring -3 Relevance:** The ME firmware itself can be modified through:
- **NFTP firmware update protocol** (MEI client dd17041c-09ea-4b17-a271-5b989867ec65) — legitimate firmware updates can be intercepted and replaced with malicious builds
- **SPI flash direct write** — if the ME's SPI flash write protection is disabled (via HMRFPO), the ME region can be directly overwritten
- **ME firmware image injection** — using the `me_cleaner` tool (4,973 GitHub stars), the ME firmware image can be deblobbed and modified, though this is primarily a defensive/neutralization tool

### 2.5 T1068 — Exploitation for Privilege Escalation

**Description:** Adversaries may exploit software vulnerabilities to escalate privileges.

**Ring -3 Relevance:** Multiple CVEs allow escalation from OS-level (Ring 3/Ring 0) to ME-level (Ring -3):
- CVE-2017-5705: ME 11.x kernel buffer overflow → arbitrary ME code execution
- CVE-2018-3659: CSME DAM vulnerability → Boot Guard bypass
- CVE-2020-8705: Red Unlock → ME JTAG access
- CVE-2023-40067: CSME unchecked return value → privilege escalation via physical access
- CVE-2025-20037: Intel CSME privilege escalation (2025)
- CVE-2025-27708: Out-of-bounds read in CSME firmware (2026)

### 2.6 T1555 — Credentials from Password Stores

**Ring -3 Relevance:** The ME has direct access to OS-level telemetry via the MKHIF_FIX MEI client (UUID: 55213584-9a29-4916-badf-0fb7ed682aeb), which feeds OS version and state information to the ME. A compromised ME can:
- Intercept OS telemetry data including user session information
- Access PTT (Platform Trust Technology) / fTPM data (MEI client UUID: 8e6a6715-9abc-4043-88ef-9e39c6f63e0f) — if ME is compromised, the fTPM is compromised, exposing disk encryption keys (LUKS, BitLocker)
- Read host memory via DMA (if ME IOMMU is bypassed — CVE-2019-0090)
- Intercept network traffic via NC-SI (the ME has its own network path independent of the OS network stack)

---

## 3. Attack Chain Analysis

### 3.1 The Ring -3 Kill Chain

```
Initial Access → ME Exploitation → Persistence → Collection → Exfiltration
     |                |                  |              |              |
  Physical       CVE-2017-5705     ME firmware     DMA read      NC-SI
  access         CVE-2019-0090     modification    host memory   network
  OR             CVE-2020-8705    (survives OS     (passwords,   (bypasses
  OS-level       CVE-2023-40067    reinstall)       keys)         host
  (Ring 0)                                           PTT/fTPM     firewall)
```

### 3.2 Escalation Path: OS → ME → Permanent Persistence

1. **Initial compromise:** Attacker gains Ring 0 (kernel) access via standard exploit
2. **ME exploitation:** Sends crafted MEI message to /dev/mei0 exploiting CVE-2017-5705
3. **ME code execution:** Attacker now runs arbitrary code inside the ME coprocessor
4. **SPI flash write:** Uses ME's SPI Proxy to write malicious ME firmware to SPI flash
5. **Permanent persistence:** Malicious ME firmware survives:
   - OS reinstalls
   - Hard drive replacements
   - BIOS/UEFI reflashes (unless ME region is specifically wiped)
   - Secure Boot resets
6. **Data collection:** Compromised ME reads host memory via DMA, intercepts PTT/fTPM keys
7. **Exfiltration:** Data sent out via NC-SI (ME's own network path, invisible to OS)

### 3.3 Escalation Path: Physical → ME → Full Compromise

1. **Physical access:** Attacker opens chassis
2. **JTAG enable:** Uses USB 3.0 debug port or Red Unlock resistor (CVE-2020-8705)
3. **ME JTAG access:** Full debugging access to ME core
4. **ME firmware dump:** Reads entire ME firmware via JTAG
5. **ME firmware patch:** Writes modified ME firmware via SPI programmer
6. **Permanent persistence + collection + exfiltration:** Same as above

---

## 4. Defensive Tooling & Detection

### 4.1 MITRE ATT&CK Detection Strategy DET0167

**Firmware Modification via Flash Tool or Corrupted Firmware Upload** — MITRE defines this detection strategy for identifying unauthorized firmware modifications. RingWatch implements this by:
- Monitoring HECI bus activity (MEI client connections)
- Tracking SPI flash write attempts via the ME
- Detecting anomalous ME firmware update requests (NFTP protocol)

### 4.2 Eclypsium Firmware ATT&CK Mapping

Eclypsium published "Firmware and Frameworks" (2024), mapping firmware attacks to MITRE ATT&CK. Key mappings relevant to Ring -3:

| ATT&CK Technique | Firmware Application | RingWatch Detection |
|---|---|---|
| T1542.001 (System Firmware) | ME can modify UEFI/BIOS | SPI flash write monitoring via MEI |
| T1542.002 (Component Firmware) | ME firmware itself is a target | ME firmware version + hash monitoring |
| T1542.003 (Bootkit) | ME can inject boot code | Boot state monitoring via HMRFPO + BIOS_INTEG clients |
| T1490 (Inhibit System Recovery) | ME can prevent firmware recovery | Recovery mode detection via EXT_BOOT client |

### 4.3 BootKeeper — Firmware Integrity Validation

**Citation:** Chevalier et al., "BootKeeper: Validating Software Integrity Properties on Boot Firmware Images," arXiv:1903.12505, 2019.

BootKeeper validates software integrity properties on boot firmware images by analyzing control flow and data flow properties. RingWatch adopts a similar approach for ME firmware:
- ME firmware version monitoring (sysfs `/sys/class/mei/mei0/fw_ver`)
- ME firmware status register decoding (fw_status 0-1)
- MEI client enumeration and state monitoring
- HECI bus activity tracking

### 4.4 Peacock — UEFI Runtime Observability

**Citation:** Cochavi Gorelik et al., "Peacock: UEFI Firmware Runtime Observability Layer for Detection and Response," arXiv:2601.07402, January 2026.

Peacock proposes a runtime UEFI firmware observability layer. The ME is the ideal execution environment for such a layer because:
- It operates independently of the OS
- It has direct hardware access via DMI
- It cannot be compromised by OS-level malware (unless ME itself is exploited)
- It can monitor UEFI runtime services via the BIOS Integration MEI client

RingWatch's HECI Spy module implements a lightweight version of this concept — probing ME state from the OS side. A future evolution would move the monitoring logic into the ME itself (if ME firmware modification is possible via legitimate Intel tools).

---

## 5. Known Exploitation Tools & PoCs

### 5.1 Offensive Tools

| Tool | Author | Stars | Description | Conference |
|---|---|---|---|---|
| IntelTXE-PoC | Positive Technologies (Goryachy & Ermolov) | 545 | JTAG activator for ME core via SA-00086 | Black Hat USA 2017, 34C3 |
| me_sa86_exploit | Peter Bosch (@peterbjornx) | 33 | Exploit generator for ME 11 buffer overflow | Multiple conferences |
| intel-me-research | Jatinkapilaq1 | 10 | Zero-dependency HECI spy tool — direct ME communication | — |
| me_cleaner | Nicola Corna | 4,973 | Partial deblobbing of Intel ME/TXE firmware | — |
| me_cleaner_thinkpad | MangoKiwiPlumGrape | 13 | HAP bit fixes for 8th–14th gen Intel (ME 12–18) | — |
| Barzakh | yasindce1998 | 4 | Ring -4 to Ring 0 offense-defense firmware research platform | — |

### 5.2 Defensive Tools

| Tool | Author | Description |
|---|---|---|
| RingWatch | Dan Vladoiu | Real-time Ring -3 monitor — HECI bus, MEI clients, SPI flash, NC-SI |
| me_cleaner | Nicola Corna | ME neutralization (HAP bit, module removal) — defensive use |
| Intel CSME Detection Tools | Intel | Official CSME vulnerability detection tool |
| CHIPSEC | CHIPSEC project | Low-level firmware/hardware security testing framework |

---

## 6. Threat Actor Activity

### 6.1 APT28 (Fancy Bear / Sednit)

- **LoJax UEFI rootkit** (ESET, September 2018) — first UEFI rootkit found in the wild
- targeted government organizations in the Balkans and Central Asia
- Used RWEverything to write to SPI flash from OS level
- MITRE ATT&CK: S0397 (LoJax), T1542.001, T1542.002
- While LoJax used OS-level SPI writes, the same attack from Ring -3 would be undetectable by OS-level tools

### 6.2 Conti Ransomware

- Leaked communications (February 2022) revealed active firmware attack capability research
- Eclypsium analysis confirmed Conti had tools for SPI flash access and UEFI persistence
- Interest in ME exploitation for persistent access across reinstalls

### 6.3 TrickBot / TrickBoot

- Eclypsium + AdvIntel research (2020): TrickBot gained TrickBoot functionality
- Checks UEFI/BIOS firmware of targeted systems
- Can identify writable SPI flash — precursor to Ring -3 attacks

---

## 7. Conference Presentations — Complete Catalog

### 7.1 Black Hat

| Year | Conference | Talk | Authors | Relevance |
|---|---|---|---|---|
| 2017 | Black Hat USA | "Intel AMT Stealth Breakthrough" | Evdokimov, Ermolov, Malyutin (Embedi) | AMT vulnerability post-CVE-2017-5689, new exploitation vectors |
| 2017 | Black Hat USA | (SA-00086 disclosure) | Goryachy & Ermolov (Positive Technologies) | ME JTAG activation via USB — full system compromise |
| 2018 | DEF CON 26 | "The Ring 0 Facade" | Christopher Domas (@xoreaxeaxeax) | Processor microcode exploitation — Ring 0 → below Ring 0 |
| 2019 | Black Hat USA | "Behind the Scenes of Intel Security and Manageability Engine" | Shai Hasarfaty & Yanai Moyal (Intel Corp) | Intel's own ME security architecture presentation |

### 7.2 Chaos Communication Congress (CCC)

| Year | Conference | Talk | Authors | Relevance |
|---|---|---|---|---|
| 2013 | 30C3 | "Persistent, Stealthy, Remote-controlled Dedicated Hardware Malware" | Various | Hardware-based malware persistence — foundational Ring -3 concept |
| 2017 | 34C3 | "Inside Intel Management Engine" | Goryachy & Ermolov (Positive Technologies) | Deep dive into SA-00086 exploitation, ME firmware internals |

### 7.3 Other Conferences

| Year | Conference | Talk | Authors | Relevance |
|---|---|---|---|---|
| 2017 | GSEC/HITB | "Intel AMT" (Part 2) | Evdokimov et al. (Embedi) | Updated AMT exploitation research |
| 2017 | SICHERHEIT | "LONGKIT — Universal BIOS/UEFI Rootkit Framework" | Rauchberger, Luh, Schrittwieser | SMM-based persistence framework |
| 2026 | EuroS&P | "Helltrap: UEFI Rootkit Traps" | Various | Defensive firmware trap deployment |

---

## 8. Academic Papers — Complete Bibliography

### 8.1 Directly Cited

1. **Chevalier et al.**, "BootKeeper: Validating Software Integrity Properties on Boot Firmware Images," arXiv:1903.12505, 2019.
2. **Cochavi Gorelik et al.**, "Peacock: UEFI Firmware Runtime Observability Layer for Detection and Response," arXiv:2601.07402, January 2026.
3. **Rauchberger et al.**, "LONGKIT — A Universal Framework for BIOS/UEFI Rootkits in System Management Mode," SICHERHEIT 2017, scitepress.org/papers/2017/61656/61656.pdf.
4. **Markettos et al.**, "Thunderclap: Exploring Vulnerabilities in Operating System IOMMU Protection via DMA from Untrustworthy Peripherals," NDSS 2019. — IOMMU bypass for DMA attacks.
5. **Wang et al.**, "DmaAuth: A Lightweight Pointer Integrity-based Secure Architecture to Defeat DMA Attacks," USENIX Security 2024. — DMA attack defense via pointer integrity.
6. **Chevalier et al.**, "Co-processor-based Behavior Monitoring," arXiv:1803.02700, 2017. — HP researchers proposed using the ME coprocessor for behavior monitoring.
7. **Zhang et al.**, "A Framework to Secure Peripherals at Runtime," LNCS 8712. — Runtime peripheral security framework.

### 8.2 Intel Official Documentation

8. **Intel**, "Using IOMMU for DMA Protection in UEFI Firmware," Intel White Paper, 2020. — Official IOMMU-based DMA defense guide.
9. **Intel**, "The Intel CSME IOMMU Hardware Issue — CVE-2019-0090 and CVE-2020-0566," Intel White Paper, June 2020.
10. **Intel**, "The Intel CSME Delayed Authentication Mode (DAM) Vulnerability — CVE-2018-3659 and CVE-2018-3643," Intel White Paper, June 2020.
11. **Intel SA-00086**: ME 6.x–11.x, SPS 4.0, TXE 1.0–3.0 vulnerability advisory.
12. **Intel SA-00141**: AMT 9.x–12.x vulnerability advisory.
13. **Intel SA-00213**: CVE-2019-0090 advisory.
14. **Intel SA-00241**: CVE-2020-8705 advisory.
15. **Intel SA-01280**: 2025.3 IPU chipset firmware advisory.

### 8.3 Standards & Guidelines

16. **NIST SP 800-147**: Cooper, Polk, Regenscheid, Souppaya, "BIOS Protection Guidelines," NIST Special Publication 800-147.
17. **NSA**, "BlackLotus Mitigation Guide," NSA Cybersecurity Information, June 2023.
18. **Eclypsium**, "Firmware and Frameworks — Mapping Firmware Attacks to MITRE ATT&CK," 2024.

### 8.4 Industry Research Reports

19. **ESET**, "LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group," WeLiveSecurity, September 2018.
20. **Kaspersky**, "MoonBounce: the dark side of UEFI firmware," Securelist, 2022.
21. **Microsoft**, "Guidance for investigating attacks using CVE-2022-21894: The BlackLotus campaign," Microsoft Security Blog, April 2023.
22. **Eclypsium/AdvIntel**, "TrickBot Now Offers TrickBoot: Persist, Brick, Profit," 2020.
23. **Eclypsium**, "Conti Opens a New Front in the Fight for Firmware," 2022.
24. **Positive Technologies**, "Intel x86 Root of Trust: loss of trust," Positive Research Center, March 2020.
25. **Positive Technologies**, "Where there's a JTAG, there's a way: obtaining full system access via USB," October 2017.

---

## 9. Gap Analysis — What MITRE ATT&CK Is Missing

### 9.1 No Ring -3 Technique IDs

MITRE ATT&CK for Enterprise does not have explicit Ring -3 (Management Engine) technique IDs. The closest mappings are:
- T1542.001/002/003 (Pre-OS Boot) — covers firmware but not the ME specifically
- T1693 (Modify Firmware) — ICS-specific, not Enterprise
- T1068 (Exploitation for Privilege Escalation) — generic, not firmware-specific

**Recommendation:** MITRE should add:
- **T1542.005 — Pre-OS Boot: Management Engine Firmware** — specifically for ME/CSME firmware modification
- **T1499.006 — Endpoint Denial of Service: Firmware Bricking** — for ME-induced system bricking

### 9.2 No Detection Strategy for Ring -3

MITRE DET0167 (Firmware Modification via Flash Tool) is the closest detection strategy, but it focuses on OS-level flash tools. There is no detection strategy for:
- HECI bus abuse (crafted MEI messages)
- ME firmware integrity validation
- ME IOMMU bypass detection
- NC-SI network exfiltration detection

### 9.3 No Mitigation Guidance for Ring -3

MITRE ATT&CK mitigations for T1542 focus on:
- Secure Boot (does not protect against ME compromise)
- BIOS password protection (irrelevant to ME)
- Firmware write protection (can be bypassed from ME)

**Missing mitigations:**
- me_cleaner / HAP bit (ME neutralization)
- IOMMU strict mode (DMA protection)
- NC-SI network isolation (USB WiFi adapter instead of internal)
- HECI bus monitoring (RingWatch's core function)
- Boot Guard verification (only effective if ME is not already compromised)

---

## 10. Conclusion

Ring -3 attacks represent a critical blind spot in the MITRE ATT&CK framework. While existing techniques (T1542.x, T1068) can be retrofitted to describe Ring -3 attacks, they fail to capture the unique characteristics of Management Engine exploitation:

1. **Persistence depth:** ME firmware survives all OS-level remediation
2. **Stealth:** ME operates independently of the OS — invisible to EDR, antivirus, and host firewalls
3. **Network independence:** ME has its own NC-SI network path, bypassing host network monitoring
4. **Cryptography compromise:** ME controls PTT/fTPM — compromising ME compromises disk encryption
5. **Unfixable vulnerabilities:** Boot ROM flaws (CVE-2019-0090 class) cannot be patched via firmware updates

RingWatch addresses this gap by providing the first open-source, real-time Ring -3 monitoring system that maps observed ME behavior to MITRE ATT&CK techniques, enabling defenders to detect and respond to Ring -3 attacks that traditional security tools cannot see.

---

*Document Version 1.0 — August 4, 2026*
*RingWatch Research Division — Dan Vladoiu*