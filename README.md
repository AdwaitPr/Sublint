# Sublint — LAN Exposure Scanner

[![Android CI](https://github.com/AdwaitPr/Sublint/actions/workflows/android-ci.yml/badge.svg)](https://github.com/AdwaitPr/Sublint/actions/workflows/android-ci.yml)
[![Version](https://img.shields.io/badge/version-v0.1.0-blue.svg)](https://github.com/AdwaitPr/Sublint/releases/tag/v0.1.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Sublint** is a lightweight pocket LAN scanner designed for home offices and small studios. When connecting new devices—such as cheap Wi-Fi routers, IP cameras, or network printers—Sublint audits the local network using standard user-space sockets, discovers active hosts, evaluates exposure risks on a curated set of critical ports, and presents actionable remediation in plain language.

---

## Key Features & Guardrails

- **Zero Root & Zero Cost:** Operates entirely in user-space using standard sockets (`java.net.Socket`). Zero root or superuser privilege required.
- **Strict RFC1918 Private Subnet Scoping:** Only permits scanning private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Public IPs, loopback (`127.0.0.0/8`), and carrier CGNAT (`100.64.0.0/10`) are strictly blocked.
- **Automatic Subnet Clamping:** If the local network has a wide prefix (e.g. `/16` or `/22`), Sublint clamps scanning strictly to the local `/24` block containing the device's IP (maximum 254 hosts) to prevent file descriptor exhaustion (`EMFILE`) and battery drain.
- **Mandatory Authorization Gate:** Hard-blocks scans until the user explicitly toggles the confirmation switch: *"I own or am explicitly authorized to audit this local network."*
- **Ethical & Passive:** Zero brute-force login attempts and zero credential guessing. Banner classification is passive (reads initial greetings, HTTP `HEAD`/`GET` headers, and HTML titles; non-intrusive TCP connect check on MQTT/SMB/RDP).
- **Transport Guards:** Requires an active Wi-Fi connection. Explicitly blocks scanning over VPN tunnels (`TRANSPORT_VPN`) to protect remote corporate subnets, and blocks mobile carrier networks (`TRANSPORT_CELLULAR`).
- **Privacy First:** Requires only `android.permission.INTERNET` and `android.permission.ACCESS_NETWORK_STATE`. Ommits `ACCESS_FINE_LOCATION` and `ACCESS_COARSE_LOCATION` entirely.

---

## Scan Architecture (Two-Phase Sweep)

Sublint employs an optimized two-phase scan pipeline that completes a full `/24` subnet audit in under 8 seconds:

```
[ Phase 1: Host Discovery Sweep ]
  ├── Concurrency: Bounded via Semaphore(25)
  ├── Probes: Port 80 discovery connect (400ms timeout)
  └── Alive Signal: Both SYN-ACK (Open) AND immediate TCP RST (Connection Refused)
                    confirm that the host's OS network stack is active on the LAN.
           │
           ▼
[ Phase 2: Curated 12-Port Audit on Live Hosts Only ]
  ├── Ports Probed: 21, 22, 23, 80, 445, 554, 1883, 3389, 5000, 8080, 8443, 9100
  ├── Passive Banner Reads: Sanitized & capped at 2,048 bytes (control characters stripped)
  └── Classification: Plain-language risk advisories mapped to severity levels
```

### Top 12 Curated Ports & Classification Rules

| Port | Service | Probe Behavior | Risk Severity | Plain Language Advisory |
| :--- | :--- | :--- | :--- | :--- |
| **21** | FTP | Read 220 banner line | **MEDIUM** | Unencrypted FTP server active. Credentials and files sent in cleartext across the network. |
| **22** | SSH | Read protocol version | **INFO** | SSH remote shell exposed. Ensure non-default credentials and key-based auth are enforced. |
| **23** | Telnet | Read initial IAC prompt | **HIGH** | Legacy cleartext Telnet active. High risk of default passwords and sniffing. Recommend disabling. |
| **80** | HTTP | Read `HEAD`/`GET` & `<title>` | **MEDIUM** | Unencrypted HTTP web management console exposed without TLS. Verify strong admin credentials. |
| **445** | SMB | TCP connect check | **MEDIUM** | Exposed Windows/Samba file sharing service reachable by anyone on the local network. |
| **554** | RTSP | Send `OPTIONS rtsp://` | **HIGH** | Exposed RTSP IP camera video stream. Video stream endpoint may be unauthenticated on local network. |
| **1883**| MQTT | TCP connect check (non-intrusive) | **HIGH** | Exposed MQTT smart home broker. Telemetry and controls may accept unauthenticated connections. |
| **3389**| RDP | TCP connect check | **MEDIUM** | Exposed Windows Remote Desktop (RDP) service. Ensure Network Level Authentication (NLA) is enabled. |
| **5000**| NAS | Read HTTP `<title>` | **MEDIUM** | Exposed NAS or storage management dashboard on port 5000. |
| **8080**| HTTP-Alt | Read HTTP `<title>` | **MEDIUM** | Alternative web management portal detected (router, camera, or proxy). |
| **8443**| HTTPS-Alt | Read peer X.509 Subject DN | **INFO** | Encrypted administrative portal active. |
| **9100**| JetDirect | TCP connect check | **MEDIUM** | Exposed RAW network printer port. Unauthenticated print jobs can be submitted by local hosts. |

---

## Codebase Architecture

```
app/src/main/java/
├── com.sublint.core/             # Pure Kotlin Engine (Zero android.* imports — iOS portable)
│   ├── model/
│   │   ├── Ipv4Address.kt        # RFC1918 validation, CIDR math, /24 host enumeration
│   │   └── SubnetModels.kt       # CuratedPort, ScanFinding, HostScanResult, RiskSeverity
│   ├── network/
│   │   ├── ISocketProber.kt      # ProbeResult (Open, ClosedByReset, TimedOutOrUnreachable)
│   │   └── JavaSocketProber.kt   # Standard socket transport with tcpNoDelay, soLinger(0)
│   ├── classifier/
│   │   └── BannerClassifier.kt   # Banner sanitizer (capped at 2k) & title/header rule engine
│   ├── scanner/
│   │   └── SubnetHostEnumerator.kt # Subnet clamping (/16->/24), self-IP exclusion
│   └── coordinator/
│       └── LanScanCoordinator.kt # Two-phase bounded scan engine (Semaphore concurrency)
├── com.sublint.android/          # Android Platform Adapter
│   └── AndroidWifiNetworkResolver.kt # ConnectivityManager & LinkProperties resolver (VPN/Cellular guards)
├── com.sublint.ui/               # Presentation Layer
│   ├── SublintViewModel.kt       # Context-free ViewModel (100% JVM unit testable)
│   └── ScanScreen.kt             # Jetpack Compose Material 3 single-screen UI
└── com.adwait.sublint/           # Application Host
    └── MainActivity.kt           # Foreground lifecycle integration (FLAG_KEEP_SCREEN_ON)
```

---

## Building & Verifying Locally

### Prerequisites
- JDK 11, 17, or 21 (Gradle JBR)
- Android SDK API 37 (Min SDK 26)

### Run Offline Unit Test Suite
```bash
./gradlew testDebugUnitTest
```
Runs all 33 offline unit tests covering RFC1918 math, /16 clamping, banner fuzzing (0% crash guarantee), mock two-phase coordinator, socket prober, and ViewModel state flows.

### Build Debug APK
```bash
./gradlew assembleDebug
```
Generates debug APK at `app/build/outputs/apk/debug/app-debug.apk`.

---

## License

This project is licensed under the MIT License.
