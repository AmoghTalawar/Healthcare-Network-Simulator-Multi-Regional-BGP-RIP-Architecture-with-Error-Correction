# Healthcare-Network-Simulator-Multi-Regional-BGP-RIP-Architecture-with-Error-Correction

# Multi-Regional Healthcare Network Simulator

[![NS-3 Version](https://img.shields.io/badge/NS--3-3.x-blue.svg)](https://www.nsnam.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![C++](https://img.shields.io/badge/Language-C++-orange.svg)](https://isocpp.org/)
[![Network](https://img.shields.io/badge/Domain-Healthcare-red.svg)](https://github.com)

> **A Dual-Campus Hospital Communication Infrastructure Simulation**  
> BGP-RIP Integrated Routing with Hamming(31,26) Error Correction

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Network Architecture](#network-architecture)
- [Technical Specifications](#technical-specifications)
- [Installation](#installation)
- [Usage](#usage)
- [Applications Simulated](#applications-simulated)
- [Performance Metrics](#performance-metrics)
- [Output Files](#output-files)
- [Results](#results)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## 🎯 Overview

This project simulates a **production-grade inter-hospital network** connecting two healthcare campuses: **Bengaluru (Primary)** and **Mysuru (Secondary)**. The simulation demonstrates enterprise-level networking concepts including multi-AS routing, VLAN segmentation, error correction, and medical application traffic modeling using the **NS-3 network simulator**.

### Business Objectives

- ✅ Enable secure, reliable communication between two hospital campuses
- ✅ Support 15-20% annual traffic growth for 5 years
- ✅ Ensure uninterrupted clinical, administrative, and emergency operations
- ✅ Protect patient data through subnetting, NAT, and routing isolation
- ✅ Provide application-layer error correction for mission-critical data

---

## 🌟 Key Features

### Network Design
- **114 Network Nodes** across 2 autonomous systems
- **14 VLANs** (7 per campus) for logical segmentation
- **Dual Routing Protocols**: BGP for inter-AS, RIPv2 for intra-AS
- **29 Subnets** with hierarchical IP addressing
- **1 Gbps Backbone** with Point-to-Point links

### Advanced Capabilities
- 🔐 **Hamming(31,26) Error Correction** at application layer
- 🌐 **NAT Implementation** (PAT for guests, Static NAT for servers)
- 📊 **Multi-Application Traffic** (SMTP, EHR, PACS, Telemedicine, NMS)
- 🎬 **Real-World Workloads** (1.1 GB video transfer, 200 MB imaging files)
- 📈 **Comprehensive Metrics** (latency, throughput, jitter, packet loss)

### Simulation Features
- ✨ **NetAnim Visualization** with packet metadata
- 📦 **PCAP Packet Captures** for Wireshark analysis
- 📊 **FlowMonitor Statistics** for detailed performance analysis
- 🔄 **RIP Convergence Tracking** across both regions

---

## 🏗️ Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   BENGALURU CAMPUS (AS 100)                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐   ┌──────────┐  │
│  │ VLAN 10  │────│ VLAN 20  │────│ VLAN 30  │───│ VLAN 40  │  │
│  │   ICU    │    │ Radiology│    │  Staff   │   │   ERP    │  │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘   └────┬─────┘  │
│       │               │               │              │         │
│       └───────────────┴───────────────┴──────────────┘         │
│                          │                                      │
│                    ┌─────▼─────┐                               │
│                    │  Core-A   │                               │
│                    │ (BGP/RIP) │                               │
│                    └─────┬─────┘                               │
│  ┌──────────┐    ┌──────▼──────┐    ┌──────────┐             │
│  │ VLAN 50  │────│  VLAN 60    │────│ VLAN 70  │             │
│  │ Servers  │    │ Patient WiFi│    │   Mgmt   │             │
│  └──────────┘    └─────────────┘    └──────────┘             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                    ┌───────▼───────┐
                    │  Inter-AS BGP │
                    │  100.64.0.0/30│
                    └───────┬───────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    MYSURU CAMPUS (AS 200)                       │
│                    ┌─────┬─────┐                               │
│                    │  Core-B   │                               │
│                    │ (BGP/RIP) │                               │
│                    └─────┬─────┘                               │
│       ┌──────────────────┼──────────────────┐                  │
│  ┌────▼─────┐    ┌───────▼────┐    ┌───────▼────┐            │
│  │ VLAN 10  │    │  VLAN 20   │    │  VLAN 30   │            │
│  │   ICU    │    │ Radiology  │    │   Staff    │  + 4 more  │
│  └──────────┘    └────────────┘    └────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```
![Uploading hospital_topology_final_comprehensive.png…]()


### VLAN Structure (Per Campus)

| VLAN ID | Department | Subnet | Hosts | Mask |
|---------|------------|--------|-------|------|
| 10 | ICU | 10.X.10.0 | 6 | /25 |
| 20 | Radiology | 10.X.20.0 | 5 | /24 |
| 30 | Staff-Secure | 10.X.30.0 | 10 | /23 |
| 40 | ERP-Finance | 10.X.40.0 | 3 | /24 |
| 50 | Servers-Core | 10.X.50.0 | 5 | /24 |
| 60 | Patient-WiFi | 10.X.60.0 | 10 | /22 |
| 70 | Management | 10.X.70.0 | 3 | /25 |

*Note: X = 10 for Bengaluru, 20 for Mysuru*

---

## 🔧 Technical Specifications

### Simulation Environment
- **Platform**: NS-3 Network Simulator (v3.x)
- **Language**: C++
- **Routing**: BGP (inter-AS) via DCE + FRRouting, RIPv2 (intra-AS)
- **Transport**: TCP NewReno, UDP
- **Link Technology**: CSMA (LANs), Point-to-Point (Backbone)
- **Visualization**: NetAnim

### Network Parameters
```cpp
Backbone Bandwidth:      1 Gbps
Backbone Delay:          2 ms
VLAN Bandwidth:          1 Gbps
VLAN Propagation Delay:  6560 ns
Queue Discipline:        FIFO + RED
Error Model:             RateErrorModel (BER: 1e-3)
```

### IP Addressing Scheme

**Bengaluru (10.10.0.0/16)**
- VLANs: 10.10.X.0 (where X = VLAN ID)
- Backbone: 192.168.X.0/30
- Loopback: 10.10.200.0/24

**Mysuru (10.20.0.0/16)**
- VLANs: 10.20.X.0 (mirrored structure)
- Backbone: 172.16.X.0/30
- Loopback: 10.20.200.0/24

**Inter-AS Link**
- Peering: 100.64.0.0/30

---

## 📥 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install g++ python3 cmake ninja-build git

# Install NS-3
cd ~
git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

### Clone This Repository

```bash
cd ~/ns-3-dev/scratch
git clone https://github.com/yourusername/healthcare-network-simulator.git hospital-network
cd hospital-network
```

### Required Files
Ensure you have the following in your project directory:
- `hospital-network-phase5b.cc` - Main simulation file
- `paper_7.pdf` - Sample document for SMTP/Hamming transmission
- `Sintel.2010.1080p.mkv` - Video file for streaming simulation (optional)

---

## 🚀 Usage

### Basic Simulation

```bash
# Navigate to NS-3 root
cd ~/ns-3-dev

# Run simulation
./ns3 run "scratch/hospital-network/hospital-network-phase5b"
```

### With Custom Parameters

```bash
# Adjust simulation time (default: 210s)
./ns3 run "scratch/hospital-network/hospital-network-phase5b --SimTime=300"

# Enable verbose logging
./ns3 run "scratch/hospital-network/hospital-network-phase5b --verbose=true"
```

### View Real-Time Animation

```bash
# Generate NetAnim file (automatically created)
# Open with NetAnim
NetAnim hospital-phase5b-mysuru.xml
```

### Analyze Packet Captures

```bash
# View specific application traffic
wireshark app1-smtp-hamming-blr-*.pcap
wireshark app4-sintel-video-blr-*.pcap
wireshark app6-rip-routing-*.pcap
```

---

## 🏥 Applications Simulated

### 1. **SMTP Email System** (Hamming-Encoded)
- **Purpose**: Clinical reports, EHR sync, alerts
- **Protocol**: UDP with custom Hamming(31,26) encoding
- **Traffic**: 1200 packets per region
- **Error Correction**: 18,860 errors corrected (100% success rate)

### 2. **Electronic Health Records (EHR)**
- **Purpose**: Large medical record transfers
- **Protocol**: TCP (Port 443 - HTTPS)
- **File Size**: 50 MB
- **Throughput**: 81.17 Mbps

### 3. **PACS Medical Imaging**
- **Purpose**: CT/MRI scan archival and sharing
- **Protocol**: TCP (Port 104 - DICOM)
- **File Size**: 200 MB
- **Throughput**: 560.03 Mbps

### 4. **Telemedicine Video Streaming**
- **Purpose**: Real-time doctor consultations
- **Protocol**: UDP (Port 9000/9001)
- **Traffic**: Bidirectional cross-region streaming
- **Latency**: < 9 ms average

### 5. **Network Management System (NMS)**
- **Purpose**: Device health monitoring
- **Protocol**: UDP (Port 161 - SNMP-like)
- **Traffic**: Cross-region polling (13 packets)
- **RTT**: < 10 ms

### 6. **Large File Transfer**
- **Purpose**: Radiology archive backup
- **Protocol**: TCP (Port 5001)
- **File Size**: 1.87 GB
- **Cross-Region**: Mysuru → Bengaluru

---

## 📊 Performance Metrics

### Achieved Performance

| Metric | Target | Achieved | Status |
|--------|--------|----------|--------|
| End-to-End Latency | < 10 ms | 7-9 ms | ✅ PASS |
| Packet Loss Rate | < 1% | 0.00% | ✅ PASS |
| Throughput (TCP) | > 50 Mbps | 81-560 Mbps | ✅ PASS |
| RIP Convergence | < 30s | ~20s | ✅ PASS |
| Error Correction | > 95% | 100% | ✅ PASS |
| Cross-Region Hops | ≤ 5 | 4 hops | ✅ PASS |

### Hamming Error Correction Results

```
Total Codewords Processed:    614,400
Codewords with Errors:        18,860
Error Rate:                   3.07%
Errors Corrected:             18,860 (100%)
Uncorrectable Errors:         0
Pre-Correction BER:           1.00e-03
Post-Correction BER:          0.00e+00
```

### Application Throughput Summary

```
SMTP (Hamming):    0.84 Mbps  (Low overhead, error-corrected)
EHR Transfer:      81.17 Mbps (50 MB in 5.69s)
PACS Imaging:      560.03 Mbps (200 MB in 3.30s)
Sintel Video:      82.29 Mbps (1.1 GB in 32s)
Cross-Region File: 64.02 Mbps (1.87 GB in 42s)
NMS Monitoring:    0.00 Mbps  (Lightweight telemetry)
```

---

## 📁 Output Files

The simulation generates the following files:

### Visualization
- `hospital-phase5b-mysuru.xml` - NetAnim animation file

### Packet Captures (PCAP)
- `app1-smtp-hamming-blr-*.pcap` - SMTP traffic with Hamming encoding
- `app2-ehr-transfer-blr-*.pcap` - EHR 50 MB transfer
- `app3-pacs-imaging-blr-*.pcap` - PACS 200 MB imaging
- `app4-sintel-video-blr-*.pcap` - 1.1 GB video streaming
- `app5-nms-monitoring-*.pcap` - NMS cross-region polling
- `app5-cross-region-nms-*.pcap` - Inter-AS monitoring traffic
- `app6-rip-routing-*.pcap` - RIPv2 routing updates

### Analysis Reports
- `hospital_flows.xml` - FlowMonitor statistics (XML format)
- Console output with detailed metrics and routing tables

---

## 📈 Results

### Network Layer
- ✅ Full BGP-RIP convergence across 2 autonomous systems
- ✅ All 29 subnets mutually reachable
- ✅ Maximum 4 router hops for cross-regional traffic
- ✅ No routing loops detected

### Transport Layer
- ✅ TCP reliability: 0% packet loss on all flows
- ✅ UDP performance: Consistent low-latency delivery
- ✅ Congestion control: TCP NewReno active and effective

### Application Layer
- ✅ Multi-region error correction operational (100% success)
- ✅ All medical applications meeting QoS requirements
- ✅ Real-time video streaming with < 9 ms latency
- ✅ Large file transfers completing successfully

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. Create a **feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. Open a **Pull Request**

### Code Standards
- Follow NS-3 coding conventions
- Add comments for complex logic
- Update documentation for new features
- Include test scenarios for major changes

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📧 Contact

**Project Maintainer**: Your Name  
**Email**: princeamogh7@gmail.com 
**LinkedIn**: [Amogh ](www.linkedin.com/in/amogh-talawar-769865319)  
**GitHub**: [@AmoghTalawar](https://github.com/AmoghTalawar)

---

## 🙏 Acknowledgments

- **NS-3 Community** - For the excellent network simulation framework
- **FRRouting Project** - For BGP implementation via DCE
- **Healthcare IT Standards** - HL7, DICOM, IHE guidelines
- **Open Source Contributors** - For tools and libraries used

---

## 📚 References

1. NS-3 Documentation: https://www.nsnam.org/documentation/
2. FRRouting: https://frrouting.org/
3. Hamming Code Theory: Error Detection and Correction
4. Healthcare Network Security Standards: HIPAA, HITECH Act
5. BGP/RIP Routing Protocols: RFC 4271, RFC 2453

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star! ⭐**

Made with ❤️ for Healthcare Network Research

</div>
