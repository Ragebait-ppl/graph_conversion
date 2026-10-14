# Graph Conversion & Host Forensics Telemetry Engine

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-0078D6?logo=windows)](https://microsoft.com)
[![Language](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg?logo=c%2B%2B)](https://isocpp.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg?logo=python)](https://python.org)
[![Graph](https://img.shields.io/badge/Topology-Homogeneous%20Graph-orange.svg)](https://networkx.org)
[![ML Ready](https://img.shields.io/badge/ML-PyTorch%20Geometric%20Ready-EE4C2C.svg?logo=pytorch)](https://pytorch-geometric.readthedocs.io)

An end-to-end framework for capturing low-level Windows host execution states, structuring system events into tabular telemetry datasets, and converting multi-entity forensics into **clean, feature-rich homogeneous graphs** formatted for Graph Neural Networks (GNNs).

---

## 📌 Architecture & Workflow

```text
+---------------------+     +--------------------------+     +--------------------------+
|  Live System State  | --> | C++20 Telemetry Engine   | --> | Raw Snapshot             |
|  Processes, Memory, |     | (Native Win32 APIs)      |     | (telemetry.json)         |
|  Sockets, Threads   |     |                          |     |                          |
+---------------------+     +--------------------------+     +--------------------------+
                                                                          |
                                                                          v
+--------------------------+     +--------------------------+     +--------------------------+
| GNN-Ready Artifacts      | <-- | Homogeneous Graph        | <-- | Tabular Datasets (CSVs)  |
| - PyG Data Tensor (.pt)  |     | Conversion Engine        |     | - nodes.csv              |
| - 0-indexed Node Tensor  |     | (Proper Labeling, Index, |     | - weighted_edges.csv     |
| - Spaced Interactive View|     | Elastic Repulsion Layout)|     |                          |
+--------------------------+     +--------------------------+     +--------------------------+
```

1. **Host Telemetry Collection (Phase 1)**: Captures running processes, process parentage (PPID), thread counts, loaded modules, unbacked executable virtual memory regions (with Shannon entropy calculation), and TCP/UDP sockets at an instantaneous moment.
2. **Data Serialization**: Serializes real-time metrics into `telemetry.json` and decomposes them into sorted, structured CSVs (`telemetry_graph_nodes.csv`, `telemetry_graph_weighted_edges.csv`).
3. **Homogeneous Graph Conversion (Phase 2)**: Transforms heterogeneous host entities into a unified homogeneous graph with contiguous 0-indexing, differentiated node taxonomy, formulated semantic labels, multi-dimensional normalized feature vectors, dynamic physics repulsion spacing, and interactive graph rendering.
4. **GNN Modeling (Future Phase)**: Ingests the homogeneous graph into GNN architectures (GCN, GAT, GraphSAGE) for malicious process classification and anomalous subgraph detection.

---

## 📂 Repository Directory Structure

```text
graph_conversion/
├── CMakeLists.txt                    # Standard CMake build configuration
├── Makefile                          # MinGW / GCC makefile
├── build.bat                         # 1-click Windows compilation script
├── run_hub.bat                       # 1-click interactive pipeline launcher
├── nexus_graph_hub.py                # Interactive CLI navigation & forensics hub
├── README.md                         # Project documentation
│
├── include/                          # C++20 Header files
│   ├── json_serializer.hpp           # Zero-dependency escaped JSON serializer
│   ├── memory_scanner.hpp            # Virtual memory scanner & Shannon entropy
│   ├── network_mapper.hpp            # Extended TCP/UDP table socket mapper
│   ├── privilege.hpp                 # SeDebugPrivilege elevation handler
│   ├── process_collector.hpp         # Toolhelp32 process & thread collector
│   └── telemetry_model.hpp           # Strongly-typed data structs
│
├── src/                              # C++20 Implementation files
│   ├── json_serializer.cpp
│   ├── memory_scanner.cpp
│   ├── network_mapper.cpp
│   ├── privilege.cpp
│   ├── process_collector.cpp
│   └── main.cpp                      # CLI entry point and orchestration
│
├── bin/                              # Compiled binaries (git ignored)
│   └── telemetry_engine.exe
│
├── organize_and_clean_telemetry.py   # Telemetry JSON-to-CSV organizer
├── generate_homogeneous_graph.py    # Refined Homogeneous Graph converter
│
├── references/                       # Presentations and background documents (local, git ignored)
└── Project_context.md                # In-depth architectural & conceptual guide (local, git ignored)
```

---

## ⚙️ Prerequisites & Compilation

### C++ Compiler

- **MinGW-w64** (GCC 11+) OR **MSVC** (Visual Studio 2022+) with C++20 support.
- Native build linking `ws2_32`, `iphlpapi`, `psapi`, `advapi32`. Pure native machine code (no .NET runtime).

### Python Environment

- Python 3.10+
- Recommended packages:

  ```bash
  pip install networkx matplotlib pandas numpy scipy pyvis torch torch_geometric scikit-learn
  ```

### Build Options

#### Option 1: Quick Batch Build (MinGW / GCC)

```cmd
build.bat
```

Produces `bin\telemetry_engine.exe`.

#### Option 2: MinGW Make

```cmd
mingw32-make
```

#### Option 3: CMake

```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

---

## 🚀 Running the Telemetry Engine

To inspect privileged system processes, virtual memory allocations, and socket tables, run with administrative privileges:

```powershell
# Run data collection and output to telemetry.json
.\bin\telemetry_engine.exe -o telemetry.json
```

### CLI Options

```text
Usage: telemetry_engine.exe [options]

Options:
  -o, --output <file>    Specify output JSON file path (default: telemetry.json)
  -s, --stdout           Stream complete JSON directly to standard output
  -q, --quiet            Suppress banner and scan logs
  -h, --help             Display help menu
```

---

## 📊 Telemetry Data & Intermediate CSV Representation

The engine outputs structured metrics:

- **Processes**: PID, PPID, executable name, image path, thread counts, loaded modules.
- **Unbacked Memory**: Base address, region size, page protection (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`), Shannon entropy ($H \in [0.0, 8.0]$).
- **Sockets**: Local address, local port, remote address, remote port, protocol, state.

To parse `telemetry.json` into tabular sorted CSV files:

```powershell
python organize_and_clean_telemetry.py
```

This generates:

- `telemetry_graph_nodes.csv`: Standardized node table.
- `telemetry_graph_weighted_edges.csv`: Weighted relational edge records (`spawns`, `has_memory`, `connected_to`).

---

## 🧬 Homogeneous Graph Conversion

GNN algorithms require homogeneous graphs where all nodes share a common feature space $\mathbb{R}^d$ and contiguous 0-indexed integer IDs.

Run the converter:

```powershell
python generate_homogeneous_graph.py
```

### Key Capabilities and Taxonomy Refinements

#### 1. Contiguous Node Indexing

Maps all heterogeneous system entities (Processes, Memory regions, Sockets) to a contiguous sequence $0, 1, \dots, |V|-1$.

#### 2. Differentiated Node Taxonomy

- **System Core Processes** (`#818cf8` Indigo Diamond): OS infrastructure binaries (`services.exe`, `lsass.exe`, `svchost.exe`).
- **User / App Processes** (`#00e5ff` Cyan Dot): User-space applications and interactive sessions (`powershell.exe`, `chrome.exe`).
- **High-Risk Memory** (`#f43f5e` Crimson Star): Unbacked executable private pages with Shannon Entropy $H \ge 6.5$ or RWX permissions (injected shellcode / stagers).
- **Normal Unbacked Memory** (`#f59e0b` Amber Square): Standard unbacked code buffers ($H < 6.5$).
- **TCP Established** (`#10b981` Green Triangle): Active network channels with destination service identification (`:443 (HTTPS)`).
- **TCP Listening** (`#38bdf8` Sky Blue Down-Triangle): Local listening daemons (`:135 (RPC/EPMAP)`).
- **UDP Sockets** (`#14b8a6` Teal Hexagon): Datagram endpoints (`:5353 (mDNS)`).

#### 3. Explicit Directed Edge Labeling & Taxonomy

- **`spawns`** (`#a855f7` Purple): Direct process parentage (PPID $\to$ PID), weighted by child thread count.
- **`has_memory`** (`#fb7185` Coral): Process $\to$ Allocated unbacked memory region, weighted by entropy risk and RWX flags.
- **`connected_to`** (`#38bdf8` Sky Blue): Process $\to$ Network socket channel, weighted by connection state (`ESTABLISHED` vs `LISTEN`).
- **Interactive Edge Controls**: Vis.js renders middle-aligned relation labels with dark stroke borders directly on the connecting springs. A dedicated **Display Edge Labels** checkbox in the sidebar allows users to toggle edge labels on and off in real time.

#### 4. Adaptive Physics Repulsion & Elastic Spacing

- Integrated live **Node Repulsion Slider** (500 to 8000) and **Edge Length Slider** (80 to 400) allowing users to expand spatial clearance between crowded hubs and nodes dynamically.
- Built-in **Collision Avoidance** (`avoidOverlap: 1.0`) preventing overlapping nodes and labels.
- **Freeze / Resume Physics** button to lock the spacious configuration in place for drift-free inspection.
- Precomputed spring coordinates expanded over a broad $[-2200, 2200]$ plane ($k = 3.6 / \sqrt{|V|}$) for generous initial visual margins.

#### 5. Unified Feature Matrix ($\mathbf{X} \in \mathbb{R}^{|V| \times 16}$)

| Feature Dimension | Name | Description | Value Range |
| :--- | :--- | :--- | :---: |
| `feat_0` | `is_process` | One-hot indicator for Process entity | $\{0.0, 1.0\}$ |
| `feat_1` | `is_memory` | One-hot indicator for Virtual Memory entity | $\{0.0, 1.0\}$ |
| `feat_2` | `is_socket` | One-hot indicator for Network Socket entity | $\{0.0, 1.0\}$ |
| `feat_3` | `threads_norm` | Process active thread count (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_4` | `modules_norm` | Process loaded DLL/module count (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_5` | `is_system` | Indicates elevated/system binary status | $\{0.0, 1.0\}$ |
| `feat_6` | `entropy_norm` | Shannon entropy $H$ normalized by max bound (8.0) | $[0.0, 1.0]$ |
| `feat_7` | `size_norm` | Memory region byte size (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_8` | `is_rwx` | Indicates `PAGE_EXECUTE_READWRITE` permission | $\{0.0, 1.0\}$ |
| `feat_9` | `port_norm` | Local/Remote port normalized ($0 \dots 65535$) | $[0.0, 1.0]$ |
| `feat_10` | `is_listening` | Socket in `LISTEN` state | $\{0.0, 1.0\}$ |
| `feat_11` | `is_established` | Socket in active `ESTABLISHED` state | $\{0.0, 1.0\}$ |
| `feat_12` | `in_deg_norm` | Graph in-degree centrality (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_13` | `out_deg_norm` | Graph out-degree centrality (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_14` | `tot_deg_norm` | Total node degree centrality (Min-Max scaled) | $[0.0, 1.0]$ |
| `feat_15` | `weighted_deg_norm` | Weighted degree centrality sum (Min-Max scaled) | $[0.0, 1.0]$ |

#### 6. Dynamic Visual & Machine-Learning Outputs

- `homogeneous_graph.json`: Full graph schema (nodes, features, edge indices, spatial coordinates).
- `homogeneous_nodes.csv`: Node table with normalized feature dimensions, category classifications, and $(x, y)$ positions.
- `homogeneous_edges.csv`: Edge table with source/target indices, relation types, and normalized weights.
- `homogeneous_pyg_data.pt`: PyTorch Geometric `Data(x=[|V|, 16], edge_index=[2, |E|], edge_attr=[|E|, 4])` artifact.
- `homogeneous_graph_view.html`: Standalone interactive web view with search by PID/name/service, category filters, live repulsion controls, edge label toggle, and 16D feature inspector.
- `homogeneous_graph_preview.png`: Publication-grade high-resolution static rendering.

> **Note**: Datasets (`telemetry.json`), intermediate CSVs, and generated graph outputs are generated dynamically on each run and are excluded from Git via `.gitignore` to preserve local privacy and prevent repository bloat.

---

## 🧠 Core Concepts & Terminology Guide

For outside researchers and developers, here is a glossary of the security and graph concepts underpinning this engine:

### 1. Instantaneous Kernel Snapshotting

Traditional security monitors (e.g. Sysmon, ETW) produce event logs over time. In contrast, this engine captures an **instantaneous spatial snapshot** of all kernel objects existing at a single point in time. This models the operating system as a single cohesive graph topology rather than disconnected event streams.

### 2. Unbacked Executable Memory Pages

In legitimate Windows execution, executable machine code is loaded from signed binaries on disk (PE files such as `.exe` or `.dll`). These pages have a memory type of `MEM_IMAGE`.

When malware executes in-memory payloads (e.g., Cobalt Strike beacons, reflective DLL injection, shellcode loaders), it allocates private memory (`MEM_PRIVATE`) via `VirtualAlloc` and marks it executable (`PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_READ`). Because there is no backing file on disk, these pages are termed **unbacked**. Detecting unbacked executable memory is one of the highest-fidelity indicators of in-memory compromise.

### 3. Shannon Entropy ($H$)

Entropy measures the degree of algorithmic randomness in a byte sequence:

$$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$

- **Plaintext / Normal Code**: Typically $H \in [3.5, 5.2]$ due to repetitive assembly opcodes (`MOV`, `PUSH`, `CALL`).
- **Encrypted / Packed Shellcode**: Exhibits high randomness approaching theoretical maximum ($H \ge 6.5$).
- This engine scans executable memory buffers up to 1 MB per region to calculate exact entropy scores without writing raw memory contents to disk.

### 4. Extended TCP/UDP Socket Mapping

Standard socket APIs reveal open ports, but fail to tie them to the originating process. The engine utilizes `GetExtendedTcpTable` and `GetExtendedUdpTable` (`TCP_TABLE_OWNER_PID_ALL`) to link every active socket directly to its host Process ID (PID). This exposes hidden C2 channels and unauthorized listening ports.

### 5. Homogeneous Graph Conversion for Graph Neural Networks (GNNs)

Heterogeneous graphs assign different feature shapes to different entity types (e.g., processes have thread counts, while sockets have IP addresses). However, standard GNN layers (such as Graph Convolutional Networks, Graph Attention Networks, and GraphSAGE) operate on a **homogeneous feature matrix** $\mathbf{X} \in \mathbb{R}^{|V| \times d}$ and an edge index matrix $\mathbf{E} \in \mathbb{Z}^{2 \times |E|}$ with contiguous zero-based indices.

Our conversion pipeline projects all heterogeneous system entities into a shared 16-dimensional continuous feature space, assigning contiguous integer IDs $0, 1, \dots, |V|-1$, enabling immediate compatibility with PyTorch Geometric and DGL.

### 6. Dynamic Physics Repulsion & Spatial Clearance

In dense host graphs, process hubs (such as `svchost.exe` hosting dozens of sockets and memory regions) naturally collapse into visual clutter under default spring algorithms. The engine utilizes an interactive ForceAtlas2 physics simulator with:

- **Inverse-Square Repulsion**: Nodes push each other away like electrostatic charges ($F \propto 1/r^2$).
- **Elastic Springs**: Edges pull connected neighbors together.
- **Dynamic Tunability**: Real-time browser sliders allow researchers to scale repulsion and spring distances on the fly to inspect dense subgraphs.

---

## 🚀 Complete Pipeline Execution Guide

You can run the engine using the **Interactive Navigation Hub** or via direct CLI steps:

### Option 1: 1-Click Interactive Console Hub (Recommended)

Run the interactive cyber-forensics command hub for a guided, menu-driven workflow with pre-flight checks, instant security triage summaries, and browser launching:

```powershell
# Double-click run_hub.bat OR run via terminal:
.\run_hub.bat

# Or launch directly with Python:
python nexus_graph_hub.py
```

The hub provides:

- `[1]` Autonomous End-to-End Pipeline (Collect $\to$ Clean $\to$ Graph $\to$ Launch View)
- `[2]` Phase 1: Live Telemetry Snapshot
- `[3]` Phase 2: Telemetry Sanitization & CSV Structuring
- `[4]` Phase 3: Homogeneous Graph Conversion & GNN Tensor Export
- `[5]` Launch Interactive Graph Visualizer in Browser
- `[6]` Instant Security Triage & Graph Topology Insights (Flagged RWX memory, top hubs)
- `[7]` Recompile Native C++ Collector

### Option 2: Step-by-Step Manual CLI Execution

Run each stage individually in your terminal:

```powershell
# 1. Capture live system execution state (run terminal as Administrator for SeDebugPrivilege)
.\bin\telemetry_engine.exe -o telemetry.json

# 2. Parse and organize into structured CSV node and edge tables
python organize_and_clean_telemetry.py

# 3. Transform into homogeneous graph, PyG tensor, static preview, and interactive HTML viewer
python generate_homogeneous_graph.py
```

Open `homogeneous_graph_view.html` in any browser to inspect the resulting interactive graph.

---

## 🛡️ License

This project is licensed under the MIT License.
