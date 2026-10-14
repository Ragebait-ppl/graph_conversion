# Graph Conversion & Host Forensics Telemetry Engine

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20x64-0078D6?logo=windows)](https://microsoft.com)
[![Language](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg?logo=c%2B%2B)](https://isocpp.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg?logo=python)](https://python.org)
[![Graph](https://img.shields.io/badge/Topology-Homogeneous%20Graph-orange.svg)](https://networkx.org)
[![ML Ready](https://img.shields.io/badge/ML-PyTorch%20Geometric%20Ready-EE4C2C.svg?logo=pytorch)](https://pytorch-geometric.readthedocs.io)

An end-to-end framework for capturing low-level Windows host execution states, structuring system events into tabular telemetry datasets, and converting multi-entity forensics into **clean, feature-rich homogeneous graphs** formatted for Graph Neural Networks (GNNs).

---

## 📌 Architecture & Workflow

```
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
| - Stable Interactive View|     | Deterministic Coordinates|     |                          |
+--------------------------+     +--------------------------+     +--------------------------+
```

1. **Host Telemetry Collection (Phase 1)**: Captures running processes, process parentage (PPID), thread counts, loaded modules, unbacked executable virtual memory regions (with Shannon entropy calculation), and TCP/UDP sockets at an instantaneous moment.
2. **Data Serialization**: Serializes real-time metrics into `telemetry.json` and decomposes them into sorted, structured CSVs (`telemetry_graph_nodes.csv`, `telemetry_graph_weighted_edges.csv`).
3. **Homogeneous Graph Conversion (Phase 2)**: Transforms heterogeneous host entities into a unified homogeneous graph with contiguous 0-indexing, differentiated node taxonomy, formulated semantic labels, multi-dimensional normalized feature vectors, deterministic spatial layout, and interactive graph rendering.
4. **GNN Modeling (Future Phase)**: Ingests the homogeneous graph into GNN architectures (GCN, GAT, GraphSAGE) for malicious process classification and anomalous subgraph detection.

---

## 📂 Repository Directory Structure

```
graph_conversion/
├── CMakeLists.txt                    # Standard CMake build configuration
├── Makefile                          # MinGW / GCC makefile
├── build.bat                         # 1-click Windows compilation script
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
```
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

### Key Capabilities & Taxonomy Refinements:
1. **Contiguous Node Indexing**: Maps all system entities (Processes, Memory regions, Sockets) to a contiguous sequence $0, 1, \dots, |V|-1$.
2. **Differentiated Node Taxonomy**:
   - **System Core Processes** (`#818cf8` Indigo Diamond): OS infrastructure binaries (`services.exe`, `lsass.exe`, `svchost.exe`).
   - **User / App Processes** (`#00e5ff` Cyan Dot): User-space applications and scripts (`powershell.exe`, `chrome.exe`).
   - **High-Risk Memory** (`#f43f5e` Crimson Star): Unbacked executable private pages with Shannon Entropy $H \ge 6.5$ or RWX permissions.
   - **Normal Unbacked Memory** (`#f59e0b` Amber Square): Standard unbacked code buffers ($H < 6.5$).
   - **TCP Established** (`#10b981` Green Triangle): Active network channels with destination service identification (`:443 (HTTPS)`).
   - **TCP Listening** (`#38bdf8` Sky Blue Down-Triangle): Local listening daemons (`:135 (RPC/EPMAP)`).
   - **UDP Sockets** (`#14b8a6` Teal Hexagon): Datagram endpoints (`:5353 (mDNS)`).
3. **Deterministic Stable Spatial Layout (Repulsion Jitter Removed)**:
   - Uses precomputed NetworkX spring coordinates with fixed seed for guaranteed layout repeatability.
   - Dynamic browser physics simulation and artificial repulsion adjustments have been replaced with a deterministic static view for instantaneous loading and lag-free inspection.
4. **Unified Feature Matrix ($\mathbf{X} \in \mathbb{R}^{|V| \times 16}$)**:
   - Entity type one-hot encoding
   - Process attributes (threads, modules, privilege status)
   - Memory attributes (Shannon entropy, region size, RWX flags)
   - Network attributes (protocol, ports, socket state)
   - Graph structural metrics (in-degree, out-degree, total degree, weighted degree)
   - Continuous features normalized via Min-Max scaling to $[0, 1]$
5. **Visual & Machine-Learning Outputs**:
   - `homogeneous_graph.json`: Full graph schema (nodes, features, edge indices, spatial coordinates).
   - `homogeneous_nodes.csv`: Node table with normalized feature dimensions, category classifications, and $(x, y)$ positions.
   - `homogeneous_edges.csv`: Edge table with source/target indices, relation types, and normalized weights.
   - `homogeneous_pyg_data.pt`: PyTorch Geometric `Data(x=[923, 16], edge_index=[2, 904], edge_attr=[904, 4])` artifact.
   - `homogeneous_graph_view.html`: Standalone interactive web view with search by PID/name/service, category filters, and 16D feature inspector.
   - `homogeneous_graph_preview.png`: Publication-grade high-resolution static rendering.

---

## 🛡️ License

This project is licensed under the MIT License.
