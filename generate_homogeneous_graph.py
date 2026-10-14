#!/usr/bin/env python3
"""
Homogeneous Graph Conversion Engine (Enhanced Taxonomy & Stable Visualization)
==============================================================================
Converts Windows host telemetry CSV records (nodes and weighted edges)
into a clean, feature-rich homogeneous graph:
- Contiguous 0-indexing for all entities (Processes, Memory regions, Sockets)
- 16-dimensional unified normalized feature tensor X in R^(|V| x 16)
- Standard COO edge_index [2, |E|] with normalized edge attributes
- Differentiated node categories:
    * System Core Processes vs User/App Processes
    * High-Risk Unbacked Memory (H >= 6.5 or RWX) vs Standard Unbacked Memory
    * TCP Established vs TCP Listening vs UDP Endpoints
- Formulated semantic labels with well-known port/service identification
- Deterministic, stable layout (artificial repulsion and dynamic drift removed)
- Interactive standalone HTML viewer (homogeneous_graph_view.html) with freeze-on-load stability
- High-resolution static preview plot (homogeneous_graph_preview.png)
- PyTorch Geometric (PyG) Data artifact (homogeneous_pyg_data.pt)
"""

import os
import json
import math
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

WELL_KNOWN_PORTS = {
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    123: "NTP",
    135: "RPC/EPMAP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1900: "SSDP",
    3389: "RDP",
    5353: "mDNS",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

SYSTEM_BINARIES = {
    "system", "[system process]", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "winlogon.exe", "dwm.exe", "spoolsv.exe", "sihost.exe", "taskhostw.exe",
    "explorer.exe", "shellexperiencehost.exe", "searchhost.exe", "startmenuexperiencehost.exe"
}

def resolve_port_service(port):
    try:
        p = int(port)
        return WELL_KNOWN_PORTS.get(p, "")
    except (ValueError, TypeError):
        return ""

def format_bytes(b):
    try:
        b = float(b)
        if b >= 1024 * 1024:
            return f"{b / (1024 * 1024):.1f} MB"
        elif b >= 1024:
            return f"{b / 1024:.0f} KB"
        return f"{int(b)} B"
    except (ValueError, TypeError):
        return "0 B"

def generate_homogeneous_graph(
    nodes_csv_path="telemetry_graph_nodes.csv",
    edges_csv_path="telemetry_graph_weighted_edges.csv",
    output_dir="."
):
    print("=" * 75)
    print("  HOMOGENEOUS GRAPH CONVERSION ENGINE (REFINED TAXONOMY & STABLE LAYOUT)")
    print("=" * 75)

    # 1. Load CSV data
    print(f"[*] Loading CSV datasets...")
    if not os.path.exists(nodes_csv_path):
        raise FileNotFoundError(f"Missing {nodes_csv_path}")
    if not os.path.exists(edges_csv_path):
        raise FileNotFoundError(f"Missing {edges_csv_path}")

    nodes_df = pd.read_csv(nodes_csv_path)
    edges_df = pd.read_csv(edges_csv_path)
    print(f"    - Loaded {len(nodes_df)} raw nodes across types: {dict(nodes_df['node_type'].value_counts())}")
    print(f"    - Loaded {len(edges_df)} raw edges across relationships: {dict(edges_df['relationship'].value_counts())}")

    # 2. Build Contiguous 0-Indexed Node Registry
    def sort_key(row):
        type_priority = {"process": 0, "memory_region": 1, "socket": 2}.get(row["node_type"], 3)
        pid = int(row["pid"]) if pd.notnull(row["pid"]) else 0
        return (type_priority, pid, str(row["node_id"]))

    nodes_df["sort_order"] = nodes_df.apply(sort_key, axis=1)
    nodes_df = nodes_df.sort_values(by="sort_order").reset_index(drop=True)
    nodes_df.drop(columns=["sort_order"], inplace=True)

    # Assign contiguous integer indices 0 ... |V|-1
    nodes_df["node_idx"] = np.arange(len(nodes_df), dtype=int)
    id_to_idx = {row["node_id"]: int(row["node_idx"]) for _, row in nodes_df.iterrows()}
    idx_to_id = {int(row["node_idx"]): row["node_id"] for _, row in nodes_df.iterrows()}
    print(f"[+] Contiguous node index assigned: 0 to {len(nodes_df) - 1}")

    # 3. Construct NetworkX Graph & Calculate Topological Centralities
    print(f"[*] Building topological graph model...")
    G = nx.DiGraph()
    for _, row in nodes_df.iterrows():
        G.add_node(row["node_idx"], node_id=row["node_id"], node_type=row["node_type"])

    valid_edges = []
    for _, e in edges_df.iterrows():
        src_id = e["source"]
        tgt_id = e["target"]
        if src_id in id_to_idx and tgt_id in id_to_idx:
            src_idx = id_to_idx[src_id]
            tgt_idx = id_to_idx[tgt_id]
            w = float(e["weight"]) if pd.notnull(e.get("weight")) else 1.0
            w_norm = float(e["weight_normalized"]) if pd.notnull(e.get("weight_normalized")) else 0.5
            rel = str(e["relationship"])
            G.add_edge(src_idx, tgt_idx, weight=w, weight_norm=w_norm, relationship=rel)
            valid_edges.append({
                "source_idx": src_idx,
                "target_idx": tgt_idx,
                "source_id": src_id,
                "target_id": tgt_id,
                "relationship": rel,
                "weight": w,
                "weight_normalized": w_norm
            })

    print(f"[+] Graph constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} directed edges.")

    # Calculate topological metrics
    in_degrees = dict(G.in_degree())
    out_degrees = dict(G.out_degree())
    total_degrees = dict(G.degree())
    weighted_degrees = {
        n: sum(d.get("weight", 1.0) for _, _, d in G.in_edges(n, data=True)) +
           sum(d.get("weight", 1.0) for _, _, d in G.out_edges(n, data=True))
        for n in G.nodes()
    }

    max_in = max(in_degrees.values()) if in_degrees else 1
    max_out = max(out_degrees.values()) if out_degrees else 1
    max_deg = max(total_degrees.values()) if total_degrees else 1
    max_w_deg = max(weighted_degrees.values()) if weighted_degrees else 1.0

    # 4. Refined Node Classification & Label Formulation
    print(f"[*] Differentiating nodes and formulating rich semantic labels...")
    
    subcategories = []
    category_colors = []
    category_shapes = []
    clean_labels = []
    display_names = []
    risk_levels = []

    # Precompute normalization scales for process metrics
    proc_threads = nodes_df[nodes_df["node_type"] == "process"]["metric_1"].astype(float)
    max_threads = max(proc_threads.max(), 1.0) if len(proc_threads) > 0 else 1.0
    
    proc_modules = nodes_df[nodes_df["node_type"] == "process"]["metric_2"].astype(float)
    max_modules = max(proc_modules.max(), 1.0) if len(proc_modules) > 0 else 1.0

    feature_matrix = np.zeros((len(nodes_df), 16), dtype=np.float32)

    for idx, row in nodes_df.iterrows():
        n_type = row["node_type"]
        pid = int(row["pid"]) if pd.notnull(row["pid"]) else 0
        name = str(row["name"]).strip() if pd.notnull(row["name"]) else ""
        name_lower = name.lower()
        m1 = float(row["metric_1"]) if pd.notnull(row["metric_1"]) else 0.0
        m2 = float(row["metric_2"]) if pd.notnull(row["metric_2"]) else 0.0
        extra = str(row["extra_info"]) if pd.notnull(row["extra_info"]) else ""

        f = np.zeros(16, dtype=np.float32)

        if n_type == "process":
            f[0] = 1.0
            f[3] = np.clip(m1 / max_threads, 0.0, 1.0)
            f[4] = np.clip(m2 / max_modules, 0.0, 1.0)
            
            is_sys = (pid <= 4) or (name_lower in SYSTEM_BINARIES)
            f[5] = 1.0 if is_sys else 0.0

            if is_sys:
                subcat = "system_process"
                color = "#818cf8"  # Royal Indigo/Purple
                shape = "diamond"
                risk = "System Baseline"
                lbl = f"[SYS] {name} (PID {pid})"
                disp = f"System Process: {name} [PID {pid}] | Threads: {int(m1)} | Modules: {int(m2)}"
            else:
                subcat = "user_process"
                color = "#00e5ff"  # Electric Cyan
                shape = "dot"
                risk = "User Space"
                lbl = f"[PROC] {name} (PID {pid})"
                disp = f"User Process: {name} [PID {pid}] | Threads: {int(m1)} | Modules: {int(m2)}"

        elif n_type == "memory_region":
            f[1] = 1.0
            entropy = m1
            region_size = m2
            f[6] = np.clip(entropy / 8.0, 0.0, 1.0)
            f[7] = np.clip(math.log10(max(region_size, 1.0)) / 8.0, 0.0, 1.0)
            is_rwx = ("READWRITE" in extra or "RWX" in extra)
            f[8] = 1.0 if is_rwx else 0.5

            size_str = format_bytes(region_size)
            perm_short = "RWX" if is_rwx else "RX"

            if entropy >= 6.5 or is_rwx:
                subcat = "high_risk_memory"
                color = "#f43f5e"  # Crimson / Rose
                shape = "star"
                risk = "HIGH RISK: Encrypted / Injected RWX Shellcode"
                lbl = f"[ALERT MEM] H={entropy:.2f} ({size_str}, {perm_short})"
                disp = f"High-Risk Unbacked Memory: PID {pid} | Entropy: {entropy:.4f} | Size: {size_str} | Perm: {extra}"
            else:
                subcat = "normal_memory"
                color = "#f59e0b"  # Amber Orange
                shape = "square"
                risk = "Moderate: Unbacked Code Buffer"
                lbl = f"[MEM] H={entropy:.2f} ({size_str}, {perm_short})"
                disp = f"Unbacked Memory: PID {pid} | Entropy: {entropy:.4f} | Size: {size_str} | Perm: {extra}"

        elif n_type == "socket":
            f[2] = 1.0
            local_port = int(m1)
            remote_port = int(m2)
            f[9] = np.clip(local_port / 65535.0, 0.0, 1.0)
            is_listen = ("LISTENING" in extra)
            is_estab = ("ESTABLISHED" in extra)
            f[10] = 1.0 if is_listen else 0.0
            f[11] = 1.0 if is_estab else 0.0

            svc = resolve_port_service(local_port) or resolve_port_service(remote_port)
            svc_tag = f" ({svc})" if svc else ""

            if is_estab:
                subcat = "socket_established"
                color = "#10b981"  # Neon Emerald Green
                shape = "triangle"
                risk = "Active Network Session"
                lbl = f"[TCP ESTAB] :{local_port} -> :{remote_port}{svc_tag}"
                disp = f"Active TCP Socket: PID {pid} | :{local_port} -> :{remote_port}{svc_tag} [ESTABLISHED]"
            elif is_listen:
                subcat = "socket_listening"
                color = "#38bdf8"  # Sky Blue
                shape = "triangleDown"
                risk = "Listening Daemon Endpoint"
                lbl = f"[TCP LISTEN] :{local_port}{svc_tag}"
                disp = f"Listening TCP Socket: PID {pid} | Port {local_port}{svc_tag} [LISTENING]"
            else:
                subcat = "socket_udp"
                color = "#14b8a6"  # Teal
                shape = "triangle"
                risk = "UDP Datagram Endpoint"
                lbl = f"[UDP] :{local_port}{svc_tag}"
                disp = f"UDP Socket: PID {pid} | Port {local_port}{svc_tag}"
        else:
            subcat = "other"
            color = "#94a3b8"
            shape = "dot"
            risk = "General"
            lbl = f"Node {idx}"
            disp = f"Node {idx}"

        # Graph topological features
        f[12] = in_degrees.get(idx, 0) / max(max_in, 1)
        f[13] = out_degrees.get(idx, 0) / max(max_out, 1)
        f[14] = total_degrees.get(idx, 0) / max(max_deg, 1)
        f[15] = weighted_degrees.get(idx, 0) / max(max_w_deg, 1.0)

        feature_matrix[idx] = f
        subcategories.append(subcat)
        category_colors.append(color)
        category_shapes.append(shape)
        clean_labels.append(lbl)
        display_names.append(disp)
        risk_levels.append(risk)

    nodes_df["subcategory"] = subcategories
    nodes_df["color"] = category_colors
    nodes_df["shape"] = category_shapes
    nodes_df["clean_label"] = clean_labels
    nodes_df["display_name"] = display_names
    nodes_df["risk_level"] = risk_levels

    # Add feature columns
    feature_col_names = [
        "feat_is_proc", "feat_is_mem", "feat_is_sock",
        "feat_threads_norm", "feat_modules_norm", "feat_is_system",
        "feat_entropy_norm", "feat_size_norm", "feat_is_rwx",
        "feat_port_norm", "feat_is_listening", "feat_is_established",
        "feat_in_deg_norm", "feat_out_deg_norm", "feat_tot_deg_norm", "feat_weighted_deg_norm"
    ]
    for i, col in enumerate(feature_col_names):
        nodes_df[col] = feature_matrix[:, i]

    # 5. Deterministic Spatial Layout (Stable, without artificial repulsion loops)
    print(f"[*] Calculating stable, deterministic spring layout coordinates...")
    # Clean standard spring layout:
    # A standard optimal k-factor gives clean, natural topological clusters
    k_val = 1.9 / math.sqrt(len(G.nodes()))
    pos = nx.spring_layout(G, k=k_val, iterations=85, seed=42)

    scale_grid = 1400.0
    coords_x = np.array([pos[i][0] * scale_grid for i in range(len(G.nodes()))])
    coords_y = np.array([pos[i][1] * scale_grid for i in range(len(G.nodes()))])

    nodes_df["pos_x"] = np.round(coords_x, 2)
    nodes_df["pos_y"] = np.round(coords_y, 2)
    print(f"[+] Deterministic coordinates generated: X in [{coords_x.min():.1f}, {coords_x.max():.1f}], Y in [{coords_y.min():.1f}, {coords_y.max():.1f}]")

    # 6. Save Tabular CSVs
    homogeneous_nodes_csv = os.path.join(output_dir, "homogeneous_nodes.csv")
    homogeneous_edges_csv = os.path.join(output_dir, "homogeneous_edges.csv")
    
    nodes_df.to_csv(homogeneous_nodes_csv, index=False)
    print(f"[+] Saved {homogeneous_nodes_csv} ({len(nodes_df)} nodes with refined taxonomy)")

    edges_out_df = pd.DataFrame(valid_edges)
    edges_out_df.to_csv(homogeneous_edges_csv, index=False)
    print(f"[+] Saved {homogeneous_edges_csv} ({len(edges_out_df)} edges)")

    # 7. Generate Machine-Readable Homogeneous Graph JSON
    print(f"[*] Generating homogeneous_graph.json...")
    homogeneous_json_path = os.path.join(output_dir, "homogeneous_graph.json")

    subcat_counts = {str(k): int(v) for k, v in nodes_df["subcategory"].value_counts().items()}
    rel_counts = {str(k): int(v) for k, v in edges_out_df["relationship"].value_counts().items()}

    graph_dict = {
        "metadata": {
            "title": "Windows Host Telemetry Homogeneous Graph (Refined)",
            "num_nodes": int(len(nodes_df)),
            "num_edges": int(len(edges_out_df)),
            "feature_dim": 16,
            "feature_schema": feature_col_names,
            "subcategory_breakdown": subcat_counts,
            "relationship_breakdown": rel_counts,
            "coordinate_bounds": {
                "x_min": float(coords_x.min()),
                "x_max": float(coords_x.max()),
                "y_min": float(coords_y.min()),
                "y_max": float(coords_y.max())
            }
        },
        "nodes": [
            {
                "index": int(row["node_idx"]),
                "node_id": str(row["node_id"]),
                "node_type": str(row["node_type"]),
                "subcategory": str(row["subcategory"]),
                "label": str(row["clean_label"]),
                "display_name": str(row["display_name"]),
                "pid": int(row["pid"]) if pd.notnull(row["pid"]) else 0,
                "name": str(row["name"]) if pd.notnull(row["name"]) else "",
                "risk_level": str(row["risk_level"]),
                "x": float(row["pos_x"]),
                "y": float(row["pos_y"]),
                "degree": int(total_degrees.get(int(row["node_idx"]), 0)),
                "features": [float(x) for x in feature_matrix[int(row["node_idx"])]]
            }
            for _, row in nodes_df.iterrows()
        ],
        "edges": [
            {
                "source_idx": int(e["source_idx"]),
                "target_idx": int(e["target_idx"]),
                "source_id": str(e["source_id"]),
                "target_id": str(e["target_id"]),
                "relationship": str(e["relationship"]),
                "weight": float(e["weight"]),
                "weight_normalized": float(e["weight_normalized"])
            }
            for e in valid_edges
        ],
        "edge_index": [
            [int(e["source_idx"]) for e in valid_edges],
            [int(e["target_idx"]) for e in valid_edges]
        ]
    }

    with open(homogeneous_json_path, "w", encoding="utf-8") as f:
        json.dump(graph_dict, f, indent=2, default=lambda o: int(o) if isinstance(o, (np.integer, np.int64)) else float(o) if isinstance(o, (np.floating, np.float32, np.float64)) else str(o))
    print(f"[+] Saved {homogeneous_json_path}")

    # 8. PyTorch Geometric Export
    try:
        import torch
        from torch_geometric.data import Data
        
        edge_index_tensor = torch.tensor(graph_dict["edge_index"], dtype=torch.long)
        x_tensor = torch.tensor(feature_matrix, dtype=torch.float)
        edge_attr_tensor = torch.tensor(
            [[e["weight_normalized"],
              1.0 if e["relationship"] == "spawns" else 0.0,
              1.0 if e["relationship"] == "has_memory" else 0.0,
              1.0 if e["relationship"] == "connected_to" else 0.0]
             for e in valid_edges],
            dtype=torch.float
        )
        
        pyg_data = Data(x=x_tensor, edge_index=edge_index_tensor, edge_attr=edge_attr_tensor, num_nodes=len(nodes_df))
        pyg_path = os.path.join(output_dir, "homogeneous_pyg_data.pt")
        torch.save(pyg_data, pyg_path)
        print(f"[+] Saved PyTorch Geometric artifact: {pyg_path}")
    except Exception as ex:
        print(f"[!] PyTorch Geometric export skipped: {ex}")

    # 9. High-Resolution Publication-Grade Diagram Preview Plot
    print(f"[*] Generating refined high-resolution preview plot...")
    plt.figure(figsize=(19, 13), facecolor="#080e1a", dpi=200)
    ax = plt.gca()
    ax.set_facecolor("#080e1a")

    # Draw directed edges
    rel_colors = {
        "has_memory": "#fb7185",   # Coral
        "connected_to": "#38bdf8", # Sky blue
        "spawns": "#a855f7"        # Purple
    }

    for e in valid_edges:
        p1 = (coords_x[e["source_idx"]], coords_y[e["source_idx"]])
        p2 = (coords_x[e["target_idx"]], coords_y[e["target_idx"]])
        rel = e["relationship"]
        c = rel_colors.get(rel, "#94a3b8")
        w = max(float(e["weight_normalized"]) * 1.5, 0.4)
        ax.annotate("", xy=p2, xytext=p1,
                    arrowprops=dict(arrowstyle="->", color=c, lw=w, alpha=0.45, mutation_scale=6))

    # Scatter nodes differentiated by subcategory and shape
    subcat_meta = {
        "system_process": {"color": "#818cf8", "marker": "D", "label": "System Process (OS Core)"},
        "user_process": {"color": "#00e5ff", "marker": "o", "label": "User Process"},
        "high_risk_memory": {"color": "#f43f5e", "marker": "*", "label": "High-Risk Memory (H >= 6.5 / RWX)"},
        "normal_memory": {"color": "#f59e0b", "marker": "s", "label": "Unbacked Memory (H < 6.5)"},
        "socket_established": {"color": "#10b981", "marker": "^", "label": "TCP Established (Active)"},
        "socket_listening": {"color": "#38bdf8", "marker": "v", "label": "TCP Listening (Daemon)"},
        "socket_udp": {"color": "#14b8a6", "marker": "h", "label": "UDP Endpoint"}
    }

    for scat_name, meta in subcat_meta.items():
        mask = (nodes_df["subcategory"] == scat_name).values
        if not np.any(mask):
            continue
        xs = coords_x[mask]
        ys = coords_y[mask]
        degs = [total_degrees.get(i, 1) for i in np.where(mask)[0]]
        base_size = 55 if "process" in scat_name else (80 if "high_risk" in scat_name else 35)
        sizes = [min(base_size + d * 3, 160) for d in degs]
        
        ax.scatter(xs, ys, c=meta["color"], marker=meta["marker"], s=sizes,
                   alpha=0.88, edgecolors="#ffffff", linewidths=0.35, label=f"{meta['label']} ({sum(mask)})")

    # Annotate top process hubs
    top_proc = nodes_df[nodes_df["node_type"] == "process"].copy()
    top_proc["deg"] = [total_degrees.get(i, 0) for i in top_proc["node_idx"]]
    top_hubs = top_proc.sort_values(by="deg", ascending=False).head(16)

    for _, row in top_hubs.iterrows():
        i = int(row["node_idx"])
        ax.text(coords_x[i], coords_y[i] + 28, row["clean_label"],
                color="#f8fafc", fontsize=7.5, fontweight="bold",
                ha="center", va="bottom",
                bbox=dict(boxstyle="round,pad=0.25", facecolor="#1e293b", edgecolor="#475569", alpha=0.9))

    plt.title("Windows Host Forensics Homogeneous Graph\n(Differentiated Node Categories, Formulated Labels, Stable Layout)",
              color="#f8fafc", fontsize=15, fontweight="bold", pad=20)
    plt.legend(facecolor="#0f172a", edgecolor="#334155", labelcolor="#f8fafc",
               loc="upper right", fontsize=9, framealpha=0.9)
    plt.axis("off")
    plt.tight_layout()
    
    preview_img_path = os.path.join(output_dir, "homogeneous_graph_preview.png")
    plt.savefig(preview_img_path, facecolor="#080e1a", dpi=200)
    plt.close()
    print(f"[+] Saved refined preview: {preview_img_path}")

    # 10. Interactive HTML Visualization (Deterministic, Stable, No Repulsion Slider)
    print(f"[*] Building refined standalone interactive HTML view...")
    html_out_path = os.path.join(output_dir, "homogeneous_graph_view.html")
    
    vis_nodes = []
    for _, row in nodes_df.iterrows():
        idx = int(row["node_idx"])
        subcat = str(row["subcategory"])
        deg = int(total_degrees.get(idx, 0))
        color = str(row["color"])
        shape = str(row["shape"])
        
        # Sizing
        if "process" in subcat:
            size = min(max(deg * 2 + 12, 12), 32)
        elif "high_risk" in subcat:
            size = 14
        elif "memory" in subcat:
            size = 8
        else:
            size = 9

        tooltip = f"""
        <div style='font-family: Inter, sans-serif; font-size: 12px; line-height: 1.5; color: #f8fafc; min-width: 260px;'>
            <strong style='color: {color}; font-size: 13px;'>[{idx}] {row['display_name']}</strong><br/>
            <b>Category:</b> {subcat.replace('_', ' ').upper()}<br/>
            <b>Classification:</b> {row['risk_level']}<br/>
            <b>Node ID:</b> {row['node_id']}<br/>
            <b>PID:</b> {row['pid']}<br/>
            <b>Metric 1:</b> {row['metric_1']}<br/>
            <b>Metric 2:</b> {row['metric_2']}<br/>
            <b>Degree Centrality:</b> {deg} (In: {in_degrees.get(idx,0)}, Out: {out_degrees.get(idx,0)})<br/>
            <b>Extra:</b> {row['extra_info']}<br/>
            <hr style='border: 0; border-top: 1px solid #334155; margin: 6px 0;'/>
            <b>Feature Vector (16D):</b><br/>
            <code style='font-size: 10px; color: #94a3b8;'>{np.array2string(feature_matrix[idx], precision=2, separator=', ')}</code>
        </div>
        """
        
        vis_nodes.append({
            "id": idx,
            "label": str(row["clean_label"]) if (("process" in subcat and deg > 2) or ("high_risk" in subcat)) else "",
            "title": tooltip,
            "color": {"background": color, "border": "#ffffff", "highlight": {"background": "#ffffff", "border": color}},
            "size": size,
            "shape": shape,
            "x": float(row["pos_x"]),
            "y": float(row["pos_y"]),
            "node_type": str(row["node_type"]),
            "subcategory": subcat,
            "pid": int(row["pid"]) if pd.notnull(row["pid"]) else 0,
            "name": str(row["name"]),
            "clean_label": str(row["clean_label"]),
            "risk_level": str(row["risk_level"]),
            "degree": deg,
            "in_deg": int(in_degrees.get(idx, 0)),
            "out_deg": int(out_degrees.get(idx, 0)),
            "features": [round(float(val), 4) for val in feature_matrix[idx]]
        })

    vis_edges = []
    for e in valid_edges:
        rel = e["relationship"]
        c = rel_colors.get(rel, "#94a3b8")
        
        vis_edges.append({
            "from": int(e["source_idx"]),
            "to": int(e["target_idx"]),
            "color": {"color": c, "highlight": "#ffffff", "opacity": 0.55},
            "width": max(float(e["weight_normalized"]) * 2.2, 0.7),
            "arrows": "to",
            "title": f"<b>{rel}</b> (weight: {e['weight']:.2f})"
        })

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Host Telemetry Homogeneous Graph Viewer</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        body {{
            background-color: #080e1a;
            color: #f1f5f9;
            overflow: hidden;
            display: flex;
            height: 100vh;
            width: 100vw;
        }}
        #sidebar {{
            width: 380px;
            background: rgba(15, 23, 42, 0.96);
            backdrop-filter: blur(12px);
            border-right: 1px solid #1e293b;
            display: flex;
            flex-direction: column;
            z-index: 10;
            box-shadow: 4px 0 24px rgba(0,0,0,0.5);
        }}
        .header {{
            padding: 18px 20px;
            border-bottom: 1px solid #1e293b;
        }}
        .header h1 {{
            font-size: 16px;
            font-weight: 700;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 4px;
        }}
        .header p {{
            font-size: 12px;
            color: #94a3b8;
        }}
        .search-box {{
            padding: 14px 20px;
            border-bottom: 1px solid #1e293b;
        }}
        .search-input {{
            width: 100%;
            padding: 9px 12px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #f8fafc;
            font-size: 13px;
            outline: none;
            transition: all 0.2s;
        }}
        .search-input:focus {{
            border-color: #38bdf8;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
        }}
        .filter-group {{
            padding: 12px 20px;
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            border-bottom: 1px solid #1e293b;
        }}
        .filter-btn {{
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.2s;
        }}
        .btn-all {{ background: #334155; color: #f8fafc; }}
        .btn-sys {{ background: rgba(129, 140, 248, 0.18); color: #818cf8; border-color: rgba(129, 140, 248, 0.4); }}
        .btn-proc {{ background: rgba(0, 229, 255, 0.18); color: #00e5ff; border-color: rgba(0, 229, 255, 0.4); }}
        .btn-alert {{ background: rgba(244, 63, 94, 0.22); color: #f43f5e; border-color: rgba(244, 63, 94, 0.5); }}
        .btn-mem {{ background: rgba(245, 158, 11, 0.18); color: #f59e0b; border-color: rgba(245, 158, 11, 0.4); }}
        .btn-sock {{ background: rgba(16, 185, 129, 0.18); color: #10b981; border-color: rgba(16, 185, 129, 0.4); }}
        .filter-btn:hover {{ opacity: 0.85; transform: translateY(-1px); }}
        
        .controls {{
            padding: 12px 20px;
            border-bottom: 1px solid #1e293b;
            display: flex;
            gap: 8px;
        }}
        .btn-action {{
            flex: 1;
            padding: 8px 12px;
            border-radius: 6px;
            background: #2563eb;
            color: white;
            font-weight: 600;
            font-size: 11px;
            border: none;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn-action:hover {{ background: #1d4ed8; }}
        .btn-secondary {{ background: #334155; }}
        .btn-secondary:hover {{ background: #475569; }}
        
        .inspector {{
            flex: 1;
            padding: 18px 20px;
            overflow-y: auto;
        }}
        .inspector-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748b;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        .info-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 14px;
            font-size: 12px;
            line-height: 1.6;
        }}
        .info-card h3 {{
            font-size: 13.5px;
            margin-bottom: 6px;
            color: #38bdf8;
            word-break: break-all;
        }}
        .info-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: 0.02em;
        }}
        .risk-badge {{
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            background: #0f172a;
            color: #fbbf24;
            display: inline-block;
            margin-bottom: 8px;
        }}
        .tensor-table {{
            width: 100%;
            font-size: 10.5px;
            margin-top: 8px;
            border-collapse: collapse;
            background: #0f172a;
            border-radius: 4px;
            padding: 6px;
        }}
        .tensor-table td {{
            padding: 2px 6px;
            border-bottom: 1px solid #1e293b;
        }}

        #network-container {{
            flex: 1;
            height: 100%;
            position: relative;
        }}
        #network {{
            width: 100%;
            height: 100%;
        }}
        .legend-overlay {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(8px);
            border: 1px solid #334155;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 11px;
            color: #cbd5e1;
            box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            pointer-events: none;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 5px;
        }}
        .legend-item:last-child {{ margin-bottom: 0; }}
        .legend-marker {{
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }}
        .stats-overlay {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(8px);
            border: 1px solid #334155;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 11.5px;
            color: #94a3b8;
            pointer-events: none;
            display: flex;
            gap: 16px;
        }}
        .stats-item strong {{
            color: #f8fafc;
        }}
    </style>
</head>
<body>
    <div id="sidebar">
        <div class="header">
            <h1>Host Telemetry Homogeneous Graph</h1>
            <p>Unified 0-Indexed Topology & Forensics Inspector</p>
        </div>
        <div class="search-box">
            <input type="text" id="search-input" class="search-input" placeholder="Search PID, Process Name, Port, Service...">
        </div>
        <div class="filter-group">
            <button class="filter-btn btn-all" onclick="filterType('all')">All ({len(nodes_df)})</button>
            <button class="filter-btn btn-sys" onclick="filterType('system_process')">System (OS)</button>
            <button class="filter-btn btn-proc" onclick="filterType('user_process')">User Apps</button>
            <button class="filter-btn btn-alert" onclick="filterType('high_risk_memory')">High-Risk Mem</button>
            <button class="filter-btn btn-mem" onclick="filterType('normal_memory')">Unbacked Mem</button>
            <button class="filter-btn btn-sock" onclick="filterType('sockets')">Sockets</button>
        </div>
        <div class="controls">
            <button class="btn-action btn-secondary" onclick="network.fit({{animation: true}})">Fit View to Screen</button>
            <button class="btn-action btn-secondary" onclick="resetSelection()">Clear Filter</button>
        </div>
        <div class="inspector" id="inspector">
            <div class="inspector-title">Entity Telemetry & Feature Vector</div>
            <div class="info-card" id="inspector-content">
                <p style="color: #64748b;">Click on any node in the graph or search above to inspect its 16-dimensional normalized GNN feature vector, parent-child relations, and memory/socket forensics.</p>
            </div>
        </div>
    </div>

    <div id="network-container">
        <div id="network"></div>

        <div class="legend-overlay">
            <div style="font-weight:700; color:#f8fafc; margin-bottom:8px; font-size:11.5px;">Node Classification</div>
            <div class="legend-item"><div class="legend-marker" style="background:#818cf8; transform:rotate(45deg);"></div> System Core Process</div>
            <div class="legend-item"><div class="legend-marker" style="background:#00e5ff; border-radius:50%;"></div> User / App Process</div>
            <div class="legend-item"><div class="legend-marker" style="background:#f43f5e;"></div> High-Risk Mem (H &ge; 6.5 / RWX)</div>
            <div class="legend-item"><div class="legend-marker" style="background:#f59e0b;"></div> Unbacked Memory (H &lt; 6.5)</div>
            <div class="legend-item"><div class="legend-marker" style="background:#10b981; clip-path: polygon(50% 0%, 0% 100%, 100% 100%);"></div> TCP Established (Active)</div>
            <div class="legend-item"><div class="legend-marker" style="background:#38bdf8; clip-path: polygon(0% 0%, 100% 0%, 50% 100%);"></div> TCP Listening (Daemon)</div>
            <div class="legend-item"><div class="legend-marker" style="background:#14b8a6;"></div> UDP Socket</div>
        </div>

        <div class="stats-overlay">
            <div class="stats-item">Total Nodes: <strong>{len(nodes_df)}</strong></div>
            <div class="stats-item">Edges: <strong>{len(valid_edges)}</strong></div>
            <div class="stats-item">Features: <strong>16-D Tensor</strong></div>
            <div class="stats-item">Layout: <strong>Deterministic Static</strong></div>
        </div>
    </div>

    <script>
        const rawNodes = {json.dumps(vis_nodes)};
        const rawEdges = {json.dumps(vis_edges)};

        const nodesDataSet = new vis.DataSet(rawNodes);
        const edgesDataSet = new vis.DataSet(rawEdges);

        const container = document.getElementById('network');
        const data = {{ nodes: nodesDataSet, edges: edgesDataSet }};

        // Deterministic stable configuration: physics disabled after precalculated coordinates
        const options = {{
            nodes: {{
                font: {{ color: '#f8fafc', size: 10, face: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto' }},
                borderWidth: 1,
                borderWidthSelected: 2.5
            }},
            edges: {{
                smooth: {{ type: 'continuous', roundness: 0.15 }}
            }},
            physics: {{
                enabled: false  // Fully deterministic static layout; no dynamic repulsion or jitter
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 100,
                hideEdgesOnDrag: false
            }}
        }};

        const network = new vis.Network(container, data, options);

        // Selection Inspector
        network.on('click', function(params) {{
            if (params.nodes.length > 0) {{
                const nodeId = params.nodes[0];
                const nodeData = rawNodes.find(n => n.id === nodeId);
                if (nodeData) {{
                    inspectNode(nodeData);
                }}
            }}
        }});

        function inspectNode(node) {{
            const badgeColor = node.color.background;
            
            const featureLabels = [
                "feat_is_proc", "feat_is_mem", "feat_is_sock",
                "feat_threads_norm", "feat_modules_norm", "feat_is_system",
                "feat_entropy_norm", "feat_size_norm", "feat_is_rwx",
                "feat_port_norm", "feat_is_listening", "feat_is_established",
                "feat_in_deg_norm", "feat_out_deg_norm", "feat_tot_deg_norm", "feat_weighted_deg_norm"
            ];
            
            let featureRows = "";
            node.features.forEach((f, i) => {{
                featureRows += `<tr><td style="color:#94a3b8;">${{featureLabels[i]}}</td><td style="text-align:right; color:#38bdf8; font-weight:700;">${{f.toFixed(3)}}</td></tr>`;
            }});

            document.getElementById('inspector-content').innerHTML = `
                <div class="info-badge" style="background: rgba(255,255,255,0.1); color: ${{badgeColor}}; border: 1px solid ${{badgeColor}};">${{node.subcategory.replace('_', ' ').toUpperCase()}}</div>
                <div class="risk-badge">${{node.risk_level}}</div>
                <h3>[Index ${{node.id}}] ${{node.clean_label}}</h3>
                <p><b>PID:</b> ${{node.pid}}</p>
                <p><b>Name:</b> ${{node.name}}</p>
                <p><b>Degree:</b> ${{node.degree}} (In: ${{node.in_deg}}, Out: ${{node.out_deg}})</p>
                <p><b>Static Coords:</b> (${{node.x}}, ${{node.y}})</p>
                <div style="margin-top: 10px;">
                    <b style="color: #cbd5e1;">Normalized 16D Feature Tensor:</b>
                    <table class="tensor-table">
                        ${{featureRows}}
                    </table>
                </div>
            `;
        }}

        // Search Filter
        document.getElementById('search-input').addEventListener('input', function(e) {{
            const query = e.target.value.toLowerCase().trim();
            if (!query) return;
            const match = rawNodes.find(n => 
                n.id.toString() === query ||
                n.name.toLowerCase().includes(query) ||
                n.clean_label.toLowerCase().includes(query) ||
                n.pid.toString() === query
            );
            if (match) {{
                network.selectNodes([match.id]);
                network.focus(match.id, {{ scale: 1.3, animation: true }});
                inspectNode(match);
            }}
        }});

        // Entity Type Filter
        function filterType(type) {{
            if (type === 'all') {{
                nodesDataSet.update(rawNodes.map(n => ({{ id: n.id, hidden: false }})));
            }} else if (type === 'sockets') {{
                nodesDataSet.update(rawNodes.map(n => ({{ id: n.id, hidden: !n.subcategory.startsWith('socket') }})));
            }} else {{
                nodesDataSet.update(rawNodes.map(n => ({{ id: n.id, hidden: n.subcategory !== type }})));
            }}
            network.fit({{animation: true}});
        }}

        function resetSelection() {{
            filterType('all');
            document.getElementById('search-input').value = '';
        }}
    </script>
</body>
</html>
"""
    with open(html_out_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Saved refined interactive HTML viewer: {html_out_path}")

    print("=" * 75)
    print("  HOMOGENEOUS GRAPH CONVERSION COMPLETED SUCCESSFULLY")
    print("=" * 75)

if __name__ == "__main__":
    generate_homogeneous_graph()
