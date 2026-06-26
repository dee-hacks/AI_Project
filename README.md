# NetSentinel — AI-Powered Network Anomaly Detection

NetSentinel is a real-time network anomaly detection system that captures network packets, extracts 128-dimensional feature vectors, and uses a hybrid AI ensemble (Autoencoder + Isolation Forest) to detect malicious traffic patterns, network intrusions, and anomalous behavior.

---

## How the Application Works (End-to-End Flow)

```
                         ┌─────────────────────────────────────────────┐
                         │        1. PACKET CAPTURE                   │
                         │  Scapy AsyncSniffer listens on interface   │
                         │  BPF filter (default: "ip")                │
                         │  Parses: IP, TCP, UDP, ICMP, Ethernet     │
                         └──────────────────┬──────────────────────────┘
                                            │ parsed packet dict
                                            ▼
                         ┌─────────────────────────────────────────────┐
                         │        2. FEATURE EXTRACTION               │
                         │  ┌─────────────────────────────────────┐   │
                         │  │ Per-packet (32 dims)                │   │
                         │  │ protocol, IP hash, ports, TTL,      │   │
                         │  │ packet length, flags, entropy       │   │
                         │  └─────────────────────────────────────┘   │
                         │  ┌─────────────────────────────────────┐   │
                         │  │ Flow-level (32 dims)                │   │
                         │  │ sliding window: packet count,       │   │
                         │  │ byte rate, burst count, port entropy│   │
                         │  └─────────────────────────────────────┘   │
                         │  ┌─────────────────────────────────────┐   │
                         │  │ Derived + Interaction (64 dims)     │   │
                         │  │ ratios, products of key metrics     │   │
                         │  └─────────────────────────────────────┘   │
                         │  Total: 128-dim feature vector            │
                         └──────────────────┬──────────────────────────┘
                                            │ feature matrix (batch)
                                            ▼
                         ┌─────────────────────────────────────────────┐
                         │        3. AI DETECTION ENGINE              │
                         │                                            │
                         │  ┌──────────────────┐  ┌────────────────┐  │
                         │  │ AUTOENCODER      │  │ ISOLATION      │  │
                         │  │ (PyTorch)        │  │ FOREST         │  │
                         │  │ 128→64→32→16→    │  │ (scikit-learn) │  │
                         │  │ 32→64→128        │  │ Sparse outlier  │  │
                         │  │ Reconstruction   │  │ detection       │  │
                         │  │ Error → score    │  │ → score         │  │
                         │  └────────┬─────────┘  └────────┬───────┘  │
                         │           └──────────┬──────────┘          │
                         │                      ▼                     │
                         │           ┌──────────────────┐             │
                         │           │ ENSEMBLE         │             │
                         │           │ 0.6*AE + 0.4*IF  │             │
                         │           │ Score > threshold│             │
                         │           │ → ANOMALY!       │             │
                         │           └──────────────────┘             │
                         └──────────────────┬──────────────────────────┘
                                            │ anomaly alert
                                            ▼
                         ┌─────────────────────────────────────────────┐
                         │        4. STORE & BROADCAST                │
                         │                                            │
                         │  ┌──────────────────┐  ┌────────────────┐  │
                         │  │ MongoDB          │  │ Redis Pub/Sub  │  │
                         │  │ Stores: events,   │  │ Publishes      │  │
                         │  │ topology, config  │  │ alerts to      │  │
                         │  │                  │  │ "alerts" channel│  │
                         │  └──────────────────┘  └────────┬───────┘  │
                         └──────────────────────────────────┼─────────┘
                                                            │
                         ┌──────────────────────────────────┼─────────┐
                         │        5. API & UI               │         │
                         │                                  ▼         │
                         │  ┌────────────────────────────────────┐    │
                         │  │ FastAPI REST + WebSocket           │    │
                         │  │ - /api/v1/events (list alerts)     │    │
                         │  │ - /ws/v1/alerts (real-time push)   │    │
                         │  │ - /api/v1/topology (network map)   │    │
                         │  │ - /api/v1/config (settings)        │    │
                         │  └────────────┬───────────────────────┘    │
                         │               │                            │
                         │  ┌────────────▼───────────────────────┐    │
                         │  │ Web UI (Vite + D3.js + vanilla JS)  │    │
                         │  │                                     │    │
                         │  │ ┌──────────┐ ┌──────────┐          │    │
                         │  │ │ Topology │ │ Timeline │          │    │
                         │  │ │ Graph    │ │ Sparkline│          │    │
                         │  │ │(D3 force │ │(D3 area  │          │    │
                         │  │ │ directed)│ │  chart)  │          │    │
                         │  │ └──────────┘ └──────────┘          │    │
                         │  │ ┌──────────┐ ┌──────────┐          │    │
                         │  │ │ Dashboard│ │ Alert    │          │    │
                         │  │ │ Stats    │ │ Table    │          │    │
                         │  │ └──────────┘ └──────────┘          │    │
                         │  └─────────────────────────────────────┘    │
                         └────────────────────────────────────────────┘
```

---

## Architecture & Component Details

### 1. Packet Capture Layer (`src/capture/`)

**Files:**
- `sniffer.py` — Scapy `AsyncSniffer` that listens on a network interface
- `packet_parser.py` — Parses raw packets into structured dictionaries
- `kafka_consumer.py` — Alternative packet source for multi-host deployments

**How it works:**
The sniffer applies a BPF filter (default: `"ip"`) to only capture IP packets. Each packet is parsed to extract:
- IP layer: src/dst IP, TTL, packet length, fragmentation info
- TCP layer: src/dst port, flags, window size, sequence numbers, options
- UDP layer: src/dst port, UDP length
- ICMP layer: type, code
- Ethernet: src/dst MAC addresses
- Payload: Shannon entropy computation

The sniffer uses an `asyncio.Queue` to bridge Scapy's synchronous callback to Python's async world, supporting 50K+ packets per second on modern hardware.

### 2. Feature Extraction Pipeline (`src/features/`)

**Files:**
- `per_packet.py` — 32 features per packet (protocol, ports, TTL, length, entropy, flags, etc.)
- `flow_features.py` — 32 features from sliding time window (1-second default)
- `normalizer.py` — Z-score or MinMax scaling
- `extractor.py` — Orchestrator that builds the full 128-dim vector

**The 128-Dimensional Feature Vector:**

| Segment | Dimensions | What it captures |
|---------|-----------|------------------|
| Per-packet | 0–31 | Protocol, IP hash, ports, packet length (log-scaled), TTL, payload entropy, TCP flags, window size, IP ID, flags |
| Flow-level | 32–63 | Packet count in window, byte count, port entropy, flow duration, packet rate, byte rate, avg/std packet size, SYN/ACK ratio, inter-arrival stats, burst count |
| Derived | 64–95 | Ratios: throughput efficiency, bytes-per-packet, TTL-per-rate, bandwidth estimate, SYN/ACK ratio, jitter ratio, burst ratio |
| Interaction | 96–127 | Pairwise products: protocol×src hash, ports, pkt_len×TTL, entropy×window, count×duration, src hash×duration, etc. |

Features are normalized using Z-score (fitted on training data) before being fed to the AI models.

### 3. AI Detection Engine (`src/ai/`)

**Files:**
- `autoencoder.py` — PyTorch deep autoencoder (128→64→32→16→32→64→128)
- `isolation_forest.py` — scikit-learn IsolationForest wrapper
- `ensemble.py` — Weighted voting: 0.6 * AE + 0.4 * IF
- `threshold.py` — p99.98 percentile threshold computation
- `trainer.py` — Offline training pipeline

**Autoencoder:**
The autoencoder learns to reconstruct normal traffic patterns. Anomalies that don't match normal patterns will have high reconstruction error (MSE). The architecture is symmetric with batch normalization and dropout for regularization.

**Isolation Forest:**
Randomly partitions the feature space to isolate outliers. Anomalies require fewer partitions to isolate, resulting in higher anomaly scores.

**Ensemble:**
```
ensemble_score = 0.6 * normalize(AE_MSE) + 0.4 * normalize(IF_score)
anomaly = ensemble_score > threshold (p99.98)
```

**Training:**
```bash
python scripts/train.py --generate-synthetic --samples 10000
```
This generates synthetic normal traffic (HTTP, DNS, internal clusters), splits 80/20, trains both models, computes the threshold on validation data, and saves all artifacts to `data/models/`.

### 4. Processor Pipeline (`src/processor/`)

**Files:**
- `pipeline.py` — Orchestrates capture → features → AI → store → alert
- `event_bus.py` — Redis Pub/Sub for real-time messaging
- `alert_builder.py` — Enriches anomalies with metadata and severity

**Pipeline flow:**
1. Packets are buffered until either 256 packets OR 150ms elapsed
2. The batch is converted to a feature matrix (128-dim vectors)
3. The ensemble predicts which packets are anomalous
4. Anomalies are enriched into structured alerts with:
   - Severity classification (low/medium/high/critical based on score/threshold ratio)
   - Flow key, feature vector sample, original packet metadata
5. Alerts are bulk-inserted to MongoDB
6. Alerts are published to Redis Pub/Sub channel "alerts"

### 5. Database Layer (`src/db/`)

**Files:**
- `mongodb.py` — Async Motor client with connection pooling
- `repositories.py` — CRUD for events, topology, config

**MongoDB Collections:**
| Collection | Purpose | Key Indexes |
|-----------|---------|-------------|
| `anomaly_events` | All detected anomalies | `timestamp`, `severity`, `(src_ip, timestamp)` |
| `network_topology` | Discovered network nodes | `ip` (unique), `last_seen` |
| `app_config` | Application settings | `key` |

### 6. Topology Discovery (`src/topology/`)

**Files:**
- `discoverer.py` — ARP scanning + passive observation
- `graph.py` — NetworkX → D3.js JSON conversion

**How it works:**
- **Active scanning:** Sends ARP requests to configured subnets (e.g., `192.168.1.0/24`)
- **Passive observation:** Learns IP-MAC pairs from every parsed packet
- **Vendor lookup:** Maps MAC OUI prefixes to vendors (VMware, Cisco, Raspberry Pi, etc.)
- **Graph building:** Infers subnet links and converts to D3.js force-directed layout JSON

### 7. API Layer (`src/api/`)

**Files:**
- `app.py` — FastAPI factory with CORS, lifespan, health check
- `routers/events.py` — `GET /api/v1/events`, `GET /events/{id}`, `GET /events/stats/summary`, `POST /events/{id}/acknowledge`
- `routers/alerts.py` — `GET /api/v1/alerts`, `GET /alerts/recent`, `WS /ws/v1/alerts` (WebSocket)
- `routers/topology.py` — `GET /api/v1/topology`, `GET /topology/nodes`, `GET /topology/compromised`, `POST /topology/scan`
- `routers/config.py` — `GET/PUT /api/v1/config/{key}`
- `middleware.py` — Rate limiting, security headers
- `dependencies.py` — Singleton injection for DB, event bus, models

**WebSocket Real-Time Alerts:**
The WebSocket endpoint at `/ws/v1/alerts` subscribes to Redis Pub/Sub and forwards every alert to connected browsers. Includes automatic reconnection and keep-alive ping/pong.

### 8. Frontend UI (`src/ui/`)

**Files:**
- `index.html` — Main HTML structure with dashboard layout
- `styles.css` — Dark-themed cyber UI design
- `main.js` — Entry point that initializes all components
- `hooks/useWebSocket.js` — Auto-reconnecting WebSocket client
- `hooks/useTopology.js` — Polling-based topology fetcher
- `store/store.js` — Reactive state management (Zustand-like pattern)
- `utils/d3Layout.js` — D3.js force-directed graph + timeline rendering

**UI Components:**

| Component | What it shows |
|-----------|---------------|
| **Topology Graph** | D3.js force-directed network map. Nodes = devices (IP/hostname). Colors: blue=normal, orange=anomalous, red=compromised. Draggable, zoomable, tooltips |
| **Anomaly Timeline** | D3.js sparkline with area fill showing anomaly scores over time |
| **Dashboard Stats** | Total events, active alerts, discovered nodes, uptime |
| **Alert Table** | Sortable, filterable table with time, severity badge, src/dst IP:port, protocol, score, status |
| **Filters** | Severity dropdown and IP search box for alert filtering |

---

## Data Flow Diagram (Detailed)

```
                    ┌──────────────┐
                    │  Network     │
                    │  Interface   │
                    └──────┬───────┘
                           │ raw packets
                           ▼
                    ┌──────────────┐
                    │  AsyncSniffer│
                    │  (Scapy)     │
                    └──────┬───────┘
                           │ parsed packet dict
                           ▼
                    ┌──────────────┐      ┌──────────────┐
                    │  Pipeline    │─────▶│  Buffer      │
                    │  Buffer      │      │  (256 pkts   │
                    │  (256 pkts   │      │    OR 150ms)  │
                    │    OR 150ms)  │      └──────┬───────┘
                    └──────┬───────┘             │
                           │ batch               │ batch
                           ▼                     ▼
                    ┌──────────────────────────────────────────────┐
                    │           Feature Extraction                 │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
                    │  │Per-packet│  │   Flow   │  │ Derived+ │   │
                    │  │  32-dim  │  │  32-dim  │  │  64-dim  │   │
                    │  └──────────┘  └──────────┘  └──────────┘   │
                    │            128-dim feature matrix            │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │           AI Ensemble                        │
                    │  ┌────────────────┐  ┌──────────────────┐    │
                    │  │ Autoencoder    │  │ Isolation Forest  │    │
                    │  │ (Reconstruct)  │  │ (Score samples)   │    │
                    │  └───────┬────────┘  └────────┬─────────┘    │
                    │          │                     │              │
                    │          └─────────┬───────────┘              │
                    │                    ▼                          │
                    │          ┌──────────────────┐                 │
                    │          │  Weighted Avg    │                 │
                    │          │  Score > p99.98  │                 │
                    │          └────────┬─────────┘                 │
                    └───────────────────┼───────────────────────────┘
                                        │ is_anomaly? yes
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │         Alert Builder                        │
                    │  - Classify severity (score/threshold ratio) │
                    │  - Add flow key, feature sample              │
                    │  - Add timestamp, packet metadata            │
                    └───────────────────┬──────────────────────────┘
                                        │ 2 operations
                                        ├────────────────────┐
                                        ▼                    ▼
                              ┌──────────────────┐   ┌──────────────────┐
                              │   MongoDB         │   │  Redis Pub/Sub  │
                              │ (anomaly_events)  │   │  "alerts"       │
                              └──────────────────┘   └────────┬─────────┘
                                                               │
                                                               ▼
                                                    ┌──────────────────┐
                                                    │  FastAPI         │
                                                    │  WebSocket (/ws) │
                                                    └────────┬─────────┘
                                                             │
                                                             ▼
                                                    ┌──────────────────┐
                                                    │  Browser UI      │
                                                    │  (D3.js +        │
                                                    │   Vanilla JS)    │
                                                    └──────────────────┘
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Real-time capture** | Scapy AsyncSniffer with BPF filter, 50K+ pps on 4 cores |
| **128-dim features** | Per-packet + sliding window flow + derived + interaction features |
| **Hybrid AI ensemble** | Autoencoder (deep) + Isolation Forest (sparse), 0.6/0.4 weighted voting |
| **Batch processing** | 256 packets or 150ms flush interval for inference efficiency |
| **WebSocket alerts** | Redis Pub/Sub → FastAPI WebSocket → browser push |
| **D3.js topology** | Force-directed graph with zoom, drag, compromised node highlighting |
| **Severity classification** | Low/Medium/High/Critical based on score-to-threshold ratio |
| **Multi-source capture** | Direct Scapy or Kafka consumer for multi-host deployments |
| **Docker Compose** | One-command deployment with MongoDB, Redis, Kafka, Kafka UI |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+ (for UI development)
- Docker Desktop (for MongoDB, Redis, Kafka infrastructure)

### Installation & Running

**Important:** On Windows, always use quotes around paths containing `&`:
```powershell
cd "d:\AI_&_ML_Project\netsentinel"
```

#### Step 1: Python setup
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements\dev.txt
```

#### Step 2: Train AI models
```powershell
python scripts\train.py --generate-synthetic --samples 10000
```

#### Step 3: Start infrastructure (Docker Desktop required)
```powershell
docker compose up -d mongodb redis
```

#### Step 4: Start the API server
```powershell
uvicorn src.api.app:create_app --reload --factory --host 0.0.0.0 --port 8000
```

#### Step 5: Start the UI (new terminal)
```powershell
cd "d:\AI_&_ML_Project\netsentinel\src\ui"
npm install
node node_modules/vite/bin/vite.js --host 0.0.0.0
```

### Access the Application

| URL | Description |
|-----|-------------|
| http://localhost:5173 | NetSentinel Dashboard (topology, timeline, alerts) |
| http://localhost:8000/docs | Swagger API Documentation |
| http://localhost:8000/redoc | ReDoc API Documentation |
| http://localhost:8000/health | Health check endpoint |

### Running Tests
```powershell
pytest src\tests\ -v
```

### Running Benchmark
```powershell
python scripts\benchmark.py --num-packets 10000
```

---

## API Endpoints

### Events
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/events` | List events (paginated, filterable by severity/IP) |
| `GET` | `/api/v1/events/{id}` | Get single event |
| `GET` | `/api/v1/events/stats/summary` | Event statistics (total, high, critical, recent) |
| `POST` | `/api/v1/events/{id}/acknowledge` | Mark event as acknowledged |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/alerts` | List alerts (paginated, filterable) |
| `GET` | `/api/v1/alerts/recent?seconds=300` | Recent alerts (default last 5 min) |
| `WS` | `/ws/v1/alerts` | Real-time WebSocket alert stream |

### Topology
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/topology` | Full topology as D3.js force-directed JSON |
| `GET` | `/api/v1/topology/nodes` | List all discovered nodes |
| `GET` | `/api/v1/topology/nodes/{ip}` | Get single node by IP |
| `GET` | `/api/v1/topology/compromised` | List compromised nodes |
| `POST` | `/api/v1/topology/scan` | Trigger ARP scan |

### Configuration
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/config` | Get all configuration |
| `GET` | `/api/v1/config/{key}` | Get specific config value |
| `PUT` | `/api/v1/config/{key}` | Update config value |

---

## Project Structure

```
netsentinel/
├── README.md                  # This file
├── LICENSE                    # MIT License
├── docker-compose.yml         # Full stack: API + MongoDB + Redis + Kafka + Kafka UI
├── Dockerfile                 # Python 3.11 container
├── .env.example               # Environment variables template
├── .gitignore
│
├── config/
│   ├── default.yaml           # Default settings (all components)
│   └── production.yaml        # Production overrides (env vars)
│
├── requirements/
│   ├── base.txt               # Core: fastapi, torch, scapy, numpy, scikit-learn...
│   ├── dev.txt                # + pytest, flake8, mypy, black...
│   └── prod.txt               # + gunicorn
│
├── scripts/
│   ├── train.py               # Offline model training (with synthetic data generator)
│   ├── benchmark.py           # Throughput/latency measurement
│   ├── seed_topology.py       # Generate fake topology data
│   └── generate_pcap_fixture.py  # Create sample .pcap files
│
├── src/
│   ├── __init__.py
│   │
│   ├── capture/
│   │   ├── packet_parser.py   # Raw bytes → structured dict
│   │   ├── sniffer.py         # AsyncScapy sniffer with BPF filter
│   │   └── kafka_consumer.py  # Kafka packet source
│   │
│   ├── features/
│   │   ├── per_packet.py      # 32 per-packet features
│   │   ├── flow_features.py   # 32 sliding window flow features
│   │   ├── normalizer.py      # Z-score / MinMax scaler
│   │   └── extractor.py       # 128-dim orchestrator
│   │
│   ├── ai/
│   │   ├── autoencoder.py     # PyTorch autoencoder (128→16→128)
│   │   ├── isolation_forest.py # scikit-learn wrapper
│   │   ├── ensemble.py        # Weighted voting (0.6 AE + 0.4 IF)
│   │   ├── threshold.py       # p99.98 percentile threshold
│   │   └── trainer.py         # Full training pipeline
│   │
│   ├── processor/
│   │   ├── pipeline.py        # Capture→Features→AI→Store→Alert
│   │   ├── event_bus.py       # Redis Pub/Sub
│   │   └── alert_builder.py   # Enrich anomalies with metadata
│   │
│   ├── db/
│   │   ├── mongodb.py         # Async Motor client
│   │   └── repositories.py    # CRUD for events, topology, config
│   │
│   ├── topology/
│   │   ├── discoverer.py      # ARP scan + passive observation
│   │   └── graph.py           # NetworkX → D3.js JSON
│   │
│   ├── api/
│   │   ├── app.py             # FastAPI factory
│   │   ├── dependencies.py    # Singleton injection
│   │   ├── middleware.py      # Rate limiting, security headers
│   │   └── routers/
│   │       ├── events.py      # Event CRUD endpoints
│   │       ├── alerts.py      # Alert + WebSocket endpoints
│   │       ├── topology.py    # Topology endpoints
│   │       └── config.py      # Configuration endpoints
│   │
│   ├── ui/
│   │   ├── index.html         # Main HTML (dashboard layout)
│   │   ├── package.json       # Vite + D3.js dependencies
│   │   ├── vite.config.js     # Vite config with API proxy
│   │   ├── public/
│   │   │   └── favicon.svg
│   │   └── src/
│   │       ├── main.js        # Entry point (initializes all components)
│   │       ├── styles.css     # Dark theme cyber UI
│   │       ├── hooks/
│   │       │   ├── useWebSocket.js  # Auto-reconnecting WebSocket
│   │       │   └── useTopology.js   # Polling topology fetcher
│   │       ├── store/
│   │       │   └── store.js   # Reactive state management
│   │       ├── utils/
│   │       │   └── d3Layout.js  # D3 force-directed graph + timeline
│   │       └── components/
│   │           # Components are rendered directly from main.js
│   │
│   └── tests/
│       ├── conftest.py        # Pytest fixtures (sample packets, features)
│       ├── test_capture.py    # Packet parsing tests
│       ├── test_features.py   # Feature extraction tests
│       ├── test_ai.py         # AI model tests (autoencoder, IF, ensemble)
│       ├── test_processor.py  # Alert builder tests
│       └── fixtures/
│           └── sample_packets.pcap  # Generated test data
│
└── data/
    └── benchmarks/            # Benchmark results directory
```

---

## Configuration

All configuration is in `config/default.yaml` with environment variable overrides in `config/production.yaml`.

Key settings:
```yaml
capture:
  interface: "eth0"         # Network interface to sniff
  bpf_filter: "ip"          # BPF filter string
  buffer_size: 256          # Batch size for inference
  flush_interval_ms: 150    # Max latency before flush

ai:
  threshold_percentile: 99.98  # Anomaly threshold
  ensemble:
    ae_weight: 0.6             # Autoencoder weight
    if_weight: 0.4             # Isolation Forest weight

features:
  sliding_window_sec: 1.0   # Flow analysis window
  input_dim: 128             # Feature vector dimension
```

---

## Troubleshooting

### Windows path with `&` character
If your project path contains `&` (like `AI_&_ML_Project`), PowerShell treats it as a special character. Always wrap paths in double quotes:
```powershell
cd "d:\AI_&_ML_Project\netsentinel"
```

### npm/vite not found
The `&` in the path can break npm's `.cmd` file resolution. Use:
```powershell
cd "d:\AI_&_ML_Project\netsentinel\src\ui"
node node_modules/vite/bin/vite.js --host 0.0.0.0
```

### MongoDB not connecting
Ensure Docker Desktop is running. Start services:
```powershell
docker compose up -d mongodb redis
```

### torch install issues
If torch fails to install, try the CPU-only version:
```powershell
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

---

## License

MIT
