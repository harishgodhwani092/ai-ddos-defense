# AI-Based Real-Time DDoS Detection and Mitigation System

A defensive, modular academic project combining rolling adaptive thresholds with a persisted Random Forest classifier. The default demonstration uses synthetic **traffic metrics**, not attack packets. Mitigation defaults to simulation/dry-run and the allowlist is checked before every block.

## Run the safe demonstration
```bash
cd ddos-ai-defense
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python ml/train.py
PYTHONPATH=. uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000, then Start monitoring and Run safe simulation
```
The model metrics are written beside the model as `.metrics.json`; no accuracy is invented. If no model exists, the API remains usable but marks ML as unavailable and uses the threshold safety path.

## Architecture
`simulation or packet adapter -> FeatureExtractor -> ThresholdEngine + MLDetector -> decision_engine -> FirewallManager -> SQLite -> REST/WebSocket dashboard`.

The current runnable system includes a real Scapy metadata-only packet-capture adapter, aggregation-window processing, SQLite audit records, WebSocket telemetry, adaptive baseline, explainable decisions, persisted model inference, allowlist protection, dry-run mitigation, and a responsive dashboard. `POST /api/monitoring/start` captures actual packets from the configured interface; `POST /api/simulation/start` is only an optional safe demonstration path. Raw packet payloads are never stored.

## Dataset training
`ml/train.py --csv data/processed/your_features.csv --out models/cic_random_forest.joblib` expects a `label` column and the feature names in `backend/app/capture/feature_extractor.py`; missing features are filled with zero for transparent experimentation. Use a documented dataset license and split by time/source where appropriate to avoid leakage.

## Safety and limitations
The included firewall manager intentionally has only a simulation adapter. Do not connect it to production interfaces. Extend it with a reviewed Linux nftables or Windows adapter only in an isolated lab, keep dry-run enabled, add authentication, and test allowlist behavior. Live Scapy capture is not enabled in the demo because raw capture requires platform privileges and interface-specific handling. No real-world accuracy is claimed; train and report metrics for the chosen dataset.

## API
`GET /api/status`, `/api/detections`, `/api/mitigations`, `/api/statistics`; `POST /api/monitoring/start`, `/stop`, `/api/simulation/start`, `/api/mitigation/enable`, `/disable`; WebSocket `/ws`.

## Academic extension checklist
Add SQLAlchemy migrations, admin authentication, CIC preprocessing mappings, a live metadata-only Scapy adapter, precision/recall reports and confusion matrices in the UI, pytest coverage, and a reviewed OS-specific firewall adapter. Keep simulation as the presentation path.
