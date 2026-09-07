from dataclasses import dataclass, field
import os, ipaddress

@dataclass
class Settings:
    db_path: str = os.getenv('DB_PATH','ddos_ai.db')
    model_path: str = os.getenv('MODEL_PATH','models/demo_random_forest.joblib')
    interface: str = os.getenv('CAPTURE_INTERFACE','auto')
    interval: float = float(os.getenv('MONITORING_INTERVAL','2'))
    threshold_window: int = int(os.getenv('THRESHOLD_WINDOW','30'))
    sensitivity: float = float(os.getenv('THRESHOLD_SENSITIVITY','2.5'))
    ml_confidence: float = float(os.getenv('ML_CONFIDENCE_THRESHOLD','0.70'))
    mitigation_enabled: bool = os.getenv('MITIGATION_ENABLED','false').lower() == 'true'
    dry_run: bool = os.getenv('MITIGATION_DRY_RUN','true').lower() != 'false'
    block_duration: int = int(os.getenv('BLOCK_DURATION','300'))
    simulation_mode: bool = os.getenv('SIMULATION_MODE','false').lower() == 'true'
    allowlist: list[str] = field(default_factory=lambda: [x.strip() for x in os.getenv('ALLOWLIST','127.0.0.1,::1,10.0.0.1').split(',') if x.strip()])

    def protected(self, ip: str) -> bool:
        try:
            addr=ipaddress.ip_address(ip)
            return any(addr == ipaddress.ip_address(x) or addr in ipaddress.ip_network(x, strict=False) for x in self.allowlist)
        except ValueError: return True
settings=Settings()
