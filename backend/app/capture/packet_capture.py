"""Metadata-only live packet capture.

Requires administrative capture privileges and Scapy/Npcap on the host. It never
stores payloads. Packets are aggregated into short windows before detection.
"""
import threading, time
from datetime import datetime, timezone
from collections import Counter
try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
except Exception:
    AsyncSniffer = None

class PacketCapture:
    def __init__(self, interface, interval, on_window):
        self.interface = None if interface in ('auto', '', None) else interface
        self.interval = interval
        self.on_window = on_window
        self._stop = threading.Event()
        self._thread = None
        self._sniffer = None
        self._records = []
        self._lock = threading.Lock()
        self.error = None

    def _packet(self, pkt):
        if IP not in pkt:
            return
        protocol='TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP' if ICMP in pkt else 'OTHER'
        transport=pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        flags=str(transport.flags) if TCP in pkt else ''
        self._records.append({'timestamp':datetime.now(timezone.utc).isoformat(), 'source_ip':pkt[IP].src, 'destination_ip':pkt[IP].dst, 'source_port':getattr(transport,'sport',None), 'destination_port':getattr(transport,'dport',None), 'protocol':protocol, 'size':len(pkt), 'flags':flags})

    def _run(self):
        try:
            if AsyncSniffer is None: raise RuntimeError('Scapy is not installed')
            self._sniffer=AsyncSniffer(iface=self.interface, prn=self._packet, store=False)
            self._sniffer.start()
            while not self._stop.wait(self.interval):
                with self._lock:
                    window, self._records = self._records, []
                if window: self.on_window(window, self.interval)
            self._sniffer.stop()
        except Exception as exc:
            self.error=str(exc)
            self._stop.set()

    def start(self):
        if self._thread and self._thread.is_alive(): return
        self._stop.clear(); self.error=None; self._thread=threading.Thread(target=self._run,daemon=True); self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread: self._thread.join(timeout=max(2,self.interval+1))
        self._thread=None
