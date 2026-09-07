from datetime import datetime, timedelta, timezone
class SimulationFirewallAdapter:
    def __init__(self): self.blocks={}
    def block(self,ip,duration,reason): self.blocks[ip]={'expires_at':(datetime.now(timezone.utc)+timedelta(seconds=duration)).isoformat(),'reason':reason,'status':'SIMULATED'}; return self.blocks[ip]
    def unblock(self,ip): return self.blocks.pop(ip,None) is not None
    def expire(self):
        now=datetime.now(timezone.utc); out=[]
        for ip,v in list(self.blocks.items()):
            if datetime.fromisoformat(v['expires_at'])<=now: out.append(ip); del self.blocks[ip]
        return out
class FirewallManager:
    def __init__(self,settings): self.settings=settings; self.adapter=SimulationFirewallAdapter()
    def block(self,ip,reason):
        if self.settings.protected(ip): return {'status':'REJECTED_ALLOWLIST','ip':ip}
        if not self.settings.mitigation_enabled or self.settings.dry_run: return {'status':'SIMULATED','ip':ip,'expires_at':self.adapter.block(ip,self.settings.block_duration,reason)['expires_at']}
        return {'status':'DISABLED_UNSAFE_ADAPTER','ip':ip}
    def unblock(self,ip): return self.adapter.unblock(ip)
