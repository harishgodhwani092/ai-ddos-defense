import asyncio, random
class Simulation:
 def __init__(self,callback): self.callback=callback; self.running=False; self.task=None; self.step=0
 async def run(self):
  rates=[100,130,180,250,400,700,1200,900,500,180]
  for rate in rates:
   if not self.running: break
   await self.callback(rate); await asyncio.sleep(1)
  self.running=False
 def start(self):
  if not self.running: self.running=True; self.task=asyncio.create_task(self.run())
 def stop(self): self.running=False
