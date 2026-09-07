from collections import deque
from statistics import mean, pstdev
class ThresholdEngine:
    def __init__(self, window=30, sensitivity=2.5): self.history=deque(maxlen=window); self.sensitivity=sensitivity
    def evaluate(self, value):
        baseline=mean(self.history) if self.history else value
        std=pstdev(self.history) if len(self.history)>1 else max(baseline*.1,1)
        threshold=baseline+self.sensitivity*std
        ratio=value/max(baseline,1)
        flagged=value>threshold and len(self.history)>=3
        self.history.append(float(value))
        return {'value':value,'baseline':baseline,'std':std,'threshold':threshold,'ratio':ratio,'flagged':flagged}
