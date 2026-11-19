import random, subprocess, math, sys
random.seed(7)
pings = int(sys.argv[1]); days = float(sys.argv[2]); out = sys.argv[3]; rras = sys.argv[4:]
step = 300
end = 1763510400 + 4*86400  # 2025-11-23T00:00Z
start = int(end - days*86400)
ds = ["DS:uptime:GAUGE:600:0:U", f"DS:loss:GAUGE:600:0:{pings}", "DS:median:GAUGE:600:0:180"] + [f"DS:ping{i}:GAUGE:600:0:180" for i in range(1, pings+1)]
subprocess.check_call(["rrdtool","create",out,"--step",str(step),"--start",str(start-step)] + ds + rras)
ups = []
t = start
while t < end:
    hour = (t % 86400)/3600
    base = 0.012 + 0.006*math.sin(hour/24*2*math.pi) + (0.02 if (t//3600) % 37 == 5 else 0)
    times = []
    for _ in range(pings):
        if random.random() < (0.3 if (t//3600) % 29 == 3 else 0.01):
            continue
        times.append(base + random.expovariate(1/0.002))
    times.sort()
    n = len(times); loss = pings - n
    median = times[n//2] if n else None
    lo = loss//2; hi = loss - lo
    vals = ["U"]*lo + ["%.10e" % x for x in times] + ["U"]*hi
    # SmokePing updates a few seconds after the round starts
    ups.append(f"{t+3}:U:{loss}:{'U' if median is None else '%.10e' % median}:" + ":".join(vals))
    t += step
for i in range(0, len(ups), 500):
    subprocess.check_call(["rrdtool","update",out] + ups[i:i+500])
