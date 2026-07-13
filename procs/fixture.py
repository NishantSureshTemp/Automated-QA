# fixture.py
import os, requests, time

# write our own PID so the prep script can find us
with open("fixture.pid", "w") as f:
    f.write(str(os.getpid()))

print(f"fixture running as PID {os.getpid()}")
for _ in range(10):
    r = requests.get("https://httpbin.org/get")
    print(f"got {len(r.content)} bytes")
    time.sleep(30)