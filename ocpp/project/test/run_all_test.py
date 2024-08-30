import subprocess
import time

# Run central_system.py
central_system_process = subprocess.Popen(["python", "central_system_test.py"])

# Add a delay (adjust as needed)
time.sleep(2)

# Run charge_point.py
charge_point_process = subprocess.Popen(["python", "charge_point_test.py"])

# Wait for all processes to finish
central_system_process.wait()
charge_point_process.wait()
