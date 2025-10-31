import sys
import subprocess
import time

SERVER_BIN = "./phase_1/bin/server"
CLIENT_BIN = "./phase_1/bin/client"
SERVER_PORT = "8080"
SERVER_IP = "127.0.0.1"

def parse_test_file(test_file):
    steps = []
    with open(test_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or parts[0] not in ("1", "2"):
                continue
            client_id = int(parts[0])
            command = parts[1]
            steps.append((client_id, command))
    return steps

def run_test(test_file):
    steps = parse_test_file(test_file)

    # Start server
    server = subprocess.Popen([SERVER_BIN, SERVER_PORT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)

    # Start clients
    client1 = subprocess.Popen([CLIENT_BIN, SERVER_IP, SERVER_PORT],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    client2 = subprocess.Popen([CLIENT_BIN, SERVER_IP, SERVER_PORT],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)

    # Send commands in order
    for client_id, command in steps:
        if client_id == 1:
            client1.stdin.write(command + "\n")
            client1.stdin.flush()
        elif client_id == 2:
            client2.stdin.write(command + "\n")
            client2.stdin.flush()
        time.sleep(0.2)  # Small delay to avoid race conditions

    # Close stdin to signal end of input
    client1.stdin.close()
    client2.stdin.close()
    client1.wait(timeout=5)
    client2.wait(timeout=5)

    # Write outputs
    with open("client_1.txt", "w") as f1:
        f1.write(client1.stdout.read())
    with open("client_2.txt", "w") as f2:
        f2.write(client2.stdout.read())

    # Cleanup server
    server.terminate()
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:
        server.kill()

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "test":
        print("Usage: ./test.py test <test_file_id>")
        sys.exit(1)
    test_file = "phase_1/unitTests/test"+sys.argv[2]+".txt"
    run_test(test_file)