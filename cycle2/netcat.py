#***********************
# Netcat Tool in Python
# Walt
#CSC842 26 May 2024
#***********************
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import platform
from queue import Queue
import time


# Executes a shell command and returns its output.
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()

#Retrieves the system's OS fingerprint, and returns a string containing OS details.
def get_fingerprint():
    os_info = {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor()
    }
    fingerprint = "\n".join(f"{key}: {value}" for key, value in os_info.items())
    return fingerprint

#define the class & Initializes the NetCat object.
#parsed command-line arguments, and data buffer to send.
class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.print_lock = threading.Lock()
        self.queue = Queue()

    #Determines the mode of operation and calls the appropriate method.
    def run(self):
        if self.args.fingerprint:
            self.send_fingerprint()
        if self.args.scan:
            self.scan_ports()
        if self.args.listen:
            self.listen()
        else:
            self.send()

    #Sends the OS fingerprint to the specified target and port.
    def send_fingerprint(self):
        fingerprint = get_fingerprint()
        self.socket.connect((self.args.target, self.args.port))
        self.socket.send(fingerprint.encode())
        self.socket.close()
        sys.exit()

    #Scans specified ports on the target host.
    def scan_ports(self):
        target = self.args.target
        port_list = self.args.scan
        ports = []

        # Expand port ranges specified in the format "start-end"
        for port in port_list:
            if '-' in port:
                start, end = map(int, port.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port))

        print(f'Scanning ports {ports} on {target}')
        self.t_IP = socket.gethostbyname(target)
        start_time = time.time()

        def threader():
            while True:
                worker = self.queue.get()
                self.portscan(worker)
                self.queue.task_done()

        # Start 100 threads to perform the port scan
        for x in range(100):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        # Add all ports to the queue
        for port in ports:
            self.queue.put(port)

        # Wait for all threads to finish
        self.queue.join()
        print('Time taken:', time.time() - start_time)
        sys.exit()

    #Checks if a specific port on the target host is open.
    def portscan(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((self.t_IP, port))
            with self.print_lock:
                print(f'Port {port}: Open')
            con.close()
        except:
            pass

    #Sends data to the target and allows interactive communication.
    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    #Listens on the specified port for incoming connections.
    def listen(self):
        print('Listening...')
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    #Handles incoming connections and executes commands if specified.
    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
            client_socket.close()

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b' #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()
        
        else:
            fingerprint = client_socket.recv(4096).decode()
            print(f"Received fingerprint:\n{fingerprint}")
            client_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(  # Provides the help arguments on how the tool behaves
        description='MyNetcat Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
          netcat.py -t 10.0.2.15 -p 5555 -l -c # command shell
          netcat.py -t 10.0.2.15 -p 5555 -l -e="cat /etc/passwd" # execute command
          echo 'ABCDEFGHI' | ./netcat.py -t 10.0.2.15 -p 135 # echo local text to server port 135
          netcat.py -t 10.0.2.15 -p 5555 # connect to server
          netcat.py -t 10.0.2.15 -s 22,80,443 # scan specific ports
          netcat.py -t 10.0.2.15 -s 20-25,80 # scan range of ports
          netcat.py -t 10.0.2.15 -p 5555 -f # send fingerprint to target
          netcat.py -t 10.0.2.15 -p 5555 -l # listen for fingerprint
          '''))   #provides an action for provided arguments
    parser.add_argument('-c', '--command', action='store_true', help='initialize command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='10.0.2.15', help='specified IP')
    parser.add_argument('-f', '--fingerprint', action='store_true', help='send OS fingerprint to target and exit')
    parser.add_argument('-s', '--scan', type=lambda x: x.split(','), help='scan specified ports or ranges (comma-separated)')
    args = parser.parse_args()

    if args.listen:
        buffer = None
    else:
        buffer = sys.stdin.read() if not sys.stdin.isatty() else None

    nc = NetCat(args, buffer.encode('utf-8') if buffer else None)
    nc.run()

