import socket
import ssl
import time

class SocketConnection:
    def __init__(self):
        self.context = None
        self.data = None
        self.s = None
        self.ssl = None
        self.ssl_enable = False

    def connect(self, host, port, timeout, proxy=None):
        try:
            if proxy:
                proxy_host, proxy_port = proxy.replace("http://", "").split(":")
                self.s = socket.create_connection((proxy_host, int(proxy_port)))
                connect_request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                self.s.sendall(connect_request.encode())
                response = self.s.recv(4096)
                if b"200 Connection established" not in response:
                    print("Error: Unable to establish proxy connection")
                    return None
            else:
                if port == 443:
                    self.ssl_enable = True
                    self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                    self.s = socket.create_connection((host, port))
                    self.ssl = self.context.wrap_socket(self.s, server_hostname=host)
                    self.ssl.settimeout(timeout)
                else:
                    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.s.settimeout(timeout)
                    self.s.connect((host, port))
            return self.s
        except socket.error as msg:
            print(f'Socket Error → {msg}')
            return None

    def send_payload(self, payload):
        if self.ssl_enable:
            self.ssl.send(str(payload).encode())
        else:
            self.s.send(str(payload).encode())

    def receive_data(self, buffer_size=1024):
        try:
            if self.ssl_enable:
                self.ssl.settimeout(None)
                self.data = self.ssl.recv(buffer_size)
            else:
                self.s.settimeout(None)
                self.data = self.s.recv(buffer_size)
        except socket.timeout:
            print('Error: Socket timeout')
        return self.data

    @staticmethod
    def detect_hrs_vulnerability(start_time, timeout):
        if time.time() - start_time >= timeout:
            return True
        return False

    def close_connection(self):
        if self.ssl_enable:
            self.ssl.close()
            del self.ssl
        self.s.close()
        del self.s