import socket
import threading
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import traceback
import ssl
import os
import ipaddress
from datetime import datetime, timedelta
import logging
import sys

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("chat.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# 常量定义
BUFFER_SIZE = 4096

def encrypt_message(message, key, nonce):
    """
    使用ChaCha20加密消息
    """
    cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode=None,
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return ciphertext

def decrypt_message(ciphertext, key, nonce):
    """
    使用ChaCha20解密消息
    """
    cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode=None,
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext).decode('utf-8') + decryptor.finalize().decode('utf-8')
    return plaintext

def aes_encrypt(data, aes_key):
    """
    使用AES-GCM加密数据
    """
    nonce = os.urandom(12)  # AES-GCM推荐12字节的nonce
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag

def aes_decrypt(ciphertext, aes_key):
    """
    使用AES-GCM解密数据
    """
    try:
        nonce = ciphertext[:12]
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[12:-16]
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        data = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return data
    except Exception as e:
        logging.error(f"AES解密失败: {e}")
        return None
       
def disguise_packet(data):
    """
    将数据包伪装成HTTP请求
    """
    http_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: cloudflare.com\r\n"
        f"Content-Length: {len(data)}\r\n\r\n"
    ).encode('utf-8') + data
    return http_request

def extract_data_from_disguised_packet(packet):
    """
    从伪装的HTTP请求中提取数据
    """
    header_end = packet.find(b'\r\n\r\n')
    if header_end == -1:
        return None
    return packet[header_end + 4:]

def generate_self_signed_cert(certfile, keyfile, server_ip):
    """
    生成自签名证书，使用服务器的IP地址作为CN
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(server_ip)),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(hours=24)
    ).add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(server_ip))]),
        critical=False
    ).sign(key, hashes.SHA256(), default_backend())

    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

def generate_key_pair():
    """
    生成 RSA 密钥对
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    序列化公钥为PEM格式
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """
    从PEM格式反序列化公钥
    """
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
   
def create_server(port, use_ssl):
    # 不管是否使用SSL，都询问IP
    use_specific_ip = input("是否要指定服务器IP地址？(y/n): ").lower() == 'y'
    server_ip = '0.0.0.0'  # 默认绑定所有接口

    if use_specific_ip:
        server_ip = input("请输入服务器的IP地址: ")
        if not validate_ip(server_ip):
            print("无效的IP地址")
            sys.exit(1)

    if use_ssl:
        # 询问用户是否使用自签名证书
        use_self_signed = input("是否使用自签名证书？(y/n): ").lower() == 'y'

        if use_self_signed:
            certfile = 'server.crt'
            keyfile = 'server.key'
            if not os.path.exists(certfile) or not os.path.exists(keyfile):
                print("生成自签名证书中...")
                generate_self_signed_cert(certfile, keyfile, server_ip)
                print("自签名证书已生成：server.crt, server.key")
        else:
            certfile = input("请输入证书文件路径 (例如: /path/to/certificate.crt): ")
            keyfile = input("请输入私钥文件路径 (例如: /path/to/private.key): ")
            if not os.path.exists(certfile) or not os.path.exists(keyfile):
                print("错误：证书文件或私钥文件不存在")
                sys.exit(1)
            print(f"使用证书：{certfile}")
            print(f"使用私钥：{keyfile}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, port))
    server.listen(1)
    print(f"服务器已启动，正在监听 {server_ip}:{port}...")

    try:
        client, addr = server.accept()
    except Exception as e:
        print("接受连接时发生错误")
        logging.error(f"接受连接时发生错误: {e}")
        sys.exit(1)

    if use_ssl:
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            client = context.wrap_socket(client, server_side=True)
        except Exception as e:
            print("SSL握手失败")
            logging.error(f"SSL握手失败: {e}")
            sys.exit(1)

    print(f"客户端 {addr} 已连接")
    
    try:
        # 生成RSA密钥对
        private_key, public_key = generate_key_pair()

        # 发送服务器的公钥给客户端
        public_key_bytes = serialize_public_key(public_key)
        client.send(public_key_bytes)

        # 接收客户端的公钥
        client_public_key_bytes = b''
        while True:
            part = client.recv(4096)
            client_public_key_bytes += part
            if b'END PUBLIC KEY-----' in client_public_key_bytes:
                break
            if len(client_public_key_bytes) > 10000:
                break  # 防止无限等待

        client_public_key = deserialize_public_key(client_public_key_bytes)

        # 生成会话密钥
        key = os.urandom(32)     # ChaCha20 密钥 (32 bytes)
        nonce = os.urandom(16)   # ChaCha20 nonce (16 bytes)
        aes_key = os.urandom(32) # AES 密钥 (32 bytes)

        # 使用客户端的公钥加密会话密钥
        encrypted_keys = client_public_key.encrypt(
            key + nonce + aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 发送加密的会话密钥
        client.send(encrypted_keys)

    except Exception as e:
        print(f"密钥交换失败: {e}")
        logging.error(f"密钥交换失败: {e}")
        sys.exit(1)

    return client, key, nonce, aes_key
    
def connect_to_server(host, port, use_ssl):
    if use_ssl:
        if not validate_ip(host):
            print("使用SSL时，主机必须是有效的IP地址")
            sys.exit(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if use_ssl:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # 开发测试环境：
        if os.path.exists("server.crt"):
            context.load_verify_locations("server.crt")
        else:
            print("警告：未找到服务器证书，将使用不安全的连接模式")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    try:
        if use_ssl:
            client = context.wrap_socket(client, server_hostname=host)
        client.connect((host, port))
    except Exception as e:
        print("连接服务器失败")
        logging.error(f"连接服务器失败: {e}")
        sys.exit(1)
    print(f"已连接到服务器 {host}:{port}")

    try:
        # 接收服务器的公钥
        server_public_key_bytes = b''
        while True:
            part = client.recv(4096)
            server_public_key_bytes += part
            if b'END PUBLIC KEY-----' in server_public_key_bytes:
                break
            if len(server_public_key_bytes) > 10000:
                break  # 防止无限等待

        server_public_key = deserialize_public_key(server_public_key_bytes)

        # 生成RSA密钥对
        private_key, public_key = generate_key_pair()

        # 发送客户端的公钥给服务器
        public_key_bytes = serialize_public_key(public_key)
        client.send(public_key_bytes)

        # 接收加密的会话密钥
        encrypted_keys = client.recv(BUFFER_SIZE * 2)  # 根据密钥大小调整缓冲区
        decrypted_keys = private_key.decrypt(
            encrypted_keys,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        key = decrypted_keys[:32]      # ChaCha20 密钥
        nonce = decrypted_keys[32:48]  # ChaCha20 nonce (16 bytes)
        aes_key = decrypted_keys[48:80]# AES 密钥 (32 bytes)
    except Exception as e:
        print("密钥交换时发生错误")
        logging.error(f"密钥交换时发生错误: {e}")
        sys.exit(1)

    return client, key, nonce, aes_key
    
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

def receive_messages(sock, key, nonce, aes_key, stop_event):
    while not stop_event.is_set():
        try:
            disguised_packet = sock.recv(1024)
            if disguised_packet:
                encrypted_data = extract_data_from_disguised_packet(disguised_packet)
                if encrypted_data is None:
                    print("\n接收到的包格式不正确")
                    continue
                ciphertext = aes_decrypt(encrypted_data, aes_key)
                if ciphertext is None:
                    print("\n接收到的消息无法解密或被篡改")
                    continue
                message = decrypt_message(ciphertext, key, nonce)
                print(f"\n对方: {message}")
            else:
                print("\n对方已断开连接")
                stop_event.set()
                break
        except ConnectionResetError:
            print("\n连接已断开")
            logging.error("接收消息时发生错误: ConnectionResetError", exc_info=True)
            stop_event.set()
            break
        except Exception as e:
            print("\n接收消息时发生错误")
            logging.error(f"接收消息时发生错误: {e}", exc_info=True)
            stop_event.set()
            break

    try:
        sock.close()
    except Exception as e:
        logging.error(f"关闭套接字失败: {e}")
    sys.exit()
    
def main():
    print("P2P 聊天程序")
    print("1. 创建服务器")
    print("2. 加入服务器")

    choice = input("请选择 (1/2): ")

    use_ssl_input = input("是否使用SSL (y/n): ").lower()
    use_ssl = use_ssl_input == 'y'

    if choice == "1":
        port_input = input("请输入要使用的端口号: ")
        if not validate_port(port_input):
            print("无效的端口号")
            return
        port = int(port_input)
        sock, key, nonce, aes_key = create_server(port, use_ssl)
    elif choice == "2":
        host = input("请输入服务器IP地址: ")
        if not validate_ip(host):
            print("无效的IP地址")
            return
        port_input = input("请输入服务器端口号: ")
        if not validate_port(port_input):
            print("无效的端口号")
            return
        port = int(port_input)
        sock, key, nonce, aes_key = connect_to_server(host, port, use_ssl)
    else:
        print("无效的选择")
        return

    # 创建一个事件用于线程间通信
    stop_event = threading.Event()

    # 创建接收消息的线程
    receive_thread = threading.Thread(target=receive_messages, args=(sock, key, nonce, aes_key, stop_event))
    receive_thread.start()

    # 发送消息的主循环
    try:
        while not stop_event.is_set():
            message = input("")
            if message.lower() == 'quit':
                stop_event.set()
                break
            ciphertext = encrypt_message(message, key, nonce)
            encrypted_data = aes_encrypt(ciphertext, aes_key)
            disguised_packet = disguise_packet(encrypted_data)
            try:
                sock.send(disguised_packet)
            except Exception as e:
                print("发送消息失败")
                logging.error(f"发送消息失败: {e}")
                stop_event.set()
                break
    except KeyboardInterrupt:
        print("\n退出聊天")
        stop_event.set()
    except Exception as e:
        print("发送消息时发生意外错误")
        logging.error(f"发送消息时发生意外错误: {e}", exc_info=True)
        stop_event.set()
    finally:
        try:
            sock.close()
        except Exception as e:
            logging.error(f"关闭套接字失败: {e}")

        # 等待接收线程结束
        receive_thread.join()

if __name__ == "__main__":
    main()
