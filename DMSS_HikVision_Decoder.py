#!/usr/bin/env python3
import argparse, base64, datetime, gzip, json, os, zlib
from PIL import Image
from pyzbar.pyzbar import decode
import pyaes

class InvalidLengthError(Exception): pass
class MalformedDeviceDataError(Exception): pass

class HikAES(pyaes.AES):
    def __init__(self, key: bytes = b'dkfj4593@#&*wlfm', rounds: int = 4):
        self.number_of_rounds = {16: rounds, 24: rounds, 32: rounds}
        super().__init__(key)

    def _fix_padding(self, s: str) -> str:
        s = s.strip()
        missing_padding = len(s) % 4
        return s + '=' * (4 - missing_padding) if missing_padding else s

    def decrypt_b64_to_str(self, ciphertext: str) -> str:
        ciphertext_fixed = self._fix_padding(ciphertext)
        decrypted = self.decrypt(base64.b64decode(ciphertext_fixed))
        return ''.join(chr(c) for c in decrypted)

    def encrypt_str_to_b64(self, plaintext: str) -> str:
        encrypted = self.encrypt(plaintext.encode())
        return base64.b64encode(bytearray(encrypted)).decode()

class LocalDevice:
    def __init__(self, name: str, ip_address: str, port: int, username: str, password: str):
        if len(username) > 16: raise InvalidLengthError('username length must be not more than 16 characters')
        if len(password) > 16: raise InvalidLengthError('password length must be not more than 16 characters')
        self._name, self._ip_address, self._port = name, ip_address, port
        self._username, self._password = username, password

    @classmethod
    def from_encoded(cls, ampersand_string: str) -> 'LocalDevice':
        try:
            name_b64, _, ip_address_b64, port, _, username_enc_b64, password_enc_b64 = ampersand_string.split('&')
        except ValueError:
            raise MalformedDeviceDataError(f'Not enough fields in ampersand string (expected 7, got {ampersand_string.count("&")})')
        username = HikAES().decrypt_b64_to_str(username_enc_b64).rstrip('\x00')
        password = HikAES().decrypt_b64_to_str(password_enc_b64).rstrip('\x00')
        return cls(
            name=base64.b64decode(name_b64).decode('utf-8'),
            ip_address=base64.b64decode(ip_address_b64).decode('utf-8'),
            port=int(port),
            username=username,
            password=password
        )

    def encode(self) -> str:
        username_padded, password_padded = self._username.ljust(16, '\x00'), self._password.ljust(16, '\x00')
        return '&'.join([
            base64.b64encode(self._name.encode('utf-8')).decode(),
            '0',
            base64.b64encode(self._ip_address.encode('utf-8')).decode(),
            str(self._port),
            '',
            HikAES().encrypt_str_to_b64(username_padded),
            HikAES().encrypt_str_to_b64(password_padded),
        ])

    @property
    def name(self) -> str: return self._name
    @property
    def ip_address(self) -> str: return self._ip_address
    @property
    def port(self) -> int: return self._port
    @property
    def username(self) -> str: return self._username
    @property
    def password(self) -> str: return self._password

    def __repr__(self):
        return (f'{self.__class__.__name__}(name="{self.name}", ip_address="{self.ip_address}", port={self.port}, '
                f'username="{self.username}", password="{self.password}")')

class QrCodeData:
    def __init__(self, e2e_password: str, local_devices: [LocalDevice],
                 header: str = 'QRC03010003', timestamp_created: int = int(datetime.datetime.now().timestamp())):
        if len(e2e_password) > 16: raise InvalidLengthError('e2e_password length must be not more than 16 characters')
        self._e2e_password, self._local_devices = e2e_password, local_devices
        self._header, self._timestamp_created = header, timestamp_created

    @classmethod
    def from_qr_string(cls, qr_string: str) -> 'QrCodeData':
        header, compressed_data_b64 = qr_string[:11], qr_string[11:].strip()
        missing_padding = len(compressed_data_b64) % 4
        if missing_padding: compressed_data_b64 += '=' * (4 - missing_padding)
        decompressed_data = zlib.decompress(base64.b64decode(compressed_data_b64)).decode()
        parts = decompressed_data.split(':')
        
        if len(parts) == 3:
            e2e_password_enc_b64, local_devices_str, timestamp_created_enc = parts
            timestamp_created = int(HikAES().decrypt_b64_to_str(timestamp_created_enc).rstrip('\x00'))
        elif len(parts) == 2:
            e2e_password_enc_b64, local_devices_str = parts
            timestamp_created = 0
        else:
            raise ValueError("Unexpected format of decompressed QR data")
        
        e2e_password = HikAES().decrypt_b64_to_str(e2e_password_enc_b64).rstrip('\x00')
        local_devices = [LocalDevice.from_encoded(local_device_encoded) 
                         for local_device_encoded in local_devices_str.split('$') if local_device_encoded]
        return cls(e2e_password=e2e_password, local_devices=local_devices, header=header, timestamp_created=timestamp_created)

    def renew(self): self._timestamp_created = int(datetime.datetime.now().timestamp())

    def encode(self) -> str:
        local_devices_str = '$'.join(local_device.encode() for local_device in self._local_devices) + '$'
        compressed_data_b64 = base64.b64encode(zlib.compress(
            ':'.join([
                HikAES().encrypt_str_to_b64(self._e2e_password.ljust(16, '\x00')),
                local_devices_str,
                HikAES().encrypt_str_to_b64(str(self._timestamp_created).ljust(16, '\x00')),
            ]).encode()
        )).decode()
        return f'{self._header}{compressed_data_b64}'

    @property
    def e2e_password(self) -> str: return self._e2e_password
    @property
    def local_devices(self) -> [LocalDevice]: return self._local_devices
    @property
    def header(self) -> str: return self._header
    @property
    def timestamp_created(self) -> int: return self._timestamp_created
    @timestamp_created.setter
    def timestamp_created(self, value: int): self._timestamp_created = value

    def __repr__(self):
        return (f'{self.__class__.__name__}(header="{self.header}", e2e_password="{self._e2e_password}", '
                f'timestamp_created={self.timestamp_created})')

def decode_gzip_base64_string(encoded_str):
    try:
        binary_data = base64.b64decode(encoded_str)
        decompressed_data = gzip.decompress(binary_data)
        return decompressed_data.decode('utf-8')
    except Exception as e:
        print(f"Error decoding string: {e}")
        return None

def parse_decoded_text(decoded_text):
    try:
        return json.loads(decoded_text)
    except json.JSONDecodeError:
        if ':' in decoded_text:
            identifier, rest = decoded_text.split(':', 1)
            parts = rest.split('&')
            result = {"identifier": identifier}
            
            if len(parts) > 0:
                try: result["deviceName"] = base64.b64decode(parts[0]).decode('utf-8')
                except Exception: result["deviceName"] = parts[0]
            if len(parts) > 1: result["deviceType"] = parts[1]
            if len(parts) > 2:
                try: result["ip"] = base64.b64decode(parts[2]).decode('utf-8')
                except Exception: result["ip"] = parts[2]
            if len(parts) > 3: result["port"] = parts[3]
            if len(parts) > 4: result["extra"] = parts[4]
            if len(parts) > 5: result["passWord"] = parts[5]
            if len(parts) > 6: result["extra2"] = parts[6]
            return result
        else:
            return {"raw": decoded_text}

def process_qr_image(image_path):
    try:
        image = Image.open(image_path)
        qr_codes = decode(image)
        if not qr_codes:
            print(f"No QR code found in image {image_path}")
            return None

        best_qr, best_area = None, 0
        for qr in qr_codes:
            rect = qr.rect
            area = rect.width * rect.height
            if area > best_area:
                best_area, best_qr = area, qr

        if best_qr:
            return best_qr.data.decode('utf-8')
        print(f"No valid QR code found in image {image_path}")
    except Exception as e:
        print(f"Error processing image {image_path}: {e}")
    return None

def process_folder(folder_path):
    image_extensions = ('.png', '.jpg', '.jpeg', '.bmp', '.gif')
    image_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) 
                  if f.lower().endswith(image_extensions)]
    
    if not image_files:
        print("No image files found in folder.")
        return []
        
    results = []
    for image_file in image_files:
        print(f"Processing image: {image_file}")
        qr_data = process_qr_image(image_file)
        if qr_data:
            parsed = process_qr_string(qr_data)
            if parsed is not None:
                results.append(parsed)
    return results

def process_qr_string(qr_string):
    if qr_string.startswith("QRC03010003") or qr_string.startswith("QRC03010002"):
        try:
            qr_code_data = QrCodeData.from_qr_string(qr_string)
            result = {
                "header": qr_code_data.header,
                "e2e_password": qr_code_data.e2e_password,
                "timestamp_created": qr_code_data.timestamp_created,
                "timestamp_iso": datetime.datetime.fromtimestamp(qr_code_data.timestamp_created).isoformat() 
                               if qr_code_data.timestamp_created else "unknown",
                "local_devices": [{
                    "name": dev.name,
                    "ip_address": dev.ip_address,
                    "port": dev.port,
                    "username": dev.username,
                    "password": dev.password
                } for dev in qr_code_data.local_devices]
            }
            return result
        except Exception as e:
            print(f"Error processing HikVision QR: {e}")
            return None
    else:
        decoded = decode_gzip_base64_string(qr_string)
        return parse_decoded_text(decoded) if decoded else None

def main():
    parser = argparse.ArgumentParser(description="Unified DMSS Decode Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--string", type=str, help="Input QR code string")
    group.add_argument("-qr", "--qr_image", type=str, help="Input QR code image file path")
    group.add_argument("-qrf", "--qr_folder", type=str, help="Folder path containing QR code images")
    args = parser.parse_args()
    
    if args.string:
        result = process_qr_string(args.string)
        print(json.dumps(result, indent=4))
    elif args.qr_image:
        qr_data = process_qr_image(args.qr_image)
        if qr_data:
            result = process_qr_string(qr_data)
            print(json.dumps(result, indent=4))
        else:
            print("No QR code data found in the image.")
    elif args.qr_folder:
        results = process_folder(args.qr_folder)
        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
