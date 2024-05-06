import rsa
from base64 import b64encode, b64decode

def xor_encrypt(data, key):
    # XOR encryption
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return encrypted_data

def xor_decrypt(data, key):
    # XOR decryption
    decrypted_data = bytearray()
    for i in range(len(data)):
        decrypted_data.append(data[i] ^ key[i % len(key)])
    return decrypted_data

def encode_key(key, private_key=None):

    if private_key:
        return private_key.save_pkcs1().decode('utf-8'), b64encode(xor_encrypt(private_key.save_pkcs1(), key.encode('utf-8'))).decode('utf-8')
    else:
        public_key, private_key = rsa.newkeys(512)
    # Generate RSA key pair
    public_key, private_key = rsa.newkeys(512)
    
    # Serialize keys to strings
    public_key_str = public_key.save_pkcs1().decode('utf-8')
    private_key_str = private_key.save_pkcs1().decode('utf-8')
    
    # Encrypt private key using XOR encryption with key
    private_key_enc = xor_encrypt(private_key_str.encode('utf-8'), key.encode('utf-8'))
    
    # Return encoded keys
    return public_key_str, b64encode(private_key_enc).decode('utf-8')

def decode_key(private_key_enc, key):
    # Decode private key using XOR decryption with key
    private_key_str = xor_decrypt(b64decode(private_key_enc.encode('utf-8')), key.encode('utf-8')).decode('utf-8')
    
    # Load private key from string
    private_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode('utf-8'))
    
    return private_key

def encode_data(data, public_key):
    # Load public key from string
    public_key = rsa.PublicKey.load_pkcs1(public_key)
    
    # Encrypt data using RSA encryption
    encrypted_data = rsa.encrypt(data.encode('utf-8'), public_key)
    
    # Return base64 encoded encrypted data
    return b64encode(encrypted_data).decode('utf-8')

def decode_data(data, private_keys):
    # Load private key from string
    # private_keyss = rsa.PrivateKey.load_pkcs1(private_keys)
    
    # Decrypt data using RSA decryption
    decrypted_data = rsa.decrypt(b64decode(data.encode('utf-8')), private_keys)
    
    # Return decoded decrypted data
    return decrypted_data.decode('utf-8')

