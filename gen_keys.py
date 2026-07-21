import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization



def gen_keys(private_key_filename, public_key_filename):
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_filename, 'wb') as f:
        f.write(pem_private)
    with open(public_key_filename, 'wb') as f:
        f.write(pem_public)

if __name__== "__main__":

    keys_dir = "keys"
    gen_keys(
        os.path.join(keys_dir, "privKc.pem"),
        os.path.join(keys_dir, "pubKc.pem"),
    )
    gen_keys(
        os.path.join(keys_dir, "privKts.pem"),
        os.path.join(keys_dir, "pubKts.pem"),
    )
