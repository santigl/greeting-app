#!/usr/bin/env python3
"""Script to generate the necessary RSA keys for the webapp to sign
the tokens sent to the backend.
"""

# BSD 2-Clause License
#
# Copyright (c) 2018, Santiago Gil
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


RSA_PUBLIC_EXPONENT = 65375
RSA_KEY_SIZE = 2048

def export_public_key(key, filename):
    """Dumps the public key into a PEM file."""
    public_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(filename, 'wb') as f:
        f.write(public_bytes)

    print('Saved public key to {}'.format(filename))

def export_private_key(key, filename):
    """Dumps the private key into a PEM file."""
    private_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PrivateFormat.TraditionalOpenSSL,
                                              encryption_algorithm=serialization.NoEncryption())

    with open(filename, 'wb') as f:
        f.write(private_bytes)

    print('Saved private key to {}'.format(filename))


def generate_rsa_key_pair(public_exponent, key_size):
    """Generates an RSA key pair using the given parameters.
    Returns (private, public).
    """
    print('Generating keys...')
    private_key = rsa.generate_private_key(public_exponent=public_exponent,
                                           key_size=key_size,
                                           backend=default_backend())

    return (private_key, private_key.public_key())


if __name__ == '__main__':
    private_key, public_key = generate_rsa_key_pair(RSA_PUBLIC_EXPONENT,
                                                    RSA_KEY_SIZE)
    export_public_key(public_key, 'public.pem')
    export_private_key(private_key, 'private.pem')
