import os

from sqlalchemy.orm import declarative_base
from sqlalchemy_utils.types.encrypted.encrypted_type import StringEncryptedType, AesEngine

Base = declarative_base()
ENCRYPTION_KEY = os.getenv("DATABASE_ENCRYPTION_KEY")

def encrypt_type(input_type):
    return StringEncryptedType(input_type, ENCRYPTION_KEY, AesEngine, 'pkcs5') if ENCRYPTION_KEY else input_type
