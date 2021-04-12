# -*- coding: utf-8 -*-

import os
import sqlalchemy
import logging

from sqlalchemy.orm import declarative_base
from sqlalchemy_utils.types.encrypted.encrypted_type import StringEncryptedType, AesEngine, EncryptionDecryptionBaseEngine, AesGcmEngine

Base = declarative_base()
ENCRYPTION_KEY = os.getenv("DATABASE_ENCRYPTION_KEY")

def encrypt_type(input_type : sqlalchemy.types.TypeEngine, engine : EncryptionDecryptionBaseEngine):
    if not ENCRYPTION_KEY:
        logging.info(f"ENCRYPTION_KEY is not set, not encrypting Type {input_type}")
        return input_type
    logging.info(f"Encrypting Type {input_type} ({input_type.python_type})")
    return StringEncryptedType(input_type, ENCRYPTION_KEY, engine, 'pkcs5')    

def encrypt_type_searchable(input_type : sqlalchemy.types.TypeEngine):
    return encrypt_type(input_type=input_type, engine=AesEngine)

def encrypt_type_safer(input_type : sqlalchemy.types.TypeEngine):
    return encrypt_type(input_type=input_type, engine=AesGcmEngine)
