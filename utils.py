import random, uuid

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_reset_token():
    return str(uuid.uuid4())
