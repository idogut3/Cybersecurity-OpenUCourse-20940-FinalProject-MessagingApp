import random
from enum import Enum


class ProtocolsCodes(Enum):
    RegisterRequestProtocolCode = "We"
    ConnectRequestProtocolCode = "Love"
    CheckWaitingMessagesProtocolCode = "This"
    ProcessCommunicateProtocolCode = "Project"

def send_by_secure_channel(code):
    return 2

def generate_random_code():
    return random.randint(100000, 999999)

