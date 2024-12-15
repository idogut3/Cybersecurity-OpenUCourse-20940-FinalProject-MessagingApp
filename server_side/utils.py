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
    """Generate a random 6-digit code as a string, preserving leading zeros."""
    return f"{random.randint(0, 999999):06}"

