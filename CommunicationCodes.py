from enum import Enum

class ProtocolCodes(Enum):
    init_RegistrationCode = "We"
    initConnectionAESExchange = "Love"
    init_CheckWaitingMessagesCode = "This"
    initCommunicationCode = "Project"


class GeneralCodes(Enum):
    GENERAL_SERVER_ERROR = 100
    GENERAL_CLIENT_ERROR = 105

class ServerSideProtocolCodes(Enum):
    SEND_PUBLIC_KEY = 101
    REGISTER_SUCCESS = 104
    CONNECT_REQUEST_ACCEPTED = 106
    CONNECT_REQUEST_NOT_ACCEPTED = 107
    INVALID_PHONE_NUMBER = 108
    INVALID_SECRET_CODE = 109
    SEND_YOUR_ENCRYPTED_MESSAGE = 111

class UserSideRequestCodes(Enum):
    SEND_PHONE_NUMBER = 102
    SEND_PUBLIC_KEY = 103
    SEND_MESSAGE = 110

