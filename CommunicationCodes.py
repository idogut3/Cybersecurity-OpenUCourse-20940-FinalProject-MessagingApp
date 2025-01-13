from enum import Enum


class ProcessCodes(Enum):
    init_RegistrationCode = "We"
    init_ConnectionCode = "Love"
    init_CheckWaitingMessagesCode = "This"
    initCommunicationCode = "Project"

class SubProcessCodes(Enum):

    class GeneralCodes(Enum):
        GENERAL_SERVER_ERROR = 100
        GENERAL_CLIENT_ERROR = 105

    class ServerSideProtocolCodes(Enum):
        
        class Registration(Enum):
            SEND_PUBLIC_KEY = 101
            REGISTER_SUCCESS = 104

    class UserSideRequestCodes(Enum):
            class Registration(Enum):
                SEND_PHONE_NUMBER = 102
                SEND_PUBLIC_KEY = 103

