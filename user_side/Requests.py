from abc import ABC, abstractmethod

class Request(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def run(self):
        """The abstract method for running a request"""
        pass