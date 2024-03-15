from dataclasses import dataclass

from app.classes.question import DNSQuestion, DNSQuestionType, parse_dns_question
from app.dns_database import dns_database


@dataclass
class DNSAnswer:
    # The DNS answer is the same as the question, but with additional fields.
    dns_question: DNSQuestion

    # Time to Live - 4 bytes
    # The number of seconds the answer can be cached.
    ttl: int = 0

    # Resource Data Length - 2 bytes
    # The length of the resource data in bytes.
    resource_data_length: int = 0

    # Resource Data - variable length
    # The format of the data depends on the type and class of the resource record.
    # The data for an A record (1) is a 4-bytes IPv4 address.
    resource_data: bytes = None

    def calculate_answer(self):
        db_record = dns_database[self.dns_question.name]

        self.ttl = db_record["ttl"]

        if self.dns_question.type == DNSQuestionType.A:
            # IPv4 address always has 4 bytes
            self.resource_data_length = 4

            ip_address = 0
            index = 0
            for block in db_record["ip"].split("."):
                ip_address |= int(block) << 12 - (index * 4)
                index += 1
            self.resource_data = ip_address.to_bytes(self.resource_data_length, byteorder="big")
        else:
            raise NotImplementedError(f"Encoding for type {self.dns_question.type.name} not implemented")

    def encode(self) -> bytearray:
        res = self.dns_question.encode()
        res.extend(self.ttl.to_bytes(4, byteorder="big"))
        res.extend(self.resource_data_length.to_bytes(2, byteorder="big"))
        res.extend(self.resource_data)

        return res


def parse_dns_answer(buf: bytes, previous_index: int) -> (DNSAnswer, int):
    question, previous_index = parse_dns_question(buf, previous_index)
    ttl = int.from_bytes(buf[previous_index:previous_index + 4], byteorder="big")
    previous_index += 4
    resource_data_length = int.from_bytes(buf[previous_index:previous_index + 2], byteorder="big")
    previous_index += 2
    resource_data = buf[previous_index:previous_index + resource_data_length]
    previous_index += resource_data_length

    return DNSAnswer(
        dns_question=question,
        ttl=ttl,
        resource_data_length=resource_data_length,
        resource_data=resource_data,
    ), previous_index
