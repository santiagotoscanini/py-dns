# The dataclass decorator is used to create a class with a __init__ method based on the fields defined in the class.
from dataclasses import dataclass

from enum import Enum


class DNSQuestionType(Enum):
    """
    # Possible values for the type field are defined here https://en.wikipedia.org/wiki/List_of_DNS_record_types
    # The most common types are:
    """

    # 1 for A records.
    A = 1

    # 5 for CNAME (canonical res) records.
    CNAME = 5

    # 15 for MX records (mail exchange).
    MX = 15

    # 16 for TXT records (text strings).
    TXT = 16

    # 28 for AAAA records (IPv6 address).
    AAAA = 28


class DNSQuestionClass(Enum):
    """
    There are only a few classes defined for DNS, but the only one that is used is IN (Internet).
    """

    # 1. for IN (the Internet).
    #    It's funny that the early DNS designers thought that there would be other classes.
    IN = 1

    # 3. for CH (the CHAOS class).
    #    Used by Chaosnet, an early local area network protocol.
    #    https://en.wikipedia.org/wiki/Chaosnet
    #    https://dspace.mit.edu/bitstream/handle/1721.1/6353/AIM-628.pdf?sequence=2
    CH = 3

    # 4. for HS (Hesiod)
    #    Used by Hesiod, a res service built on top of DNS. Which was part of the MIT Project Athena.
    #    It uses DNS to store information about users, groups, and other system information.
    #    Frequently an LDAP server is used instead of Hesiod.
    #    https://en.wikipedia.org/wiki/Hesiod_(name_service)
    HS = 4


@dataclass
class DNSQuestion:
    # This is the domain name being queried - variable length
    # The domain name is a sequence of labels, where each label consists of a length octet followed by that number of
    # octets. The domain name terminates with the zero length octet for the null label of the root. The domain name is
    # case-insensitive.
    # e.g. "google.com" is encoded as "\x06google\x03com\x00"
    name: str

    # This is the type of record being requested - 2 bytes
    type: DNSQuestionType

    # This is the class of the query - 2 bytes
    class_field: DNSQuestionClass

    def encode(self) -> bytearray:
        res = bytearray()
        for token in self.name.split("."):
            res.append(len(token))
            res.extend(token.encode("utf-8"))
        res.append(0)

        res.extend(self.type.value.to_bytes(2, byteorder="big"))

        res.extend(self.class_field.value.to_bytes(2, byteorder="big"))

        return res


def parse_dns_question(buf: bytes, previous_index: int) -> (DNSQuestion, int):
    chunks = []
    question_pointer = None

    while True:
        chunk_length = int.from_bytes(buf[previous_index:previous_index + 1])
        if chunk_length == 0:
            break
        elif chunk_length & 0b11000000 == 0b11000000:
            # This is a pointer to a previous part of the message.
            # The pointer is a 14-bit value that points to an offset from the start of the message.
            # The first two bits are always 1, and the remaining 14 bits are the offset.
            # The offset is the number of bytes from the start of the message to the start of the referenced part.
            # The pointer is followed by a 2-byte field that contains the rest of the message.
            # The pointer is used to avoid repeating the same domain name in the message.
            # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            pointer = int.from_bytes(buf[previous_index:previous_index + 2])
            pointer &= 0b00111111_11111111
            question_pointer, _ = parse_dns_question(buf, pointer)
            chunks = chunks + question_pointer.name.split(".")
            previous_index += 2
            break
        else:
            chunk = buf[previous_index + 1:previous_index + 1 + chunk_length]
            chunks.append(chunk.decode("utf-8"))
            previous_index += 1 + chunk_length

    if question_pointer:
        question = DNSQuestion(
            name='.'.join(chunks),
            type=question_pointer.type,
            class_field=question_pointer.class_field,
        )
        return question, previous_index
    else:
        question = DNSQuestion(
            name='.'.join(chunks),
            type=DNSQuestionType(int.from_bytes(buf[previous_index + 1:previous_index + 3])),
            class_field=DNSQuestionClass(int.from_bytes(buf[previous_index + 3:previous_index + 5])),
        )

        return question, previous_index + 5
