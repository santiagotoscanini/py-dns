from dataclasses import dataclass


@dataclass
class DNSHeader:
    # Packet Identifier - 16 bits
    # A random ID assigned to query packets. Response packets must reply with the same ID.
    # This is needed to differentiate responses due to the stateless nature of UDP.
    id: int

    # Query/Response (QR) - 1 bit
    # 0 for queries, 1 for responses.
    qr: bool

    # Operation Code (OPCODE) - 4 bits
    # 0 for a standard query, 1 for an inverse query, 2 for a server status request, and 3-15 for reserved values.
    # More details on the operation codes can be found in RFC 1035, section 4.1.1.
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    operation_code: int

    # Authoritative Answer (AA) - 1 bit
    # 1 if the responding server is an authority for the domain name in question, 0 if not.
    authoritative_answer: bool

    # Truncation (TC) - 1 bit
    # 1 if the response was truncated (larger than 512 bytes), 0 if not (always 0 in UDP responses).
    # Traditionally a hint that the query can be reissued using TCP, for which the length limitation doesn't apply.
    truncation: bool

    # Recursion Desired (RD) - 1 bit
    # 1 if the client requests recursion, 0 if not.
    # Set by the sender of the request if the server should attempt to resolve the query recursively if it does not
    # have an answer readily available.
    recursion_desired: bool

    # Recursion Available (RA) - 1 bit
    # 1 if the server supports recursion, 0 if not.
    # Set by the server to indicate whether recursive queries are allowed.
    recursion_available: bool

    # Reserved (Z) - 3 bits
    # Originally reserved for later use, but now used for DNSSEC queries. Must be 0 in non-DNSSEC queries.
    # DNSSEC https://www.cloudflare.com/dns/dnssec/how-dnssec-works/
    reserved: int

    # Response Code (RCODE) - 4 bits
    # Set by the server to indicate the status of the response:
    # 0 for no error.
    # 1 for format error.
    # 2 for server failure.
    # 3 for name error.
    # 4 for not implemented.
    # 5 for refused.
    response_code: int

    # Question Count (QDCOUNT) - 16 bits
    # The number of questions in the question section of the packet.
    question_count: int

    # Answer Record Count (ANCOUNT) - 16 bits
    # The number of resource records in the answer section of the packet.
    answer_record_count: int

    # Authority Record Count (NSCOUNT) - 16 bits
    # The number of name server resource records in the authority records section of the packet.
    authority_record_count: int

    # Additional Record Count (ARCOUNT) - 16 bits
    # The number of resource records in the additional records section of the packet.
    additional_record_count: int

    def encode(self) -> bytes:
        header = 0

        # 2 bytes
        header = (header << 16) + self.id
        # 1 byte
        header = (header << 1) + self.qr
        header = (header << 4) + self.operation_code
        header = (header << 1) + self.authoritative_answer
        header = (header << 1) + self.truncation
        header = (header << 1) + self.recursion_desired
        # 1 byte
        header = (header << 1) + self.recursion_available
        header = (header << 3) + self.reserved
        header = (header << 4) + self.response_code
        # 2 bytes
        header = (header << 16) + self.question_count
        # 2 bytes
        header = (header << 16) + self.answer_record_count
        # 2 bytes
        header = (header << 16) + self.authority_record_count
        # 2 bytes
        header = (header << 16) + self.additional_record_count

        return header.to_bytes(12, byteorder="big")


def parse_dns_header(buf: bytes) -> DNSHeader:
    op_code = (int.from_bytes(buf[2:3]) >> 3) & 0b1111
    header = DNSHeader(
        # 2 bytes
        id=int.from_bytes(buf[:2]),

        # 1 byte
        qr=True,
        operation_code=op_code,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=(int.from_bytes(buf[2:3]) & 0b1) == 1,

        # 1 byte
        recursion_available=False,
        reserved=0,
        response_code=0 if op_code == 0 else 4,

        question_count=int.from_bytes(buf[4:6]),
        answer_record_count=int.from_bytes(buf[6:8]),
        authority_record_count=0,
        additional_record_count=0,
    )

    return header
