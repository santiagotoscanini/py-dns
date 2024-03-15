from dataclasses import dataclass

from app.classes.answer import DNSAnswer, parse_dns_answer
from app.classes.header import DNSHeader, parse_dns_header
from app.classes.question import DNSQuestion, parse_dns_question
from app.dns_database import dns_database


@dataclass
class DNSMessage:
    header: DNSHeader
    questions: list[DNSQuestion]
    answers: list[DNSAnswer] = None

    def generate_answers(self):
        self.answers = []
        for q in self.questions:
            if q.name in dns_database:
                answer = DNSAnswer(dns_question=q)
                answer.calculate_answer()
                self.answers.append(answer)
        self.header.answer_record_count = len(self.answers)

    def encode(self) -> bytearray:
        res = bytearray()
        res.extend(self.header.encode())
        for q in self.questions:
            res.extend(q.encode())
        if self.answers:
            for a in self.answers:
                res.extend(a.encode())
        return res


def parse_dns_message(buf: bytes) -> DNSMessage:
    header = parse_dns_header(buf)

    questions = []
    previous_index = 12
    for i in range(header.question_count):
        question, previous_index = parse_dns_question(buf, previous_index)
        questions.append(question)

    answers = []
    for i in range(header.answer_record_count):
        answer, previous_index = parse_dns_answer(buf, previous_index)
        answers.append(answer)

    return DNSMessage(
        header=header,
        questions=questions,
        answers=answers
    )
