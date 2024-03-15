import socket
import sys

from app.classes.dns_message import parse_dns_message

ADDRESS = "127.0.0.1"
PORT = 2053


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((ADDRESS, PORT))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            msg = parse_dns_message(buf)

            # Here we assume that the resolver only supports one question at a time
            if len(sys.argv) >= 3 and sys.argv[1] == "--resolver":
                forward_ip, forward_port = sys.argv[2].split(":")
                answers = []
                questions = msg.questions
                for question in questions:
                    # Change the question to the one we want to forward
                    msg.questions = [question]
                    msg.header.question_count = 1
                    msg.header.qr = False

                    # Send the message to the forwarder
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(msg.encode(), (forward_ip, int(forward_port)))
                    response, _ = sock.recvfrom(512)
                    response_message = parse_dns_message(response)
                    if response_message.answers:
                        answers.append(response_message.answers[0])

                msg.questions = questions
                msg.answers = answers
                msg.header.question_count = len(questions)
                msg.header.answer_record_count = len(answers)
                msg.header.qr = True
            else:
                msg.generate_answers()

            response = msg.encode()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
