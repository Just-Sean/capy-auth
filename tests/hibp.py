"""A stand-in for Have I Been Pwned's range API, so no test goes over the network."""

import hashlib

# A real answer is padded to hundreds of lines; padding lines have a count of 0.
PADDING = [f"{number:035X}:0" for number in range(800)]


def suffix_of(password):
    """The part of the password's SHA-1 hash the service lists (after the 5-character
    prefix)."""
    return hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()[5:]


def answer(found=None, count=1):
    """A padded answer, listing the password `found` (if any) `count` times."""
    lines = [*PADDING, *([f"{suffix_of(found)}:{count}"] if found else [])]
    return "\r\n".join(lines)


class StandInResponse:
    def __init__(self, status=200, body=None):
        self.status = status
        self.body = answer().encode() if body is None else body
        self.reads = []

    def read(self, amount):
        self.reads.append(amount)
        chunk, self.body = self.body[:amount], self.body[amount:]
        return chunk


class HibpStandIn:
    """Takes the place of http.client.HTTPSConnection for api.pwnedpasswords.com."""

    made = []
    response = None  # None: a fresh padded answer that lists nothing

    def __init__(self, host, timeout):
        self.host, self.timeout, self.closed = host, timeout, False
        HibpStandIn.made.append(self)

    def request(self, method, path, headers):
        self.method, self.path, self.headers = method, path, headers

    def getresponse(self):
        self.response = HibpStandIn.response or StandInResponse()
        return self.response

    def close(self):
        self.closed = True
