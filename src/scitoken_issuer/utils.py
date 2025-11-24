import base64


def basic_decode(data: bytes | str) -> tuple[str, str]:
    data = base64.b64decode(data).decode('utf-8')
    u,p = data.split(':', 1)
    return (u,p)
