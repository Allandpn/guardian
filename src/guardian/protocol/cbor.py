"""Decodificador CBOR mínimo, só o que o WebAuthn usa (attestationObject e chave COSE)."""


class CborError(ValueError):
    pass


def decode(data: bytes):
    """Decodifica o primeiro item. Devolve (valor, resto)."""
    value, pos = _item(data, 0, 0)
    return value, data[pos:]


def _item(d: bytes, pos: int, depth: int):
    if depth > 8:
        raise CborError("aninhamento demais")
    if pos >= len(d):
        raise CborError("fim inesperado")
    head = d[pos]
    major, info = head >> 5, head & 0x1F
    pos += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if pos + n > len(d):
            raise CborError("fim inesperado")
        arg = int.from_bytes(d[pos:pos + n], "big")
        pos += n
    else:
        raise CborError("comprimento indefinido não suportado")

    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if pos + arg > len(d):
            raise CborError("fim inesperado")
        raw = d[pos:pos + arg]
        return (raw if major == 2 else raw.decode("utf-8")), pos + arg
    if major == 4:
        if arg > 64:
            raise CborError("array grande demais")
        out = []
        for _ in range(arg):
            v, pos = _item(d, pos, depth + 1)
            out.append(v)
        return out, pos
    if major == 5:
        if arg > 64:
            raise CborError("mapa grande demais")
        out = {}
        for _ in range(arg):
            k, pos = _item(d, pos, depth + 1)
            v, pos = _item(d, pos, depth + 1)
            out[k] = v
        return out, pos
    if major == 6:
        return _item(d, pos, depth + 1)  # ignora a etiqueta
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
    raise CborError("tipo CBOR não suportado")
