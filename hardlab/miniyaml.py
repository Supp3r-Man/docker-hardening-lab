"""A tiny YAML subset reader, just enough for docker-compose.yml, so the lab needs no PyYAML.

Supported: nested mappings by indentation, lists of scalars (`- item`), inline lists
(`[a, b]`), quoted and plain scalars, booleans, ints, floats, `#` comments. Anything else
(anchors, multi-line strings, lists of mappings) raises ValueError instead of guessing.
"""


def parse_yaml(text):
    rows = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise ValueError("line %d: tabs are not allowed for indentation" % number)
        rows.append((len(line) - len(line.lstrip(" ")), line.strip(), number))
    if not rows:
        return {}
    node, pos = _block(rows, 0, rows[0][0])
    if pos != len(rows):
        raise ValueError("line %d: unexpected indentation" % rows[pos][2])
    return node


def _strip_comment(line):
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _block(rows, pos, indent):
    if rows[pos][1].startswith("- ") or rows[pos][1] == "-":
        return _list(rows, pos, indent)
    return _mapping(rows, pos, indent)


def _list(rows, pos, indent):
    items = []
    while pos < len(rows) and rows[pos][0] == indent and (rows[pos][1].startswith("- ") or rows[pos][1] == "-"):
        body = rows[pos][1][1:].strip()
        # `- key: value` is a list of mappings; reject rather than mis-parse it as a string.
        # `no-new-privileges:true` has a colon but no ': ' separator, so it stays a scalar.
        if _split_key(body)[1]:
            raise ValueError("line %d: lists of mappings are not supported" % rows[pos][2])
        items.append(_scalar(body))
        pos += 1
    return items, pos


def _mapping(rows, pos, indent):
    result = {}
    while pos < len(rows) and rows[pos][0] == indent:
        text, number = rows[pos][1], rows[pos][2]
        key, sep, value = _split_key(text)
        if not sep:
            raise ValueError("line %d: expected 'key: value'" % number)
        pos += 1
        if value == "":
            if pos < len(rows) and rows[pos][0] > indent:
                result[key], pos = _block(rows, pos, rows[pos][0])
            else:
                result[key] = None
        else:
            result[key] = _scalar(value)
    if pos < len(rows) and rows[pos][0] > indent:
        raise ValueError("line %d: unexpected indentation" % rows[pos][2])
    return result, pos


def _split_key(text):
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            return text[:i].strip().strip("\"'"), ":", text[i + 1:].strip()
    return text, "", ""


def _scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(part) for part in inner.split(",")] if inner else []
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text
