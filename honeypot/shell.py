import unicodedata


def sanitize_for_terminal(text: str) -> str:
    kept = []

    for ch in text:
        category = unicodedata.category(ch)

        if ch == "\n" or ch == "\t":
            kept.append(ch)
        elif category == "Cc":
            continue
        else:
            kept.append(ch)

    return "".join(kept)
