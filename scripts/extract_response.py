
import argparse
import json
import re
from pathlib import Path


def extract_code(response_path: Path) -> str:
    response = json.loads(response_path.read_text(encoding="utf-8-sig"))
    code = "\n".join(
        block["text"]
        for block in response["content"]
        if block["type"] == "text"
    ).strip()

    # Extract a single fenced Python block, allowing surrounding explanation.
    fences = re.findall(
        r"^[ \t]*```(?:python|py)?[ \t]*\r?\n(.*?)^[ \t]*```[ \t]*$",
        code,
        flags=re.DOTALL | re.IGNORECASE | re.MULTILINE,
    )

    if fences:
        if len(fences) != 1:
            raise ValueError(
                "Response contains multiple code blocks; manual review required."
            )
        code = fences[0].strip()
    elif "```" in code:
        raise ValueError(
            "Response contains an unrecognized or malformed code fence."
        )

    if not code.strip():
        raise ValueError("Response contains no Python code.")

    return code + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("response", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    code = extract_code(args.response)
    compile(code, str(args.response), "exec")  # Checks syntax only.

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as output:
        output.write(code)

    print(f"Saved: {args.out}")
    print("Syntax check passed. Code was not executed.")


if __name__ == "__main__":
    main()
