import argparse
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv

parser = argparse.ArgumentParser()
parser.add_argument("effort", choices=["low", "medium", "high"])
args = parser.parse_args()

# The script is in pilot/, so go up to the repository root.
root = Path(__file__).resolve().parent.parent
load_dotenv(root / ".env")

output = root / "runs" / "pilot" / f"product_search_{args.effort}_ordinary.json"
if output.exists():
    raise SystemExit(f"Pilot already saved: {output}")

prompt = (root / "prompts" / "product_search_prompt.txt").read_text(encoding="utf-8")

response = Anthropic().messages.create(
    model="claude-sonnet-5-5",
    max_tokens=4096,
    thinking={"type": "adaptive"},
    output_config={"effort": args.effort},
    messages=[{"role": "user", "content": prompt}],
)

output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(response.model_dump_json(indent=2), encoding="utf-8")

print(f"Saved: {output}")
print(f"Stop reason: {response.stop_reason}")
print(f"Input tokens: {response.usage.input_tokens}")
print(f"Output tokens: {response.usage.output_tokens}")