#!/usr/bin/env python3
"""Small offline structural validator for the checked-in Mermaid diagrams."""
import re
from pathlib import Path
text = (Path(__file__).resolve().parents[1] / "spec/protocol-sequences.md").read_text()
blocks = re.findall(r"```mermaid\n(.*?)```", text, re.S)
if len(blocks) != 6: raise SystemExit("expected six Mermaid diagrams")
for block in blocks:
    lines = [x.strip() for x in block.splitlines() if x.strip()]
    if not lines or lines[0] != "sequenceDiagram": raise SystemExit("missing sequenceDiagram")
    participants = {re.match(r"participant (\w+)", x).group(1) for x in lines if re.match(r"participant (\w+)", x)}
    arrows = [re.match(r"(\w+)(?:--|-)>>(\w+):", x) for x in lines]
    arrows = [x for x in arrows if x]
    if not participants or not arrows or any(a.group(1) not in participants or a.group(2) not in participants for a in arrows): raise SystemExit("invalid participants/arrows")
    if not any(x.startswith("Note over") for x in lines) or "alt " not in "\n".join(lines): raise SystemExit("missing crypto note or abort path")
    opens = sum(x.startswith(("alt ", "opt ", "rect ", "loop ", "par ", "critical ")) for x in lines)
    if opens != sum(x == "end" for x in lines): raise SystemExit("unbalanced Mermaid block")
print("Mermaid OK: 6 sequence diagrams")
