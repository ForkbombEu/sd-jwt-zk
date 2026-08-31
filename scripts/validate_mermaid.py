#!/usr/bin/env python3
# Copyright (C) 2026 by The Forkbomb Company
# designed, written and maintained by Denis Roio
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
