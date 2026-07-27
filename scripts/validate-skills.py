import os
import re
import sys

SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", ".opencode", "skills")
errors = []

for folder in sorted(os.listdir(SKILLS_DIR)):
    folder_path = os.path.join(SKILLS_DIR, folder)
    if not os.path.isdir(folder_path):
        continue

    skill_file = os.path.join(folder_path, "SKILL.md")
    if not os.path.exists(skill_file):
        errors.append(f"[MISSING] {folder}: no SKILL.md found")
        continue

    with open(skill_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Check YAML frontmatter delimiters
    if not content.startswith("---"):
        errors.append(f"[BAD] {folder}: SKILL.md must start with ---")
        continue

    second = content.find("---", 3)
    if second == -1:
        errors.append(f"[BAD] {folder}: missing closing --- in frontmatter")
        continue

    frontmatter = content[3:second].strip()

    # Extract name field
    name_match = re.search(r"^name:\s*(.+)$", frontmatter, re.MULTILINE)
    if not name_match:
        errors.append(f"[BAD] {folder}: missing 'name' field in frontmatter")
        continue

    skill_name = name_match.group(1).strip()
    if skill_name != folder:
        errors.append(f"[MISMATCH] {folder}: name field is '{skill_name}' but folder is '{folder}'")

    # Extract description field
    desc_match = re.search(r"^description:\s*(.+)$", frontmatter, re.MULTILINE)
    if not desc_match:
        errors.append(f"[BAD] {folder}: missing 'description' field in frontmatter")
        continue

    desc = desc_match.group(1).strip()
    if len(desc) < 10:
        errors.append(f"[SHORT] {folder}: description too short ({len(desc)} chars)")

if errors:
    print(f"Found {len(errors)} error(s):\n")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print(f"All {len([d for d in os.listdir(SKILLS_DIR) if os.path.isdir(os.path.join(SKILLS_DIR, d))])} skills valid.")
    sys.exit(0)
