#!/usr/bin/env python3
import argparse
import re
from itertools import permutations, product
from pathlib import Path

COMMON_EMAIL_PROVIDERS = {
    "aol",
    "gmx",
    "gmail",
    "hotmail",
    "icloud",
    "live",
    "mail",
    "msn",
    "outlook",
    "protonmail",
    "yahoo",
    "yandex",
}

SEPARATORS = ("", ".", "_", "-")

def parse_entry(entry):
    value = entry.strip().lower()
    company = None

    if "@" in value:
        local, domain = value.rsplit("@", 1)
        value = local
        domain_name = domain.split(".", 1)[0]
        if domain_name and domain_name not in COMMON_EMAIL_PROVIDERS:
            company = domain_name

    parts = [part for part in re.split(r"[^a-z0-9]+", value) if part]
    return parts, company


def joined_permutations(parts):
    candidates = set()
    for size in range(1, len(parts) + 1):
        for ordering in permutations(parts, size):
            for separators in product(SEPARATORS, repeat=size - 1):
                candidates.add(
                    ordering[0]
                    + "".join(separator + part for separator, part in zip(separators, ordering[1:]))
                )
    return candidates


def candidates_for_entry(entry):
    parts, company = parse_entry(entry)
    if not parts:
        return set()

    candidates = joined_permutations(parts)
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        name_parts = [first, last]
        candidates.update(joined_permutations(name_parts))
        candidates.update(
            {
                f"{first[0]}{last}",
                f"{first[0]}.{last}",
                f"{first[0]}_{last}",
                f"{first}{last[0]}",
                f"{first}.{last[0]}",
                f"{last}{first[0]}",
                f"{last}.{first[0]}",
            }
        )

        if company:
            candidates.update(joined_permutations([first, last, company]))
            candidates.update(
                {
                    f"{first}.{company}",
                    f"{last}.{company}",
                    f"{first[0]}{last}.{company}",
                    f"{first[0]}.{last}.{company}",
                    f"{first}{last}.{company}",
                    f"{last}.{first}.{company}",
                }
            )
    elif company:
        candidates.update(joined_permutations([parts[0], company]))

    return candidates


def generate(input_path, output_path):
    candidates = set()
    with input_path.open(encoding="utf-8") as input_file:
        for line in input_file:
            candidates.update(candidates_for_entry(line))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    needs_separator = output_path.exists() and output_path.stat().st_size > 0
    if needs_separator:
        with output_path.open("rb") as existing_file:
            existing_file.seek(-1, 2)
            needs_separator = existing_file.read(1) != b"\n"

    with output_path.open("a", encoding="utf-8", newline="\n") as output_file:
        if needs_separator and candidates:
            output_file.write("\n")
        output_file.write("\n".join(sorted(candidates)))
        if candidates:
            output_file.write("\n")
    return len(candidates)


def main():
    parser = argparse.ArgumentParser(description="Generate username combinations from usernames and email addresses.")
    parser.add_argument("input", type=Path, help="Input file containing one username or email per line.")
    parser.add_argument("output", type=Path, help="Output file for the generated username list.")
    args = parser.parse_args()

    count = generate(args.input, args.output)
    print(f"Wrote {count} unique username candidates to {args.output}")


if __name__ == "__main__":
    main()
