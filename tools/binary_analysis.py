#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""
binary_analysis.py — Offline firmware binary analysis for MikroTik and embedded devices.

Extracts ELF binaries from disk images and performs:
    - LIEF: ELF header parsing, section analysis, import/export enumeration
    - Security feature detection: NX, PIE, RELRO
    - Dangerous import identification: system, popen, execve, strcpy, sprintf, gets
    - Capstone: entrypoint disassembly for x86/x86_64 binaries

Requirements:
    pip install lief capstone

Usage:
    python -m tools.binary_analysis --image path/to/firmware.img --output report_dir
    python -m tools.binary_analysis --image path/to/chr-7.22.1.img.zip --output reports/mikrotik
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log_entries: list[dict[str, Any]] = []


def _add_finding(fid: str, sev: str, title: str, detail: str, evidence: str = "") -> None:
    """Register an analysis finding."""
    log_entries.append({
        "id": fid, "severity": sev, "title": title,
        "detail": detail, "evidence": evidence[:2000],
    })
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid} ({sev}): {title}")


def extract_image(src: Path, tmp_dir: Path) -> Path:
    """Extract disk image from zip/gz archive or return raw image path.

    Args:
        src: Path to image file (.img, .img.zip, .img.gz).
        tmp_dir: Temporary directory for extracted files.
    """
    tmp_dir.mkdir(parents=True, exist_ok=True)

    if src.suffix == ".zip":
        dst = tmp_dir / src.stem
        if not dst.exists():
            with zipfile.ZipFile(src) as z:
                for name in z.namelist():
                    if name.endswith(".img"):
                        dst.write_bytes(z.read(name))
                        break
        return dst
    elif src.name.endswith(".img.gz"):
        dst = tmp_dir / src.name.replace(".gz", "")
        if not dst.exists():
            with gzip.open(src, "rb") as fin:
                dst.write_bytes(fin.read())
        return dst
    return src


def extract_elf_from_disk(data: bytes, max_count: int = 50) -> list[dict[str, Any]]:
    """Scan raw disk image bytes for ELF binaries.

    Args:
        data: Raw disk image bytes.
        max_count: Maximum number of ELF binaries to extract.

    Returns:
        List of dicts with offset, size, data, and bits for each ELF found.
    """
    ELF_MAGIC = b"\x7fELF"
    elfs: list[dict[str, Any]] = []
    pos = 0

    while pos < len(data) - 4:
        idx = data.find(ELF_MAGIC, pos)
        if idx == -1:
            break
        if idx + 64 > len(data):
            break

        ei_class = data[idx + 4]
        if ei_class == 1:
            if idx + 52 > len(data):
                pos = idx + 4
                continue
            e_shoff = struct.unpack_from("<I", data, idx + 32)[0]
            e_shentsize = struct.unpack_from("<H", data, idx + 46)[0]
            e_shnum = struct.unpack_from("<H", data, idx + 48)[0]
        elif ei_class == 2:
            if idx + 64 > len(data):
                pos = idx + 4
                continue
            e_shoff = struct.unpack_from("<Q", data, idx + 40)[0]
            e_shentsize = struct.unpack_from("<H", data, idx + 58)[0]
            e_shnum = struct.unpack_from("<H", data, idx + 60)[0]
        else:
            pos = idx + 4
            continue

        elf_size = max(e_shoff + e_shentsize * e_shnum, 4096)
        if elf_size > 50 * 1024 * 1024:
            pos = idx + 4
            continue

        elf_end = min(idx + elf_size, len(data))
        elf_data = data[idx:elf_end]
        elfs.append({
            "offset": idx,
            "size": len(elf_data),
            "data": elf_data,
            "bits": 32 if ei_class == 1 else 64,
        })
        pos = elf_end
        if len(elfs) >= max_count:
            break

    return elfs


def analyze_elf(elf_data: bytes, label: str = "") -> dict[str, Any]:
    """Analyze a single ELF binary using LIEF.

    Args:
        elf_data: Raw ELF binary bytes.
        label: Human-readable label for findings.

    Returns:
        Analysis result dict with security features, imports, exports.
    """
    import lief

    result: dict[str, Any] = {"label": label, "issues": []}
    try:
        binary = lief.parse(elf_data)
        if binary is None:
            return result

        header = binary.header
        result["machine"] = str(header.machine_type)
        result["type"] = str(header.file_type)
        result["entrypoint"] = hex(header.entrypoint)
        result["bits"] = 64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32

        result["sections"] = [
            {"name": s.name, "size": s.size, "type": str(s.type)}
            for s in binary.sections
        ]

        dangerous = {
            "system", "popen", "execve", "execvp", "execl",
            "sprintf", "strcpy", "strcat", "gets", "scanf",
            "mktemp", "tmpnam",
        }
        result["imports"] = [sym.name for sym in binary.imported_symbols]
        result["dangerous_imports"] = [n for n in result["imports"] if n in dangerous]

        for fname in set(result["dangerous_imports"]):
            _add_finding(
                f"F-BIN-{fname.upper()}-{label[:20]}",
                "MEDIUM",
                f"Dangerous import: {fname}() in {label}",
                f"Binary imports {fname}() — potential buffer overflow or command injection.",
            )

        result["exports"] = [sym.name for sym in binary.exported_symbols][:50]
        result["nx"] = binary.has_nx if hasattr(binary, "has_nx") else True
        result["pie"] = binary.is_pie if hasattr(binary, "is_pie") else False

        has_relro = any(
            seg.type == lief.ELF.Segment.TYPE.GNU_RELRO
            for seg in binary.segments
        )
        full_relro = any(
            d.tag == lief.ELF.DynamicEntry.TAG.FLAGS and hasattr(d, "value") and d.value & 0x8
            for d in binary.dynamic_entries
        )
        result["relro"] = "full" if full_relro else ("partial" if has_relro else "none")

        if not result["nx"]:
            _add_finding(
                f"F-BIN-NO-NX-{label[:20]}", "HIGH",
                f"No NX protection: {label}",
                "Executable stack — direct shellcode execution possible.",
            )
        if not result["pie"]:
            _add_finding(
                f"F-BIN-NO-PIE-{label[:20]}", "MEDIUM",
                f"No PIE: {label}",
                "Fixed load address — ROP and return-to-libc attacks easier.",
            )
    except Exception as e:
        result["error"] = str(e)
    return result


def disassemble_entry(elf_data: bytes, bits: int = 64, count: int = 30) -> list[str]:
    """Disassemble the ELF entrypoint using Capstone.

    Args:
        elf_data: Raw ELF bytes.
        bits: 32 or 64.
        count: Max instructions to disassemble.

    Returns:
        List of disassembled instruction strings.
    """
    import lief
    import capstone

    try:
        binary = lief.parse(elf_data)
        if binary is None:
            return []
        entry = binary.header.entrypoint
        for section in binary.sections:
            if section.virtual_address <= entry < section.virtual_address + section.size:
                offset = entry - section.virtual_address
                code = bytes(section.content)[offset:offset + 500]
                arch = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
                md = capstone.Cs(capstone.CS_ARCH_X86, arch)
                return [
                    f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                    for insn in list(md.disasm(code, entry))[:count]
                ]
    except Exception as e:
        return [f"Error: {e}"]
    return []


def analyze_image(name: str, img_path: Path, max_elfs: int = 30) -> list[dict[str, Any]]:
    """Run full binary analysis on a firmware disk image.

    Args:
        name: Human-readable target name.
        img_path: Path to raw disk image.
        max_elfs: Maximum number of ELF binaries to analyze.

    Returns:
        List of analysis result dicts for each ELF binary.
    """
    print(f"\n{'='*70}")
    print(f"  {name} — DEEP BINARY ANALYSIS")
    print(f"{'='*70}")

    data = img_path.read_bytes()
    print(f"  Image size: {len(data) // 1024 // 1024} MB")
    print("  Searching for ELF binaries...")

    elfs = extract_elf_from_disk(data, max_count=max_elfs + 20)
    print(f"  Found {len(elfs)} ELF binaries")

    results: list[dict[str, Any]] = []
    for i, elf in enumerate(elfs[:max_elfs]):
        sz_kb = elf["size"] // 1024
        label = f"ELF@0x{elf['offset']:08X}_{sz_kb}KB"
        print(f"\n  [{i+1}/{min(len(elfs), max_elfs)}] {label} ({elf['bits']}-bit, {sz_kb} KB)")

        r = analyze_elf(elf["data"], label)
        r["offset"] = elf["offset"]
        r["size"] = elf["size"]

        if r.get("imports"):
            print(f"    Imports: {len(r['imports'])}")
        if r.get("dangerous_imports"):
            print(f"    !!! Dangerous: {', '.join(r['dangerous_imports'])}")

        print(f"    Security: NX={r.get('nx','?')} PIE={r.get('pie','?')} RELRO={r.get('relro','?')}")

        machine = str(r.get("machine", ""))
        if elf["bits"] == 64 and "X86_64" in machine:
            asm = disassemble_entry(elf["data"], 64, 10)
            if asm and not asm[0].startswith("Error"):
                r["entry_asm"] = asm
                print(f"    Entry ASM: {asm[0]}")

        results.append(r)
    return results


def generate_report(
    target_name: str,
    results: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    """Generate markdown report from analysis results.

    Args:
        target_name: Human-readable target name.
        results: List of analysis result dicts.
        output_dir: Directory to write the report.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "binary_analysis_report.md"
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    lines = [
        f"# {target_name} — Deep Binary Analysis Report",
        f"> Generated: {ts}",
        "> Analyst: André Henrique (@mrhenrike) | União Geek",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"- ELF binaries analyzed: {len(results)}",
        f"- Without NX: {sum(1 for r in results if not r.get('nx'))}",
        f"- Without PIE: {sum(1 for r in results if not r.get('pie'))}",
        f"- Without RELRO: {sum(1 for r in results if r.get('relro') == 'none')}",
        f"- With dangerous imports: {sum(1 for r in results if r.get('dangerous_imports'))}",
        "",
    ]

    all_dangerous: Counter = Counter()
    for r in results:
        for imp in r.get("dangerous_imports", []):
            all_dangerous[imp] += 1
    if all_dangerous:
        lines += ["## Most Common Dangerous Imports", ""]
        for func, cnt in all_dangerous.most_common(10):
            lines.append(f"- `{func}()`: found in {cnt} binaries")
        lines.append("")

    lines += ["## Binary Details", ""]
    for r in results:
        label = r.get("label", "?")
        lines += [
            f"### {label}",
            "",
            "| Property | Value |",
            "|----------|-------|",
            f"| Offset | `0x{r.get('offset', 0):08X}` |",
            f"| Size | {r.get('size', 0):,} bytes |",
            f"| Arch | {r.get('machine', '?')} |",
            f"| NX | {r.get('nx', '?')} |",
            f"| PIE | {r.get('pie', '?')} |",
            f"| RELRO | {r.get('relro', '?')} |",
            "",
        ]
        if r.get("dangerous_imports"):
            lines.append(f"**Dangerous imports**: `{', '.join(r['dangerous_imports'])}`\n")
        if r.get("entry_asm"):
            lines += ["```asm"]
            lines.extend(r["entry_asm"][:10])
            lines += ["```", ""]

    lines += [
        "---",
        "*Binary Analysis Engine — MikrotikAPI-BF*",
        "*André Henrique (@mrhenrike) | União Geek*",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  Report: {path}")

    json_path = output_dir / "binary_analysis_findings.json"
    json_path.write_text(json.dumps(log_entries, indent=2, default=str), encoding="utf-8")


def main() -> None:
    """CLI entrypoint for binary analysis tool."""
    parser = argparse.ArgumentParser(
        description="Offline firmware binary analysis for MikroTik and embedded devices",
    )
    parser.add_argument("--image", required=True, help="Path to firmware image (.img, .img.zip, .img.gz)")
    parser.add_argument("--output", required=True, help="Output directory for reports")
    parser.add_argument("--name", default="Firmware", help="Target name for report header")
    parser.add_argument("--max-elfs", type=int, default=30, help="Max ELF binaries to analyze")
    args = parser.parse_args()

    img_src = Path(args.image)
    if not img_src.exists():
        print(f"Error: Image not found: {img_src}")
        sys.exit(1)

    tmp_dir = Path(args.output) / ".tmp"
    img_path = extract_image(img_src, tmp_dir)

    results = analyze_image(args.name, img_path, max_elfs=args.max_elfs)
    generate_report(args.name, results, Path(args.output))

    print(f"\n{'='*70}")
    print(f"  COMPLETE: {len(log_entries)} findings across {len(results)} binaries")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
