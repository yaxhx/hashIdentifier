import argparse
import sys
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.table import Table

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class hashCandidate:
    algorithm: str
    confidence: Confidence
    reason: str

PREFIX_RULES : list[tuple[str, str, str]] = [
    ("$argon2id$", "Argon2id", "modern phc string"),
    ("$argon2i$", "Argon2i", "phc string"),
]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

HEX_LENGTH_RULES: dict[int, list[str]] = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    
}



def _is_hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)


_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1 


def _is_mysql5(text: str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)




_DESCRYPT_CHARSET : frozenset[str] = frozenset( 
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz" 
)
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
        )




def identify(raw_input: str) -> list[hashCandidate]:
    text = raw_input.strip()
    
    if not text:
        return []
    
    
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return[
                hashCandidate(
                    algorithm=algorithm,
                    confidence="high",
                    reason=f"prefix `{prefix}` - {note}",
                )
            ]
    
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        if(len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [hashCandidate(algorithm="NetNTLMv2", confidence="high", reason="user::domain::challenge::hmac::blob shape")]
        if(len(parts) >= 6 and len(parts[3]) ==48  and _is_hex(parts[3])):
            return [hashCandidate(algorithm="NetNTLMv1", confidence="high", reason="user::domain:lm(48 hex):nt(48 hex):challenge shape")]  
    
    if _is_mysql5(text):
        return [hashCandidate(algorithm="MySQL5", confidence="high", reason="starts with `*` folllowd by  40 uppercase chars")]
    if _is_descrypt(text):
        return [hashCandidate(algorithm="DES crypt", confidence="medium",)]
    
    
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[hashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length"
            )
            candidates.append(
                hashCandidate(algorithm=algorithm, confidence=confidence, reason=f"{len(text)} hex chars - {label}")
            )
            return candidates   
    
    
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name= rest.split("$", 1)[0]
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [hashCandidate(algorithm=f"PHC string ({algo_name})", confidence="low", reason=f"`$(algo_name)$..` shape - generic PHC no specific rule" )]
            
    
    if text.startswith("eyJ"):
        return [hashCandidate(algorithm="JWT (not a hash)", confidence="low", reason="leading `eyJ` is base64" )]
    if any(c in text for c in "+/=")  and len(text)>8:
        return [hashCandidate(algorithm="base64 blob not a hash", confidence="low", reason="contains base64  only chars")]
        
    
    return []

    
def _build_argument_parse() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
        prog = "hashid",
        description = (
            "Identify a hash string by prefix, length, and charset. "
            "Returns ranked candidates with confidence and reasoning."
        ),
    )
        parser.add_argument(
            "hash",
            help =
            "The hash string to identify (wrap in single quotes if it contains $).",
        )
        parser.add_argument(
            "--top",
            "-n",
            type = int,
            default = 5,
            help = "Show at most this many candidates (default: 5).",
        )
        return parser

    
    
    
def _render_table(raw_input:str, candidates: list[hashCandidate], console:Console) -> None:
    table = Table(title=f"Candidates for: {raw_input.strip()}",
    title_style="bold cyan",
    show_lines=False
    )
    table.add_column("algorithm", style="bold white", no_wrap=True)
    table.add_column("confidence", no_wrap=True)
    table.add_column("reason", style="dim")
    
    confidence_colors: dict[Confidence, str] = {
        "high": "green",
        "medium": "orange",
        "low": "red"
    }
    
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
        )
    console.print(table)
    
    
    


def main() -> int:
    parser = _build_argument_parse()
    args = parser.parse_args()
    console = Console()
    
    candidates = identify(args.hash)
    
    if not candidates:
        console.print("[red] No identification possible.[/red]")
        return 1
    
    trimmed = candidates[:args.top]
    _render_table(args.hash, trimmed, console)
    
    if trimmed[0].confidence == "high":
        console.print("\n[dim]Next step: try the matching cracker [/dim]")
        "(see ../../beginner/hash-cracker).[/dim]"
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
    
    
    
