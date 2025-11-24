"""Basit komut satırı hesap makinesi.

İki sayıyı toplama, çıkarma, çarpma ve bölme işlemlerine yönelik sade bir
komut satırı arayüzü sağlar. Bölme işleminde sıfıra bölme hatası kullanıcıya
anlaşılır bir uyarı olarak döner.
"""
from __future__ import annotations

import argparse
import sys
from typing import Callable, Dict


def safe_divide(x: float, y: float) -> float:
    """Y'yi sıfır olduğunda kullanıcı dostu bir mesajla hata yükselt."""

    if y == 0:
        raise ValueError("Sıfıra bölme yapılmaz.")
    return x / y


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Basit hesap makinesi.\n"
            "İşlem ve iki sayı girin. Örnek: 'python hesap_mac.py topla 2 3'"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("operation", choices=["topla", "cikar", "carp", "bol"], help="Yapılacak işlem")
    parser.add_argument("x", type=float, help="Birinci sayı")
    parser.add_argument("y", type=float, help="İkinci sayı")
    return parser


def main() -> None:
    operations: Dict[str, Callable[[float, float], float]] = {
        "topla": lambda a, b: a + b,
        "cikar": lambda a, b: a - b,
        "carp": lambda a, b: a * b,
        "bol": safe_divide,
    }

    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()

    hesapla = operations[args.operation]
    try:
        sonuc = hesapla(args.x, args.y)
    except ValueError as exc:
        print(f"Hata: {exc}")
        raise SystemExit(1)

    print(f"Sonuç: {sonuc}")


if __name__ == "__main__":
    main()
