"""
Eclipse Plus key tool (for the seller only, not shipped in the exe).

  python tools\\license_tool.py init                       create the signing key pair (once)
  python tools\\license_tool.py issue "Mario Rossi" --months 1
  python tools\\license_tool.py issue "mario@example.com" --until 2027-12-31
  python tools\\license_tool.py issue "Mario Rossi" --lifetime
  python tools\\license_tool.py check ECL1-...             show what a key contains

The PRIVATE key is kept in %USERPROFILE%\\.eclipse-plus\\signing_key.txt, outside the repository.
Never commit it or share it: whoever has it can create unlimited Plus keys. Back it up somewhere
safe; if it is lost, keys can no longer be issued for the current releases.
"""
import argparse
import calendar
import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import plus  # noqa: E402

KEY_DIR = os.path.join(os.path.expanduser("~"), ".eclipse-plus")
KEY_FILE = os.path.join(KEY_DIR, "signing_key.txt")
PLUS_PY = os.path.join(ROOT, "src", "plus.py")


def load_secret():
    try:
        with open(KEY_FILE, encoding="ascii") as f:
            return bytes.fromhex(f.read().strip())
    except OSError:
        sys.exit(f"No signing key at {KEY_FILE}: run 'init' first.")


def cmd_init(_):
    if os.path.exists(KEY_FILE):
        sys.exit(f"A signing key already exists at {KEY_FILE}. Refusing to overwrite it "
                 "(that would invalidate every key already sold).")
    os.makedirs(KEY_DIR, exist_ok=True)
    secret = os.urandom(32)
    with open(KEY_FILE, "w", encoding="ascii") as f:
        f.write(secret.hex())
    pub = plus.public_from_secret(secret).hex()
    src = open(PLUS_PY, encoding="utf-8").read()
    new = re.sub(r'^PUBLIC_KEY = "[^"]*"', f'PUBLIC_KEY = "{pub}"', src, count=1, flags=re.M)
    with open(PLUS_PY, "w", encoding="utf-8") as f:
        f.write(new)
    print(f"Private key saved to {KEY_FILE}  (back it up, never share it)")
    print(f"Public key written into src/plus.py: {pub}")


def add_months(d, n):
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return d.replace(year=y, month=m, day=min(d.day, calendar.monthrange(y, m)[1]))


def cmd_issue(a):
    secret = load_secret()
    if plus.public_from_secret(secret).hex() != plus.PUBLIC_KEY:
        sys.exit("The signing key does not match PUBLIC_KEY in src/plus.py.")
    if a.lifetime:
        exp = "0"
    elif a.until:
        exp = datetime.date.fromisoformat(a.until).strftime("%Y%m%d")
    else:
        exp = add_months(datetime.date.today(), a.months).strftime("%Y%m%d")
    key = plus.make_key(secret, a.owner, exp)
    info = plus.parse_key(key)
    print(key)
    print(f"owner: {info['owner']}   expires: {'never' if exp == '0' else exp}   id: {info['id']}",
          file=sys.stderr)


def cmd_check(a):
    try:
        print(plus.parse_key(a.key))
    except ValueError as e:
        sys.exit(str(e))


ap = argparse.ArgumentParser(description="Eclipse Plus key tool")
sub = ap.add_subparsers(dest="cmd", required=True)
sub.add_parser("init").set_defaults(fn=cmd_init)
p = sub.add_parser("issue")
p.add_argument("owner", help="name or e-mail of the customer (shown in the app)")
g = p.add_mutually_exclusive_group()
g.add_argument("--months", type=int, default=1)
g.add_argument("--until", help="YYYY-MM-DD")
g.add_argument("--lifetime", action="store_true")
p.set_defaults(fn=cmd_issue)
p = sub.add_parser("check")
p.add_argument("key")
p.set_defaults(fn=cmd_check)
args = ap.parse_args()
args.fn(args)
