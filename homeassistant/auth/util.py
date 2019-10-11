"""Auth utils."""
import base64
import binascii
import os
import unicodedata

from typing import cast, Optional

import bcrypt


def generate_secret(entropy: int = 32) -> str:
    """Generate a secret.

    Backport of secrets.token_hex from Python 3.6

    Event loop friendly.
    """
    return binascii.hexlify(os.urandom(entropy)).decode("ascii")


def unicode_normalize(inp: str) -> str:
    """Normalize the (Unicode) string.

    Multiple Unicode encodings exist for the same string. For example, differen
    browser(versions) can have differing Unicode representations for the same
    string.

    This method applies applies NFKC normalization.

    See 5.1.1.2 in [0].

    [0]: https://pages.nist.gov/800-63-3/sp800-63b.html

    Args:
        inp (str): Unicode string to normalize

    Returns:
        str: Unicode normalized string

    """
    return unicodedata.normalize("NFKD", inp)


def hash_password(password: str) -> str:
    """Hash a password and return it (as base64 string).

        1: Unicode normalize the password
        2: Create new hash
        3: Return string of base64 encoding of said hash.

    Args:
        password (str): The password to hash.o
        for_storage (bool): Whether to base64 encode the resulting hash

    Returns:
        str: String containing base64 encoded password hash

    """
    pw_norm_bytes = unicode_normalize(password).encode()
    h: bytes = bcrypt.hashpw(pw_norm_bytes, bcrypt.gensalt(rounds=12))

    return base64.b64encode(h).decode()


def verify_password(password: str, base64_hash: Optional[str]) -> bool:
    """Check a password against its (base64 string) hash.

        1: Base64 decode the provided hash, if it exists.
           verifying None (missing hash) is as fast as verifying a real hash.
        2: Unicode normalize the password.
        3: Check password and return

    Behaviour is constant time by checking against a static hash when no hash
    is available before returning False.

    Args:
        password (str): The password to verify.
        base64_hash (Optional[bytes]): base64 of password hash to verify
            against if one is available.

    Returns:
        bool: Whether the password matches the given hash.

    """
    pw_norm_bytes = unicode_normalize(password).encode()

    # bcrypt.checkpw is constant time.
    if base64_hash:
        return cast(bool, bcrypt.checkpw(pw_norm_bytes, base64.b64decode(base64_hash)))
    else:
        # dummy password, *12* rounds as in gensalt(..) above.
        dummy = b"$2b$12$CiuFGszHx9eNHxPuQcwBWez4CwDTOcLTX5CbOpV6gef2nYuXkY7BO"
        # There is no hash -> take similar amount of time.
        bcrypt.checkpw(pw_norm_bytes, dummy)

        return False
