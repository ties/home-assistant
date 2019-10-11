"""Tests for the utils."""
import base64
import bcrypt

# import time

from homeassistant.auth.util import hash_password, verify_password, unicode_normalize


def test_normalize_is_working():
    """Valide unicode normalization.

    Validate that unicode normalization function is working and does not return
    a wrong result (None, "", "a_constant").

    Test cases taken from [0] and [1].
    [0]: https://github.com/tombentley/saslprep/blob/master/src/test/java/com/github/tombentley/saslprep/SaslPrepTest.java
    [1]: https://unicode.org/reports/tr15/#Examples

    """
    # Naieve path
    assert "user" == unicode_normalize("user")
    assert "user" != unicode_normalize("USER")
    # Normalized paths
    assert "I\xadX" == unicode_normalize("I\u00ADX")
    assert "A B" == unicode_normalize("A\u00A0B")

    # unicode.org examples:
    assert "A\u0308ffin" == unicode_normalize("Äffin")
    assert "A\u0308ffin" == unicode_normalize("Ä\uFB03n")

    assert "Henry IV" == unicode_normalize("Henry \u2163")


def test_hash_password():
    """Test password hashing."""
    # hash is base64-encoded by default, and validates
    h_bytes = base64.b64decode(hash_password("password").encode())
    assert bcrypt.checkpw("password".encode(), h_bytes)

    # wrong password does not validate
    assert not bcrypt.checkpw("password2".encode(), h_bytes)


def test_verify_password():
    """Test password verification."""
    # h('password')
    h_bcrypt64 = "JDJiJDEyJC9rZHhBY1VRNDMyQmd3S3poVHdHTS5DS3E3Z0RIQWhnRElZRTN6eVRpckRhaG1hNkVzaGhL"
    # Test that it verifies a base64-ed hash (bcrypt) password.
    assert verify_password("password", h_bcrypt64)

    # Test that it supports empty hashes
    assert not verify_password("password", None)


# def test_verify_password_empty_is_slow():
#     """Validate that validating against empty has is similarly fast
#
#     Validate that validating a correct password, wrong password, and empty
#     hash are about equally slow.
#
#     """
#     h_bcrypt64 = 'JDJiJDEyJC9rZHhBY1VRNDMyQmd3S3poVHdHTS5DS3E3Z0RIQWhnRElZRTN6eVRpckRhaG1hNkVzaGhL'
#     h_wrong = base64.b64encode("".encode())

#     t0 = time.perf_counter()
#     for x in range(25):
#         verify_password("", None)
#     t1 = time.perf_counter()

#     t_verify_missing_hash = t1-t0

#     t0 = time.perf_counter()
#     for x in range(25):
#         verify_password("", h_bcrypt64)
#     t1 = time.perf_counter()

#     t_bcrypt_incorrect = t1-t0

#     t0 = time.perf_counter()
#     for x in range(25):
#         verify_password("password", h_bcrypt64)
#     t1 = time.perf_counter()

#     t_bcrypt_correct = t1-t0

#     print(t_bcrypt_correct, t_bcrypt_incorrect, t_verify_missing_hash)

#     assert 0.90 < (t_bcrypt_correct / t_bcrypt_incorrect) < 1.10
#     assert 0.90 < (t_bcrypt_correct / t_verify_missing_hash) < 1.10
