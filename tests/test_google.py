"""Sign in with Google, checked in-process with its own empty data folder and the network replaced."""
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

os.environ["PEAKCUT_DATA"] = tempfile.mkdtemp(prefix="pc-google-")
os.environ["DATABASE_URL"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlalchemy as sa  # noqa: E402
from studio import auth, db  # noqa: E402

db.init()
fails = []


def check(name, got, want):
    ok = got == want if not callable(want) else want(got)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"   got {got!r}"))
    if not ok:
        fails.append(name)


def google(sub, email):
    """Run the Google callback with Google's answer faked. Returns the user row id, or the AuthError text."""
    _, state = auth.google_url()
    token = mock.Mock(status_code=200)
    token.json.return_value = {"access_token": "t"}
    info = mock.Mock(status_code=200)
    info.json.return_value = {"sub": sub, "email": email, "email_verified": True, "name": "Test"}
    with mock.patch.object(auth.httpx, "post", return_value=token), mock.patch.object(auth.httpx, "get", return_value=info):
        try:
            return auth.google_finish("code", state)[0].id
        except auth.AuthError as e:
            return str(e)


def row(uid):
    with db.engine.begin() as c:
        return c.execute(sa.select(db.users).where(db.users.c.id == uid)).first()


# a password-only account already holds the email the renamed Google user will switch to
pw_taken = auth._create("renamed@acme.com", "Old Password", password_hash=auth.hash_password("pw-only-123"))[0].id

# ---- user 1 signs in with Google and gets an account
u1 = google("sub-1", "shared@acme.com")
check("first Google sign-in creates an account", isinstance(u1, str) and u1.startswith("u_"), True)

# ---- a different Google account cannot take over that email
check("second Google account on the same email is refused",
      google("sub-2", "shared@acme.com"), "That email is already linked to a different Google account.")
check("refused account did not change the first user", row(u1).google_sub, "sub-1")

# ---- returning user 1 keeps the account even when Google now reports a taken email
check("returning Google user keeps the account after an email change",
      google("sub-1", "renamed@acme.com"), u1)
check("returning user did not touch the password-only row", row(pw_taken).google_sub, None)

# ---- a password-only account is linked to the Google owner of that email
pw = auth._create("pw@acme.com", "Password Only", password_hash=auth.hash_password("pw-only-456"))[0].id
check("password-only user signs in with Google and is linked", google("sub-pw", "pw@acme.com"), pw)
check("link sets google_sub", row(pw).google_sub, "sub-pw")
check("link clears password_hash", row(pw).password_hash, None)

print("\n%d failed" % len(fails) if fails else "\nALL PASSED")
shutil.rmtree(os.environ["PEAKCUT_DATA"], ignore_errors=True)
sys.exit(1 if fails else 0)
