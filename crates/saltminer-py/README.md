# saltminer

Identify and audit password hashes — offline.

`saltminer` is the Python interface to the Saltminer engine (written in Rust).
Give it a hash string and it tells you what algorithm most likely produced it,
and whether that choice is still considered secure under current OWASP guidance.
It recognises 45+ hash formats — bcrypt, the Argon2 family, the Unix crypt
family, phpass, LDAP schemes, Django, MySQL, NetNTLM, and bare hex digests.

## Install

    pip install saltminer

## Usage

    import saltminer

    saltminer.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    # [('MD5', 'medium', '32 hex chars — most likely at this length'),
    #  ('NTLM', 'low', '32 hex chars — also possible at this length'), ...]

    saltminer.audit("$2b$04$abcdefghijklmnopqrstuv")
    # ('bcrypt', 'WeakParams', 'cost 4 is below the minimum of 10')

`identify()` returns a list of (algorithm, confidence, reason) tuples.
`audit()` returns an (algorithm, verdict, detail) tuple, or None for formats
it does not rate.

## Links

Source, CLI, and desktop GUI: https://github.com/DebanganMALI/Salt-miner

Released under the MIT License.
