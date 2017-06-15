import gnupg
import json
import sys

gpg = gnupg.GPG()
verified = gpg.verify_file(open(sys.argv[2], 'rb'),
                           sys.argv[1])

if verified.valid:
    print json.dumps({
        "data": {
            "fingerprint": verified.fingerprint,
            "username": verified.username,
            "valid": True
        }
    })
else:
    print json.dumps({
        "error": {
            "message": verified.status
        }
    })
