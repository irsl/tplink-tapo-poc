#!/usr/bin/env python3

import sys
import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

if len(sys.argv) != 2:
    print("Usage: %s b64encoded_ciphertext" % (sys.argv[0]))
    sys.exit(1)

msg_b64 = sys.argv[1]
msg = base64.b64decode(msg_b64.encode())


private_key = RSA.importKey("""-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALgPqLSgP8Zrmpv/
9F9J7wys9UiswgZ5wLGRwZYaP2THGTvipA2rxdS5ejLY9zNDfQGmJEeuWRu0EQ95
Yumrzm1+5tNSOEHPU0829asLzy5phUa/M2mDNk6oMLfn3rW49O691Rry/O1xRCMR
nLXpZuZ61GNREUiJYmAUKZ6bJhVtAgMBAAECgYBnuUtVHslRw+nI56CK4ls4RW+k
mNZuV8ZjSsRRFlGLNTffK4VPvvEpQ6y9Ys9LsEiN2VawnmvQ1NSYZ8t56zvUOrF9
51BveRJqYEwSse7+Nd5GLsxoYItPI70B77T48UAdR2V3VCNfnSYBkP/59sM+/vNR
5s2syQXNuX31y1jOcQJBAPCIc0E/nVU4XZ/ylGadyvlClmZZlvdk0/D1Bz/3uSft
ezzMbPU0ERQD1ItwXbkpe/oalV2vpfsG6Fd4H0dmk1MCQQDD5ZgKcHUqNjPrwWIh
iQDreWu+c3Ygb2mWWS35rPpcV1eA52qh2iLela+aGRTnlnY3SiS4aOb3eo7Wl5sL
clw/AkA6yf7xiazYsWggudePpS2A8sdzyJ3fZaNvl1PoTJHSsnaWi5ht7gXmkHEY
i6Q8p2kH3gt31ICK9EtBZbivaODFAkEAmjX4PWeP5F3s+48td+bJEZVxCukLubba
8N9dQOo54E1ldfU2zRjSUFSXewB5o2GfyCCWzZDPGUyiey23gQhSswJAKA6EsnVK
hTDVET5vfHmGm6JsWmKSdf0wCM3EwnW8dAWCxhMhWUP0t0dz/6cZt5eHOLQEnaHd
Hm2ZCYix46z1/Q==
-----END PRIVATE KEY-----
""")

cipher = PKCS1_v1_5.new(private_key)
print(cipher.decrypt(msg, None))
