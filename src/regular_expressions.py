# The following regexes has been obtained from the following links
# https://ieeexplore.ieee.org/document/8878085
# An Automated Live Forensic and Postmortem Analysis Tool for Bitcoin on Windows Systems

# https://stackoverflow.com/questions/21683680/regex-to-match-bitcoin-addresses/48643915#48643915

EXODUS = b"[eE]xodus"
ELECTRUM = b"[eE]lectrum"

PATTERNS = {
    "BITCOIN_P2SH": b"^[a-km-zA-HJ-NP-Z1-9]{24,33}",  # multisignature,
    "BTCOIN_BECH32": b"bc1[a-zA-HJ-NP-Z0-9]{25,59}",
    "BITCOIN_LEGACY": b"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    "EXTENDED_PUBLIC_KEY": b"xpub[a-km-zA-HJ-NP-Z1-9]{107,108}",
    "WIF_PRIVATE_KEY": b"5[a-km-zA-HJ-NP-Z1-9]{50}",
    "WIF_COMPRESSED_PRIVATE_KEY": b"[KL][a-km-zA-HJ-NP-Z1-9]{51}",
    "ENCRYPTED_PRIVATE_KEY": b"6P[a-km-zA-HJ-NP-Z1-9]{56}",
    "EXTENDED_PRIVATE_KEY": b"xprv[a-km-zA-HJ-NP-Z1-9]{107,108}",
    "MINI_PRIVATE_KEY": b"S[a-km-zA-HJ-NP-Z1-9]{29}",
}


# BITCOIN_VANINITY_ADDRESS = b"[1a-km-zA-HJ-NP-Z1-9]{24,33}"
# BITCOIN_P2SH = b"^[a-km-zA-HJ-NP-Z1-9]{24,33}"  # multisignature
# BTCOIN_BECH32 = b"bc1[a-zA-HJ-NP-Z0-9]{25,59}"
# BITCOIN_LEGACY = b"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"


# Bitcoin addresses:
# P2PKH (BASE58) / Legacy
# P2SH (BASE58) / Segwit - Pay to Script Hash
# P2WPKH (BECH32) / Native SegWit
# P2TR / Taproot
