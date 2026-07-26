# Passport Cake Signer Intro Post

Team, here is a short demo of the current Passport Prime Monero signer proof of
concept.

Prime now acts as an offline Monero signer for the public Cake Wallet app. Cake
stays online as the watch-only wallet, while Prime keeps the private spend key
offline, reviews unsigned transactions, signs locally, and returns
Cake-compatible signed transaction QR codes for broadcast. Experimental
QuantumLink plumbing is also now present so we can move large payloads off QR
once the phone-side flow is ready.

The key architectural choice was to make Prime mimic the cold-side behavior Cake
already expects from CupCake, rather than requiring a custom Cake build or a new
Foundation-specific protocol first.

One Monero-specific piece worth calling out: key-image sync is where Prime tells
Cake which wallet outputs are already spent, without revealing the spend key, so
Cake can build the next transaction correctly.

What is working now: Cake pairing, Prime-derived wallets, imported Polyseed and
legacy Monero seeds, key-image sync, address verification, transaction review,
on-device signing, and successful Cake broadcast after scanning Prime's signed
transaction QR.

Current limitations: this is still a hardware-tested proof of concept. QR works
with today's public Cake app, but Monero payloads are large, scanning can feel
slow, QuantumLink is not yet the proven default path, and repeated
output/key-image sync flows need more fixture coverage before we call this
production-ready.

Natural next steps: build a real Cake fixture suite, stress test larger wallet
states on hardware, harden QuantumLink/USB transport, and run a focused security
review.

Private Prime app repo: https://github.com/Foundation-Devices/passport-cake-signer

Companion Cake Android fork:
https://github.com/BitcoinQnA/cake_wallet/tree/codex/passport-prime-quantumlink

The accompanying technical spec in the repo has the full protocol, wallet model,
signing flow, limitations, and proposed next steps.
