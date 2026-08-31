# Wallet and verifier workflows

Create challenges from public arguments and protected nonce/key files. Give
`prove` only file paths; never put credentials, holder keys, status indices,
or Merkle paths in argv or environment variables. Outputs are new owner-only
files and are not overwritten. `inspect` prints public mode, audience, nonce,
and status presence only.

Bearer credentials are theft-sensitive: anyone holding the presentation can
answer an unconsumed challenge. Holder-bound mode adds possession of the
bounded holder key, but does not turn the credential into a general-purpose
anonymous credential.
