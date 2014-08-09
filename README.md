An offline Bitcoin wallet written in Rust.

* planned features:
    * generates secure random addresses.
    * keeps addresses in a plaintext file, with encrypted private keys at the
      bottom, and instructions on exactly how they were encrypted so you don't
      have to depend on the software to recover them in the future.
    * lets you give aliases to addresses or groups of addresses, to easily
      recognize them and refer to them. (optional?)
    * other than that, it just signs transactions.

What a wallet file might look like:

    work:
      1BcayosrBPfrL3dvLPEGVqm6ZXPg3VZCye
    public:
      1EZ4JvUPzZQxznv2J5THxofeWUuP7hMNzb
    change:
      15rB7HHcHF7MwKR61mX68EyTGNkiNSxH2w
      1JxAyxmWHG5QrufWVBj3jZfRsKM81H7dgu
      1C3T93Urn6pDXcnmriLsehqVNsadJRQ4r1
      1JF5jv38gEnnyrB6Bt8hB7aiKg9NUdDeAM
      19cj1nCUkksnhgsAnDQGAUEcH5qQH9Zw5K
      13VCuecDpFbM1Gejxs81pTDQrbED2qVvTP
      1Kk27NfSuxsSNJhRoLPw1ciog8BbMoNFeQ
    trash:
      1AN6BJRSVbKveFHFeuV9fmSwgRgmpN9kt7
      18Y8Rt1qRh9vWqoq9mHJERoFMeVGmPFwx8
      17TCHDW5aqvXKmwv1onpyBmjBxSUMhxgDW
      1BVsyiqN39FJwAratV7MoKVx4LkTqZ5JQ8

    secrets:
      # Private key data encrypted with AES-256-CBC using PBKDF2-HMAC-SHA1 with 4000
      # iterations and the following salt and iv:
      salt: e8d9139cf2e7c57e156ac6f61a356d4b
      iv: 74bab1ee057bb5affbbf3216a72311de

      # The decrypted data consists of concatenated 32-byte private keys in the same
      # order as the addresses are listed in this file.
      encrypted_data:
        8a7c3f26eec17414b9ac53f9e525950df19354d531501931e34c39b33e8e493f
        ae38605547b44bb6d02de7d83d659c14a84722d0319b40fb9657259493744ca1
        1fbd701ddc8af1c82da88e7db991be8cad49007f2205a7c7c93b34a3f09a855c
        e999e654bb9e8115f27c2c81e1fb13561a4219d0353f38360cbdecb958c9fc4c
        5413dd1edcde48a6104e82c566df2007f20f59d1024808944cfbc25ca71c3367
        f6aeb3791bad2d0417b607a810ea3848eb705c541bf2aebb2dde1b7afd5dc6e5
        fb209df2f0776dea9dae70228c4a007cb2962d1f8ef797064db4be1912a4c476
        ef0a8cea8eec585f5393421d271e51340df2d19a2462d3

`change` will be a special alias for change addresses. `trash` is another
special alias, for addresses that you delete (nothing should ever be erased).

To keep your bitcoins safe, you need to (a) keep the private keys secret but
(b) not risk losing them. The solution to (a) is to encrypt the private keys,
and only allow the decrypted information to live in RAM for a short period of
time preferably on a computer that never has and never will connect to the
internet, and that has a good source of entropy you can trust. I think the
raspberry pi satisfies that pretty well. The solution to (b) is to back up the
encrypted private keys in several (dozen? :P) places, and to not lose your
passphrase. You should only give someone an address after its private key has
been backed up.

Keeping a secret and preserving information are both critical to keeping
bitcoins safe, and are the two things `cykas` aims to do best (with the
co-operation of the user).

possible commands: gen, import (dangerous), export (dangerous), list, show,
sign, verify, passwd, rename_alias, move (address to a different alias), rm...

* ideas/misc.
    * optionally encrypt the addresses too, probably want to keep those private
      at least in certain backup locations.
    * keep code small and simple to encourage self-auditing
    * have some way of "proving" the encrypted data contains the private keys
      for the addresses, without exposing the private keys.
    * if an address is missing from the first section of the wallet file, don't
      throw the key away. regenerate the address from the key and put it in
      trash or lost+found or something.

