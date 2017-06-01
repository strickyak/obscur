# obscur
Obscure portions of lines of a text file.

Copies stdin to stdout, line by line,
assuming stdin is a LF-delimited text file (as in Unix & Linux),
encrypting or decrypting selected portions of certain lines.

    Usage:
        obscur -e -k 'SecretKey' < plaintext  > ciphertext  [to encrypt]
        obscur -d -k 'SecretKey' < ciphertext > plaintext   [to decrypt]

Since the secret key is a command-line argument, only run this on your own laptop,
or else edit the program to handle the key a better way.

To choose what to encrypt or decrypt, add a line like this (usually as a comment):

    obscur N {plainRegep} {plainReplace} {cipherRegexp} {cipherReplace}

It doesn't matter what comes at the front or end of the lines, so this may be buried
in comment markers like these:

    # obscur N {plainRegep} {plainReplace} {cipherRegexp} {cipherReplace}
    /* obscur N {plainRegep} {plainReplace} {cipherRegexp} {cipherReplace} */

N is the number of following lines that are governed by this pattern.
If N is 0, the rest of the file is governed by it.
But if another obscur line is found, it replaces the existing pattern and line counter.

If encrypting:

{plainRegexp} is a regexp pattern that matches the portion of the line to be replaced.
Only the first (parenthesized) match in the pattern will be encrypted.
Then {plainReplace} is substituted for the entire match, with the substring <@>
replace with the encrypted first (parenthesized) match.

If decrypting:

{cipherRegexp} is a regexp pattern that matches the portion of the line to be replaced.
Only the first (parenthesized) match in the pattern will be decrypted.
Then {cipherReplace} is substituted for the entire match, with the substring <@>
replace with the decrypted first (parenthesized) match.

Nota Bene: It can be tricky to get the patterns right, so that it will encrypt
the right things, and decrypt only what got encrypted, so test carefully!
You might want to avoid curly braces in your obscur patterns, since this is the
regular expression that matches the obscur pattern:

    obscur ([0-9]+) {(.+?)} {(.*?<@>.*?)} {(.+?)} {(.*?<@>.*?)}

Example:

Suppose this is the obscur pattern:


    frodo obscur 4 {a(.*)b} {A<@>B} {A(.*)B} {a<@>b}


If encrypting,
then on the next 4 lines,
anything within 'a' & 'b' characters will be encrypted,
and the 'a' & 'b' delimiters will be replaced by 'A' & 'B'.  For instance,
aMoob might be replaced with Aem59GaP6Dhluuqn55FZffwV-s2nvkWrf5uPZ-9zUpynYB.

If decrypting, then on the next 4 lines, anything within 'A' & 'B' characters will be encrypted,
and the 'A' & 'B' delimiters will be replaced by 'a' & 'b'. For instance,
Aem59GaP6Dhluuqn55FZffwV-s2nvkWrf5uPZ-9zUpynYB might be replaced with AMoob.

Notice the ciphertext is much longer than the plaintext, and is base64 encoded,
so it can use any characters in the set
    [-_A-Za-z0-9]
(that is, all ASCII uppercase & lowercase letters, all 10 ASCII digits,
and the two characters dash & underscore).

Useful Example:

In shell scripts, you might use this to obscure a password:

    # obscur 1 {PASSWORD="(.*)"} {encrypted_password="<@>"} {encrypted_password="(.*)"} {PASSWORD="<@>"}
    PASSWORD="open-sesame"

and when you encrypt it with key xyzzy (try `go run obscur.go -e -k xyzzy < README.md`), you might get

    # obscur 1 {PASSWORD="(.*)"} {encrypted_password="<@>"} {encrypted_password="(.*)"} {PASSWORD="<@>"}
    encrypted_password="-yVI-RmQ4Mgim8pQdCoyZA8biTX-pqJd0XbvocvIAKMJaqVxyb2k"

and if you decrypt that (try `go run obscur.go -e -k xyzzy | go run obscur.go -d -k xyzzy`), you should recover
the original.

You can see how this pattern or something similar could work in many other languages.

Another Useful Example:

This simpler example uses the same double-quote delimiters for both the plain and the cipher text:

    # obscur 1 {"(.*)"} {"<@>"} {"(.*)"} {"<@>"}
    s += "open-sesame"
