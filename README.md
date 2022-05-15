# simple-crypto
A collection of single-file public domain/unlicense cryptographic functions 
in different programming languages.

Feel free to copy-paste the code you need because this is what this collection is made for. 
Some (or even most) of this collection is itself a copy-paste from another repos 
(original authors are mentioned in files).

Functions are not designed to be blazing-fast, secure (protected against timing/cache attacks or 
zeroing out memory before freeing), but simple and portable. Its secureness is up to you 
(like zeroing out memory), but for a serious crypto, you should use a special crypto library.

## Collection
| Language | Category | Function                        | Note |
|----------|----------|---------------------------------|------|
| C        | Hash     | [SHA256](c/hash/sha256.h)       |      |
| C        | Cipher   | [ChaCha20](c/cipher/chacha20.h) |      |

## How to contribute
To add a new set of functions, please submit a PR.

Please consider the following:
* Put the functions into a single self-contained source file
* Provide simple documentation on how to use this code in the comments at the file header
* Mention the original author and source of the code in file header to prove this is 
   public domain/unlicense and make authors happier
* If you are the author - state so. Also, it would be more clear to upload your code somewhere else under \
   public domain/unlicense and link it here like the previous note suggests (but not required)
* For C/C++: make sure to make your code header-only with include guard/pragma once
* A specific codestyle is not required, but make it consistent across the file
