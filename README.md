# firmware-signer
Encedo firmware signing tool - simply adding a digital signature to the firmware image to ensure integrity and origin.

Compile
=======

Signer is a single C file application and can be easly compile by any ANSI C compiler. No makefile required. Just type:

gcc signer.c -o signer.exe

I`m using mingw32 under Windows, change parameters regards your enviroment.

To enable (enabled by default) ED25519 code signing feature, download ED25519 code from https://github.com/encedo/ed25519 or https://github.com/orlp/ed25519 to folder ED25519
and type:

gcc signer.c ED25519/*.c -o signer.exe






