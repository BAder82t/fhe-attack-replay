# Copyright 2026 Vaultbytes (Bader Alissaei)
# SPDX-License-Identifier: Apache-2.0

"""Reference toy cryptosystems used to validate attack modules in CI.

These are deliberately small and not cryptographically secure. They exist so
that attack modules can be exercised end-to-end without depending on a native
FHE library build. Verdicts produced against a toy cryptosystem are flagged
in the result evidence so users do not mistake them for verdicts against a
production library.
"""

from fhe_attack_replay.lab.toy_lwe import ToyLWE, ToyLWECiphertext, ToyLWEKeys

__all__ = ["ToyLWE", "ToyLWECiphertext", "ToyLWEKeys"]
