# Performance

## 

SwiftDilithium's performance for generating keys, signing a small message and verifying the signature for a small message was measured on an MacBook Pro 2024, Apple M3 chip.

The table below shows the times in milliseconds for the three Dilithium kinds.

| Kind          | GenerateKeyPair | Sign        |      Verify |
|:--------------|----------------:|------------:|------------:|
| ML_DSA_44     | 1.5 mSec        | 0.75 mSec   | 0.15 mSec   |
| ML_DSA_65     | 2.7 mSec        | 1.2 mSec    | 0.19 mSec   |
| ML_DSA_87     | 4.9 mSec        | 1.3 mSec    | 0.26 mSec   |

