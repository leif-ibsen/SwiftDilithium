# Performance

## 

SwiftDilithium's performance for generating keys, signing a small message and verifying the signature for a small message was measured on an iMac 2021, Apple M1 chip.

The table below shows the times in milliseconds for the three Dilithium kinds.

| Kind          | GenerateKeyPair | Sign        |      Verify |
|:--------------|----------------:|------------:|------------:|
| ML_DSA_44     | 0.77 mSec       | 1.6 mSec    | 0.74 mSec   |
| ML_DSA_65     | 1.4 mSec        | 2.5 mSec    | 1.3 mSec    |
| ML_DSA_87     | 2.2 mSec        | 3.5 mSec    | 2.2 mSec    |

