# Performance

## 

SwiftDilithium's performance for generating keys, signing a small message and verifying the signature for a small message was measured on a MacBook Pro 2024, Apple M3 chip.

The table below shows the times in milliseconds for the three Dilithium kinds.

| Kind          | GenerateKeyPair | Sign        |      Verify |
|:--------------|----------------:|------------:|------------:|
| ML_DSA_44     | 1.1 mSec        | 0.60 mSec   | 0.11 mSec   |
| ML_DSA_65     | 2.1 mSec        | 0.92 mSec   | 0.15 mSec   |
| ML_DSA_87     | 3.7 mSec        | 1.0 mSec    | 0.20 mSec   |
