# Code Architecture

Here are some block diagrams of how the code is structured. Not all details are shown, but these diagrams give a reasonably cohesive idea of how data is passed through and modified.

# Decryption
## Low Detail View

Data is first passed through `Header Decryption` which is responsible for initializing the shared `Header` state with correct values, consuming all header-related bytes, and undoing any encryption from deniability mode. By the time data is passed out of `Header Decryption`, the `Header` object is fully initialized and ready to be used. Any damaged bytes are reported to the shared `DamageTracker`.

Data then passes through `Body Decryption` which is responsible for decoding the file data and checking it for correctness. The data output by `Body Decryption` is fully decoded. Any damaged bytes are reported to the shared `DamageTracker`.

```mermaid
flowchart TB

  subgraph SH[Header Decryption]
    direction LR

    SH_S1[[Deniability Wrapper]]
    SH_S2[[Header Fields]]

    SH_A[/Incoming bytes/] --> SH_S1 --> SH_S2 --> SH_B[\Outgoing bytes\]

  end

  subgraph SB[Body Decryption]
    direction LR

    SB_A[/Incoming bytes/]
    SB_S1[[ReedSolomon]]
    SB_S2[[MAC]]
    SB_S3[[Encryption]]
    SB_SB[\Outgoing bytes\]

    SB_A --> SB_S1
    SB_S1 --> SB_S2
    SB_S2 --> SB_S3
    SB_S3 --> SB_SB
  end

  A[/Encrypted data/] --> SH --> SB --> B[/Decrypted data/]

  HEADER[(Header)]
  DMG[(DamageTracker)]
```

## High Detail View

```mermaid
flowchart TB

  subgraph SH[Header Decryption]
    direction TB

    subgraph SH_S1[Deniability Wrapper]
      direction LR
      SH_S1_HEADER[(Header)]
      SH_S1_A[/Incoming bytes/] --> SH_S1_B{Are the first bytes a valid version?}
      SH_S1_B --> |Yes| SH_S1_C[\Outgoing bytes\]
      SH_S1_B --> |No| SH_S1_D[Consume the first 40 bytes]
      SH_S1_D -.-> |denyMode, denyNonce, denySalt| SH_S1_HEADER
      SH_S1_D --> SH_S1_E[ChaCha20 Cipher]
      SH_S1_HEADER -.-> |denyNonce, denySalt| SH_S1_E
      SH_S1_E --> SH_S1_C
    end

    subgraph SH_S2[Header Fields]
      direction LR
      SH_S2_HEADER[(Header)]
      SH_S2_DMG[(DamageTracker)]
      SH_S2_A[/Incoming bytes/] --> SH_S2_B{{"Loop over fields in [version, comments, flags, salt, hkdfSalt, serpentIV, nonce, keyRef, keyfileRef, macTag]"}}
      SH_S2_B --> |field| SH_S2_C{"Are bytes for field decodable?"}
      SH_S2_C --> |No| SH_S2_D(Consume all bytes)
      SH_S2_D -.-> |damaged| SH_S2_DMG
      SH_S2_C --> |Yes| SH_S2_E{Was error correction required?}
      SH_S2_E --> |Yes| SH_S2_F[Record damage]
      SH_S2_F -.-> |damaged| SH_S2_DMG
      SH_S2_F --> SH_S2_G[Consume field bytes]
      SH_S2_E --> |No| SH_S2_G
      SH_S2_G --> SH_S2_B
      SH_S2_G -.-> |field| SH_S2_HEADER
      SH_S2_B --> |done| SH_S2_H[\Outgoing bytes\]

      SH_S5_I>"Note: actual implementation unrolls the loop"]
    end

    SH_S1 --> SH_S2

  end

  subgraph SB[Body Decryption]
    direction TB

    subgraph SB_S1[ReedSolomon]
      SB_S1_HEADER[(Header)]
      SB_S1_DMG[(DamageTracker)]

      SB_S1_A[/Incoming bytes/] --> SB_S1_B{Has Reed Solomon encoding?}
      SB_S1_B --> |Yes| SB_S1_C[Break into 136 byte chunks]
      SB_S1_C --> SB_S1_D[Consume Reed Solomon bytes]
      SB_S1_D --> SB_S1_E{Is chunk decodable?}
      SB_S1_E --> |Yes| SB_S1_F{Was error correction required?}
      SB_S1_F --> |Yes| SB_S1_G[Record damage]
      SB_S1_G -.-> |damaged| SB_S1_DMG
      SB_S1_I -.-> |damaged| SB_S1_DMG
      SB_S1_G --> SB_S1_H[\Outgoing bytes\]
      SB_S1_E --> |No| SB_S1_I[Use first bytes as best guess]
      SB_S1_I --> SB_S1_H
      SB_S1_F --> |No| SB_S1_H
      SB_S1_HEADER -.-> |ReedSolomon| SB_S1_B
      SB_S1_B --> |No| SB_S1_H
    end

    subgraph SB_S2[MAC]
      direction LR
      SB_S2_HEADER[(Header)]
      SB_S2_DMG[(DamageTracker)]
      SB_S2_A[/Incoming bytes/] --> SB_S2_B{Encrypted with Paranoid mode?}
      SB_S2_B --> |Yes| SB_S2_C["Record to SHA3.512 (does not modify bytes)"]
      SB_S2_B --> |No| SB_S2_D["Record to Blake2 (does not modify bytes)"]
      SB_S2_E[\Outgoing bytes\]
      SB_S2_C --> SB_S2_E
      SB_S2_D --> SB_S2_E

      SB_S2_F{Does final sum match macTag?}
      SB_S2_G(Do nothing)
      SB_S2_H(Report error)
      SB_S2_C -.-> |On flush| SB_S2_F
      SB_S2_D -.-> |On flush| SB_S2_F
      SB_S2_F -.-> |Yes| SB_S2_G
      SB_S2_F -.-> |No| SB_S2_H
      SB_S2_H -.-> |damaged| SB_S2_DMG

      SB_S2_HEADER -.-> |paranoid| SB_S2_B
      SB_S2_HEADER -.-> |macTag| SB_S2_F
    end

    subgraph SB_S3[Encryption]
      direction LR
      SB_S3_HEADER[(Header)]
      SB_S3_A[/Incoming bytes/]
      SB_S3_B[ChaCha20 cipher]
      SB_S3_C{Is paranoid?}
      SB_S3_D[Serpent]
      SB_S3_E[\Outgoing bytes\]
      SB_S3_A --> SB_S3_B --> SB_S3_C
      SB_S3_C --> |Yes| SB_S3_D --> SB_S3_E
      SB_S3_C --> |No| SB_S3_E
      SB_S3_HEADER -.-> |nonce, salt| SB_S3_B
      SB_S3_HEADER -.-> |paranoid| SB_S3_C
      SB_S3_HEADER -.-> |iv| SB_S3_D
    end

    SB_S1 --> SB_S2 --> SB_S3

  end

  A[/Data to decrypt/] --> SH --> SB --> B[/Decrypted data/]
```

# Encryption

Encryption is broken into 2 steps: encode the file itself through `Encryption Stream`, then combine the `Header` bytes with the encoded body data. These steps are separated because some header data such as the `macTag` cannot be known until the file data has been fully encrypted. The header fields required for `Encryption Stream` are initialized from the passed `Settings` and randomly generated seeds.


```mermaid
flowchart LR

  A[Settings]
  B[Random Seeds]
  C[Header]
  D[[Encryption Stream]]
  E[/Input File/]
  F[header + body]
  H[Encrypted body data]
  I[\Output File\]
  J[Apply deniability if enabled]

  A -.-> C
  B -.-> C
  C -.-> D
  E --> D
  D --> H
  H --> |body bytes| F
  C --> |After body data is encrypted| J --> |header bytes| F
  F --> I
```

## Low Detail View

Low detail view of the `Encryption Stream`. It is very similar to running the `Decryption Stream` in reverse. Data is first passed through `Primary Encryption` (ChaCha20, plus Serpent if paranoid). Then a mac is computed and saved to the header to check against when decrypting. Then Reed-Solomon bytes are added if requested. Then everything is passed through `Deniability Wrapper` (another ChaCha20) if requested. The output bytes are the full body, ready to be appended to the header bytes, which can now be computed.

```mermaid
flowchart TB

  subgraph SB[Body Encryption]
    direction LR
    SB_S1[[Encryption]]
    SB_S2[[MAC]]
    SB_S3[[ReedSolomon]]
    SB_S4[[Deniability Wrapper]]
    SB_S1 --> SB_S2 --> SB_S3 --> SB_S4
  end

  A[/Data to encrypt/] --> SB --> B[/Encrypted data/]
```

## High Detail View

```mermaid
flowchart TB

  subgraph SB[Body Encryption]
    direction TB

    subgraph SB_S1[Encryption]
      direction LR
      SB_S1_HEADER[(Header)]
      SB_S1_A[/Incoming bytes/]
      SB_S1_B[ChaCha20 cipher]
      SB_S1_C{Is paranoid?}
      SB_S1_D[Serpent]
      SB_S1_E[\Outgoing bytes\]
      SB_S1_A --> SB_S1_B --> SB_S1_C
      SB_S1_C --> |No| SB_S1_E
      SB_S1_C --> |Yes| SB_S1_D --> SB_S1_E
      SB_S1_HEADER -.-> |nonce, salt| SB_S1_B
      SB_S1_HEADER -.-> |paranoid| SB_S1_C
      SB_S1_HEADER -.-> |iv| SB_S1_D
    end

    subgraph SB_S2[MAC]
      direction LR
      SB_S2_HEADER[(Header)]
      SB_S2_A[/Incoming bytes/] --> SB_S2_B{Paranoid Mode?}
      SB_S2_B --> |Yes| SB_S2_C["Record to SHA3.512 (does not modify bytes)"]
      SB_S2_B --> |No| SB_S2_D["Record to Blake2 (does not modify bytes)"]
      SB_S2_E[\Outgoing bytes\]
      SB_S2_C --> SB_S2_E
      SB_S2_D --> SB_S2_E

      SB_S2_F(Save sum to header)
      SB_S2_C -.-> |On flush| SB_S2_F
      SB_S2_D -.-> |On flush| SB_S2_F
      SB_S2_F -.-> |macTag| SB_S2_HEADER

      SB_S2_HEADER -.-> |paranoid| SB_S2_B
    end

    subgraph SB_S3[ReedSolomon]
      SB_S3_HEADER[(Header)]
      SB_S3_A[/Incoming bytes/] --> SB_S3_B{Reed Solomon encoding?}
      SB_S3_B --> |Yes| SB_S3_C[Break into 128 byte chunks]
      SB_S3_C --> SB_S3_D[Add 8 Reed Solomon bytes per chunk]
      SB_S3_D --> SB_S3_E[\Outgoing bytes\]
      SB_S3_HEADER -.-> |ReedSolomon| SB_S3_B
      SB_S3_B --> |No| SB_S3_E
    end

    subgraph SB_S4[Deniability Wrapper]
      direction LR
      SH_S4_HEADER[(Header)]
      SH_S4_A[/Incoming bytes/] --> SH_S4_B{Deniability mode?}
      SH_S4_B --> |No| SH_S4_C[\Outgoing bytes\]
      SH_S4_B --> |Yes| SH_S4_D["ChaCha20 Cipher (seeded with mock header bytes)"]
      SH_S4_HEADER -.-> |denyNonce, denySalt| SH_S4_D
      SH_S4_D --> SH_S4_C
    end

    SB_S1 --> SB_S2 --> SB_S3 --> SB_S4

  end

  A[/Data to encrypt/] --> SB --> B[/Encrypted data/]
```