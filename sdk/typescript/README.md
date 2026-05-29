# @esoptron/verify

Self-contained TypeScript verifier for `.eopx` files.

## Installation

```bash
npm install @esoptron/verify
```

## Usage

```typescript
import { readManifest, verifyChunksOnly, verifyWithPixelExtractor } from '@esoptron/verify';
import { readFileSync } from 'fs';

const eopxData = new Uint8Array(readFileSync('vault.eopx'));

// Quick verification (chunks + signature, skips pixel hash)
const quickResult = verifyChunksOnly(eopxData);
console.log(quickResult.ok ? 'Valid!' : quickResult.errors);

// Full verification requires a pixel extractor
import { PNG } from 'pngjs';

const pixelExtractor = (data: Uint8Array) => {
  const png = PNG.sync.read(Buffer.from(data));
  const rgb = new Uint8Array(png.width * png.height * 3);
  for (let i = 0, j = 0; i < png.data.length; i += 4, j += 3) {
    rgb[j] = png.data[i];
    rgb[j + 1] = png.data[i + 1];
    rgb[j + 2] = png.data[i + 2];
  }
  return rgb;
};

const fullResult = verifyWithPixelExtractor(eopxData, pixelExtractor);
console.log(fullResult.ok ? 'Fully verified!' : fullResult.errors);
```

## API

### `readManifest(pngData: Uint8Array): Manifest`

Parse the manifest from a `.eopx` file without cryptographic verification.

### `verifyChunksOnly(pngData: Uint8Array, options?): VerificationResult`

Verify chunks + payload hash + ML-DSA-87 signature. Skips pixel hash verification.

### `verifyWithPixelExtractor(pngData, extractor, options?): VerificationResult`

Full verification including pixel hash. Requires a pixel extractor function.

### Options

- `expectedDilithiumPkFp`: SHA3-256 fingerprint (hex or bytes) the signer must match

## Verification Checks

1. **Chunks OK**: PNG tEXt chunks parse correctly
2. **Image Hash OK**: SHA3-512(RGB pixels) matches `eopx:image_sha3_512`
3. **Payload Hash OK**: SHA3-512(canonical payload) matches `eopx:payload_hash`
4. **Signature OK**: ML-DSA-87 signature is valid

## License

MIT
