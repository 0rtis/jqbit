[![GitHub license](https://img.shields.io/github/license/0rtis/jqbit.svg?style=flat-square)](https://github.com/0rtis/jqbit/blob/master/LICENSE)

## jqbit

This an implementation of quantum secure cryptographic scheme in pure Java:
- WOTS+ as described in [RFC8391 -  XMSS: eXtended Merkle Signature Scheme](https://tools.ietf.org/html/rfc8391)
- XMSS as described in [RFC8391 -  XMSS: eXtended Merkle Signature Scheme](https://tools.ietf.org/html/rfc8391) and modified for multi-thread tree
 computation and optional tree caching (speed up computation on large tree)
 
### Usage
*Full examples can be found in the test directory*
#### WOTS+ - Winternitz One-Time Signature Plus
WOTS+ is a one-time-use, hash-based Digital Signature Algorithm (DSA).
Unlike most common signature scheme such as RSA, DSA or ECDSA that relies on "conjectured hardness of mathematical problems", WOTS+ uses hash
functions (SHA256, SHA512, Blake2, etc). It remains secure even if the collision resistance of the function is broken, is resistant to 
side-channel attacks and withstand known attacks using quantum computers.
 
```
/* Select WOTS+ paramters. The digest length of the hash function must match n parameter (here 32) */
final HashFunction sha256 = /* A 32 bytes digest hash function */
final WOTSpConfig config = WOTSpConfig.get32bytesCompactSignatureConfig(sha256) /* new WOTSpConfig(16, 4, 32, _32bytesHashFunction, 64, 3) */

/* Generate key pairs */
final SecureRandom random = new SecureRandom();

final byte[] privateKey = new byte[config.getKeyLength()];
random.nextBytes(privateKey);
final byte[] publicSeed = new byte[config.getN()];
random.nextBytes(publicSeed);
final byte[] publicKey = new byte[config.getKeyLength()];

WOTSp.generate(config, privateKey, publicSeed, publicKey, 0);

/* Sign message */
final byte[] msg = /* Message to sign */
final byte[] signature = new byte[config.getKeyLength()];
WOTSp.sign(config, msg, privateKey, publicKey, publicSeed, signature, 0);


if(!WOTSp.verify(config, msg, signature, publicKey, publicSeed))
    throw new Exception("Signature verification failed");

```
#### XMSS - eXtended Merkle Signature Scheme
XMSS is based on WOTS+ and share similar properties but is stateful and can be use multiple times.

```
/* Select WOTS+ paramters. The digest length of the hash function must match n parameter (here 32) */
final HashFunction sha256 = /* A 32 bytes digest hash function */
final WOTSpConfig wotspConfig = WOTSpConfig.get32bytesCompactSignatureConfig(sha256) /* new WOTSpConfig(16, 4, 32, _32bytesHashFunction, 64, 3) */
final XMSSConfig config = new XMSSConfig(0, wotspConfig, 4 /* generate a tree 2^4 (16) leaves */);

/* Generate key pairs */
final SecureRandom random = new SecureRandom();

final byte[] wotspCompactPrivateKeys = new byte[config.getCompactedWOTSPPrivateKeysLength()];
random.nextBytes(wotspCompactPrivateKeys);
final byte[] privateSeed = new byte[config.getWOTSPConfig().getN()];
random.nextBytes(privateSeed);
final byte[] publicSeed = new byte[config.getWOTSPConfig().getN()];
random.nextBytes(publicSeed);

final XMSS.KeyPair keyPair = XMSS.keyPair(config, wotspCompactPrivateKeys, privateSeed, publicSeed, true /* cache the tree */, 2 /* threads */);
final XMSSPrivateKey privateKey = keyPair.getPrivateKey();
final XMSSPublicKey publicKey = keyPair.getPublicKey();
final XMSSTree tree = keyPair.getTree(); /* Tree was cached during the generation of the keys */


/* Sign 2^4 messages */

final byte[] signature = new byte[config.getKeyLength()];

for(int i = 0; i < config.getWotspCount(); i++)
{
    final byte[] msg = /* Message to sign */
    XMSSSignature signature = XMSS.sign(config, msg, privateKey, tree /* The cached tree is used to speed up computation */);

    privateKey = privateKey.incrementIdx(); /* Increment the leaf index */

    if(!XMSS.verify(config, msg, signature, publicKey))
        throw new Exception("Signature verification failed at leaf index" + i);
}

```