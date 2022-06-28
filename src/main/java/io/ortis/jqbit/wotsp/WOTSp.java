package io.ortis.jqbit.wotsp;

import io.ortis.jqbit.HashFunction;

import java.util.Arrays;

/**
 * Winternitz One-Time Signature Plus (WOTS+)
 * <p>
 * WOTS+ is a one-time-use, hash-based Digital Signature Algorithm (DSA).
 * Unlike most common signature scheme such as RSA, DSA or ECDSA that relies on "conjectured hardness of mathematical problems",
 * WOTS+ uses hash functions (SHA256, SHA512, Blake2, etc). It remains secure even if the collision resistance
 * of the function is broken, is resistant to side-channel attacks and withstand known attacks using quantum computers.
 */
public class WOTSp
{

	/**
	 * Generate a WOTS+ key pair
	 *
	 * @param config:            WOTS+ parameters
	 * @param privateKey:        private key of length LEN * N
	 * @param publicSeed:        public seed of length N
	 * @param destination:       byte array with at least LEN * N slots available to store the resulting public key
	 * @param destinationOffset: byte array offset
	 */
	public static void generate(final WOTSpConfig config, final byte[] privateKey, final byte[] publicSeed, final byte[] destination, final int destinationOffset)
			throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getN();
		final int keyLength = config.getKeyLength();

		if(privateKey.length != keyLength)
			throw new IllegalArgumentException("Private key must be " + keyLength + " bytes long");

		if(publicSeed.length != n)
			throw new IllegalArgumentException("Public Seed must be " + n + " bytes long");

		//final Adrs adrs = Adrs.of(publicKSA, size + n).setType(Adrs.Type.OTS);
		final Adrs adrs = new Adrs().setType(Adrs.Type.OTS);

		WOTSpRFC.publicKey(config, privateKey, publicSeed, adrs, destination, destinationOffset);
	}

	/**
	 * Sign a message
	 *
	 * @param config:            WOTS+ parameters
	 * @param msg:               message to sign
	 * @param privateKey:        private key of length LEN * N
	 * @param publicKey:         public key of length LEN * N
	 * @param publicSeed:        public seed of length N
	 * @param destination:       byte array with at least LEN * N slot available to store the resulting public key
	 * @param destinationOffset: byte array offset
	 */
	public static void sign(final WOTSpConfig config, final byte[] msg, final byte[] privateKey, final byte[] publicKey, final byte[] publicSeed,
			final byte[] destination, final int destinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getN();
		final int keyLength = config.getKeyLength();


		if(msg.length != n)
			throw new IllegalArgumentException("Message must be " + n + " bytes long");

		if(privateKey.length != keyLength)
			throw new IllegalArgumentException("Private key must be " + keyLength + " bytes long");

		if(publicKey.length != keyLength)
			throw new IllegalArgumentException("Public key must be " + keyLength + " bytes long");

		if(publicSeed.length != n)
			throw new IllegalArgumentException("Public seed must be " + n + " bytes long");


		WOTSpRFC.sign(config, msg, privateKey, publicSeed, new Adrs().setType(Adrs.Type.OTS), destination, destinationOffset);
	}


	/**
	 * Derived a public key from the a signed message
	 *
	 * @param config:     WOTS+ parameters
	 * @param msg:        message to verify
	 * @param signature:  signature attached to the message
	 * @param publicSeed: public seed of length N
	 */
	public static byte[] signatureToPublicKey(final WOTSpConfig config, final byte[] msg, final byte[] signature, final byte[] publicSeed)
			throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getN();
		final int keyLength = config.getKeyLength();

		if(msg.length != n)
			throw new IllegalArgumentException("Message must be " + n + " bytes long");

		if(signature.length != keyLength)
			throw new IllegalArgumentException("Signature must be " + keyLength + " bytes long");

		if(publicSeed.length != n)
			throw new IllegalArgumentException("Public seed must be " + n + " bytes long");

		final byte[] derivedPublicKey = new byte[keyLength];
		WOTSpRFC.signatureToPublicKey(config, msg, signature, publicSeed, new Adrs().setType(Adrs.Type.OTS), derivedPublicKey, 0);

		return derivedPublicKey;
	}

	/**
	 * Verify the authenticity of a signed message
	 *
	 * @param config:     WOTS+ parameters
	 * @param msg:        message to verify
	 * @param signature:  signature attached to the message
	 * @param publicKey:  public key of length LEN * N
	 * @param publicSeed: public seed of length N
	 */
	public static boolean verify(final WOTSpConfig config, final byte[] msg, final byte[] signature, final byte[] publicKey, final byte[] publicSeed)
			throws HashFunction.Instance.HashFunctionException
	{
		if(publicKey.length != config.getKeyLength())
			throw new IllegalArgumentException("Public key must be " + config.getKeyLength() + " bytes long");

		final byte[] derivedPublicKey = signatureToPublicKey(config, msg, signature, publicSeed);
		return Arrays.equals(publicKey, derivedPublicKey);
	}
}
