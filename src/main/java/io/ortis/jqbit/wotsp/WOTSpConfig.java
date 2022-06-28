package io.ortis.jqbit.wotsp;

import io.ortis.jqbit.HashFunction;


public class WOTSpConfig
{
	//public static final WOTSpConfig SHA256_COMPACT_SIGNATURE = new WOTSpConfig(16, 4, 32, HashFunction..Sha256, 64, 3);
	// public static final WOTSPParameters SHA256_FAST_SIGNATURE = new WOTSPParameters(4, 2, 32, Hasher.Type.Sha256, 128, 5); untested !

	private final int w;
	private final int logW;
	private final int n;
	private final HashFunction hashFunction;
	private final int len1;
	private final int len2;
	private final int len;

	private final int keyLength;

	public WOTSpConfig(final int w, final int logW, final int n, final HashFunction hashFunction, final int len1, final int len2)
	{
		this.w = w;
		if(this.w != 4 && this.w != 16)
			throw new IllegalArgumentException("W must be from set {4;16}");

		this.logW = logW;

		this.n = n;
		if(this.n <= 0 || (this.n & (this.n - 1)) != 0)
			throw new IllegalArgumentException("N must be a power of 2");

		this.hashFunction = hashFunction;
		if(this.hashFunction.digestLength() != this.n)
			throw new IllegalArgumentException("Digest size must be equal to N");

		this.len1 = len1;
		this.len2 = len2;
		this.len = this.len1 + this.len2;

		this.keyLength = this.len * this.n;
	}

	public HashFunction getHashFunction()
	{
		return this.hashFunction;
	}

	public int getW()
	{
		return this.w;
	}

	public int getLogW()
	{
		return this.logW;
	}

	public int getN()
	{
		return this.n;
	}

	public int getLen1()
	{
		return this.len1;
	}

	public int getLen2()
	{
		return this.len2;
	}

	public int getLen()
	{
		return this.len;
	}

	public int getKeyLength()
	{
		return this.keyLength;
	}

	public static WOTSpConfig get32bytesCompactSignatureConfig(final HashFunction _32bytesHashFunction)
	{
		return new WOTSpConfig(16, 4, 32, _32bytesHashFunction, 64, 3);
	}

	/* UNTESTED !
	public static WOTSpConfig get32bytesFastSignatureConfig(final HashFunction _32bytesHashFunction)
	{
		return new WOTSpConfig(4, 2, 32, _32bytesHashFunction, 128, 5);
	}

	 */
}
