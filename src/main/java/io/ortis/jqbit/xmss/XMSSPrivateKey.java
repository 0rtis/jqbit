package io.ortis.jqbit.xmss;

import io.ortis.jqbit.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Private Key = idx || wots+ private keyS || SK_PRF || root || SEED
 */
public class XMSSPrivateKey
{
	private final int nextIdx;// 4 bytes
	private final byte[] wotspCompactPrivateKeys;// multiple of n bytes
	private final byte[] privateSeed;// n bytes
	private final byte[] root;// n bytes
	private final byte[] publicSeed;// n bytes

	private final int wotspCount;
	private final int remainingWOTSPLeaves;

	private final int length;

	private transient final int hashCode;

	public XMSSPrivateKey(final int nextIdx, final byte[] wotspCompactPrivateKeys, final byte[] privateSeed, final byte[] root, final byte[] publicSeed)
	{
		this.nextIdx = nextIdx;
		if(this.nextIdx < 0)
			throw new IllegalArgumentException("Next idx cannot be negative");

		this.wotspCompactPrivateKeys = wotspCompactPrivateKeys;
		if((this.wotspCompactPrivateKeys.length & 1) != 0)
			throw new IllegalArgumentException("WOTSP compact private keys length must be even");

		this.privateSeed = privateSeed;
		if((this.privateSeed.length & 1) != 0)
			throw new IllegalArgumentException("Private seed length must be even");

		this.root = root;
		this.publicSeed = publicSeed;

		if(this.privateSeed.length != this.root.length || this.privateSeed.length != this.publicSeed.length)
			throw new IllegalArgumentException("Private seed, root and public seed must be of same length");

		this.wotspCount = this.wotspCompactPrivateKeys.length / this.root.length;
		this.remainingWOTSPLeaves = this.wotspCount - this.nextIdx;

		this.length = 4 + this.wotspCompactPrivateKeys.length + this.privateSeed.length + this.root.length + this.publicSeed.length;

		{
			int result = Objects.hash(this.nextIdx, this.length);
			result = 31 * result + Arrays.hashCode(this.wotspCompactPrivateKeys);
			result = 31 * result + Arrays.hashCode(this.privateSeed);
			result = 31 * result + Arrays.hashCode(this.root);
			result = 31 * result + Arrays.hashCode(this.publicSeed);
			this.hashCode = result;
		}
	}


	public int getRemainingWOTSPLeaves()
	{
		return this.remainingWOTSPLeaves;
	}

	public XMSSPrivateKey incrementIdx()
	{
		if(this.remainingWOTSPLeaves <= 0)
			throw new IllegalStateException("No WOTS+ leaves remaining");

		return new XMSSPrivateKey(this.nextIdx + 1, this.wotspCompactPrivateKeys, this.privateSeed, this.root, this.publicSeed);
	}

	public byte [] toBytes()
	{
		final ByteBuffer buffer = ByteBuffer.allocate(this.length);
		buffer.putInt(this.nextIdx);
		buffer.put(this.wotspCompactPrivateKeys);
		buffer.put(this.privateSeed);
		buffer.put(this.root);
		buffer.put(this.publicSeed);

		if(buffer.position() != buffer.capacity())
			throw new IllegalStateException("Buffer must be filled");

		return buffer.array();
	}

	public int getNextIdx()
	{
		return this.nextIdx;
	}

	public byte[] wotspCompactPrivateKeys()
	{
		return this.wotspCompactPrivateKeys;
	}

	public byte[] privateSeed()
	{
		return this.privateSeed;
	}

	public byte[] root()
	{
		return this.root;
	}

	public byte[] publicSeed()
	{
		return this.publicSeed;
	}

	public int length()
	{
		return this.length;
	}

	@Override
	public int hashCode()
	{
		return this.hashCode;
	}

	@Override
	public boolean equals(final Object o)
	{
		if(this == o)
			return true;

		if(o instanceof XMSSPrivateKey)
		{
			final XMSSPrivateKey other = (XMSSPrivateKey) o;
			return this.nextIdx == other.nextIdx && this.length == other.length && Arrays.equals(this.wotspCompactPrivateKeys,
					other.wotspCompactPrivateKeys) && Arrays.equals(
					this.privateSeed, other.privateSeed) && Arrays.equals(this.root, other.root) && Arrays.equals(this.publicSeed, other.publicSeed);
		}

		return false;
	}

	public static XMSSPrivateKey of(final XMSSConfig config, final byte[] serial, final int offset)
	{
		final int n = config.getWOTSPConfig().getN();
		int o = 0;

		final int idx = Utils.bytesToUnsignedZ(serial, offset, 4).intValueExact();
		o += 4;

		final byte[] wotspCompactPrivateKeys = new byte[config.getCompactedWOTSPPrivateKeysLength()];
		System.arraycopy(serial, offset + o, wotspCompactPrivateKeys, 0, wotspCompactPrivateKeys.length);
		o += wotspCompactPrivateKeys.length;

		final byte[] privateSeed = new byte[n];
		System.arraycopy(serial, offset + o, privateSeed, 0, privateSeed.length);
		o += privateSeed.length;

		final byte[] root = new byte[n];
		System.arraycopy(serial, offset + o, root, 0, root.length);
		o += root.length;

		final byte[] publicSeed = new byte[n];
		System.arraycopy(serial, offset + o, publicSeed, 0, publicSeed.length);
		o += publicSeed.length;

		return new XMSSPrivateKey(idx, wotspCompactPrivateKeys, privateSeed, root, publicSeed);
	}
}
