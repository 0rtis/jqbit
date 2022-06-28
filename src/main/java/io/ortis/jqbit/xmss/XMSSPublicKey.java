package io.ortis.jqbit.xmss;

import io.ortis.jqbit.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Public Key = OID || root || SEED;
 */
public class XMSSPublicKey
{
	private final int oid;// 4 bytes
	private final byte[] root;// n bytes
	private final byte[] publicSeed;// n bytes

	private final int length;

	private transient final int hashCode;

	public XMSSPublicKey(final int oid, final byte[] root, final byte[] publicSeed)
	{
		this.oid = oid;

		this.root = root;
		if((this.root.length & 1) != 0)
			throw new IllegalArgumentException("Root seed length must be even");

		this.publicSeed = publicSeed;
		if((this.publicSeed.length & 1) != 0)
			throw new IllegalArgumentException("Public seed length must be even");

		this.length = 4 + this.root.length + this.publicSeed.length;

		{
			int result = Objects.hash(oid, this.length);
			result = 31 * result + Arrays.hashCode(this.root);
			result = 31 * result + Arrays.hashCode(this.publicSeed);
			this.hashCode = result;
		}
	}

	public byte[] toBytes()
	{
		final ByteBuffer buffer = ByteBuffer.allocate(this.length);
		buffer.putInt(this.oid);
		buffer.put(this.root);
		buffer.put(this.publicSeed);

		if(buffer.position() != buffer.capacity())
			throw new IllegalStateException("Buffer must be filled");

		return buffer.array();
	}

	public int getOid()
	{
		return this.oid;
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

		if(o instanceof XMSSPublicKey)
		{
			final XMSSPublicKey other = (XMSSPublicKey) o;
			return this.oid == other.oid && this.length == other.length && Arrays.equals(this.root, other.root) && Arrays.equals(this.publicSeed, other.publicSeed);
		}

		return false;
	}


	public static XMSSPublicKey of(final XMSSConfig config, final byte[] serial, final int offset)
	{
		final int n = config.getWOTSPConfig().getN();
		int o = 0;

		final int oid = Utils.bytesToUnsignedZ(serial, offset, 4).intValueExact();
		o += 4;

		final byte[] root = new byte[n];
		System.arraycopy(serial, offset + o, root, 0, root.length);
		o += root.length;

		final byte[] publicSeed = new byte[n];
		System.arraycopy(serial, offset + o, publicSeed, 0, publicSeed.length);
		o += publicSeed.length;

		return new XMSSPublicKey(oid, root, publicSeed);
	}
}
