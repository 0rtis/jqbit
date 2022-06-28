package io.ortis.jqbit.xmss;

import io.ortis.jqbit.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * XMSS Signature = WOTSP Index + R Randomness + WOTSP Signature + Authentication Path
 */
public class XMSSSignature
{
	private final int wotspIndex;// 4 bytes
	private final byte[] rRandomness;// n bytes
	private final byte[] wotspSignature;// len * n bytes
	private final byte[] authenticationPath;// h * n bytes

	private final int length;

	private transient final   int hashCode;

	public XMSSSignature(final int wotspIndex, final byte[] rRandomness, final byte[] wotspSignature, final byte[] authenticationPath)
	{
		this.wotspIndex = wotspIndex;

		this.rRandomness = rRandomness;
		if((this.rRandomness.length & 1) != 0)
			throw new IllegalArgumentException("R randomness length must be even");

		this.wotspSignature = wotspSignature;
		if((this.wotspSignature.length & 1) != 0)
			throw new IllegalArgumentException("WOTS+ signature length must be even");

		this.authenticationPath = authenticationPath;
		if((this.authenticationPath.length & 1) != 0)
			throw new IllegalArgumentException("Authentication path length must be even");

		this.length = 4 + this.rRandomness.length + this.wotspSignature.length + this.authenticationPath.length;

		{
			int result = Objects.hash(this.wotspIndex, this.length);
			result = 31 * result + Arrays.hashCode(this.rRandomness);
			result = 31 * result + Arrays.hashCode(this.wotspSignature);
			result = 31 * result + Arrays.hashCode(this.authenticationPath);
			this.hashCode = result;
		}
		//= Objects.hash(this.wotspIndex, this.rRandomness, this.wotspSignature, this.authenticationPath, this.length);
	}

	public byte [] toBytes()
	{
		final ByteBuffer buffer = ByteBuffer.allocate(this.length);
		buffer.putInt(this.wotspIndex);
		buffer.put(this.rRandomness);
		buffer.put(this.wotspSignature);
		buffer.put(this.authenticationPath);

		if(buffer.position() != buffer.capacity())
			throw new IllegalStateException("Buffer must be filled");

		return buffer.array();
	}

	public int wotspIndex()
	{
		return this.wotspIndex;
	}

	public byte[] rRandomness()
	{
		return this.rRandomness;
	}

	public byte[] wotspSignature()
	{
		return this.wotspSignature;
	}

	public byte[] authenticationPath()
	{
		return this.authenticationPath;
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

		if(o instanceof XMSSSignature)
		{
			final XMSSSignature other = (XMSSSignature) o;
			return this.wotspIndex == other.wotspIndex && this.length == other.length && Arrays.equals(this.rRandomness,
					other.rRandomness) && Arrays.equals(this.wotspSignature, other.wotspSignature) && Arrays.equals(this.authenticationPath, other.authenticationPath);
		}

		return false;
	}


	public static XMSSSignature of(final XMSSConfig config, final byte[] serial, final int offset)
	{
		final int n = config.getWOTSPConfig().getN();
		int o = 0;

		final int wotspIndex = Utils.bytesToUnsignedZ(serial, o, 4).intValueExact();
		o += 4;

		final byte[] rRandomness = new byte[n];
		System.arraycopy(serial, offset + o, rRandomness, 0, rRandomness.length);
		o += rRandomness.length;

		final byte[] wotspSignature = new byte[config.getWOTSPSignatureLength()];
		System.arraycopy(serial, offset + o, wotspSignature, 0, wotspSignature.length);
		o += wotspSignature.length;

		final byte[] authenticationPath = new byte[config.getAuthLength()];
		System.arraycopy(serial, offset + o, authenticationPath, 0, authenticationPath.length);
		o += authenticationPath.length;

		return new XMSSSignature(wotspIndex, rRandomness, wotspSignature, authenticationPath);
	}
}

