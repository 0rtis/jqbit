package io.ortis.jqbit.xmss;


import io.ortis.jqbit.Utils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Public Key = OID || root || SEED;
 */
public class XMSSTree
{
	private final int h;// 4 bytes
	private final int n;// 4 bytes
	private final byte[] flatTree;// 2^h - 1 bytes
	private final byte[] root;

	private final int length;

	private transient final int hashCode;

	public XMSSTree(final int h, final int n, final byte[] flatTree)
	{
		this.h = h;
		if(this.h < 1)
			throw new IllegalArgumentException("H must be greater than 0");

		this.n = n;
		if(this.n <= 0 || (this.n & (this.n - 1)) != 0)
			throw new IllegalArgumentException("N must be a power of 2");


		this.flatTree = flatTree;
		/*if(this.flatTree.length != (XMSSRFC.pow2(this.h) - 1) *)
			throw new IllegalArgumentException("Flat tree length must be " + (XMSSRFC.pow2(this.h) - 1));
		 */
		this.root = new byte[n];
		System.arraycopy(this.flatTree, this.flatTree.length - this.root.length, this.root, 0, this.root.length);

		this.length = 4 + this.flatTree.length;

		{
			int result = Objects.hash(this.h, this.n, this.length);
			result = 31 * result + Arrays.hashCode(this.flatTree);
			this.hashCode = result;
		}
	}

	public void readNode(final int treeHeight, final int treeIndex, final byte[] destination, final int destinationOffset)
	{
		final int index = XMSSRFC.flatTreeIndex(treeHeight, treeIndex, 0, this.h, this.n);
		System.arraycopy(this.flatTree, index, destination, destinationOffset, this.n);
	}

	public byte[] toBytes()
	{
		final ByteBuffer buffer = ByteBuffer.allocate(this.length);
		buffer.putInt(this.h);
		buffer.putInt(this.n);
		buffer.put(this.flatTree);

		if(buffer.position() != buffer.capacity())
			throw new IllegalStateException("Buffer must be filled");

		return buffer.array();
	}

	public int getH()
	{
		return this.h;
	}

	public int getN()
	{
		return this.n;
	}

	public byte[] flatTree()
	{
		return this.flatTree;
	}

	public byte[] getRoot()
	{
		return Arrays.copyOf(this.root, this.root.length);
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

		if(o instanceof XMSSTree)
		{
			final XMSSTree other = (XMSSTree) o;
			return this.h == other.h && this.n == other.n && this.length == other.length && Arrays.equals(this.flatTree,
					other.flatTree);
		}

		return false;
	}

	public static XMSSTree of(final XMSSConfig config, final byte[] serial, final int offset)
	{
		int o = 0;

		final int h = Utils.bytesToUnsignedZ(serial, offset, 4).intValueExact();
		o += 4;

		if(config.getH() != h)
			throw new IllegalArgumentException("H mismatch (config=" + config.getH() + ", serial=" + h + ")");

		final int n = Utils.bytesToUnsignedZ(serial, offset, 4).intValueExact();
		o += 4;

		if(config.getWOTSPConfig().getN() != n)
			throw new IllegalArgumentException("N mismatch (config=" + config.getWOTSPConfig().getN() + ", serial=" + n + ")");

		final byte[] flatTree = new byte[(XMSSRFC.pow2(h) - 1) * n];
		System.arraycopy(serial, offset + o, flatTree, 0, flatTree.length);
		o += flatTree.length;

		return new XMSSTree(h, n, flatTree);
	}





}
