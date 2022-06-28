package io.ortis.jqbit.wotsp;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * OTS
 * +-------------------------+
 * | layer address  (32 bits)|
 * +-------------------------+
 * | tree address   (64 bits)|
 * +-------------------------+
 * | type = 0 	    (32 bits)|
 * +-------------------------+
 * | OTS address    (32 bits)|
 * +-------------------------+
 * | chain address  (32 bits)|
 * +-------------------------+
 * | hash address   (32 bits)|
 * +-------------------------+
 * | keyAndMask     (32 bits)|
 * +-------------------------+
 * <p>
 * LTree (Leaves tree)
 * +-------------------------+
 * | layer address  (32 bits)|
 * +-------------------------+
 * | tree address   (64 bits)|
 * +-------------------------+
 * | type = 1 	    (32 bits)|
 * +-------------------------+
 * | L-tree address (32 bits)|
 * +-------------------------+
 * | tree height    (32 bits)|
 * +-------------------------+
 * | tree index     (32 bits)|
 * +-------------------------+
 * | keyAndMask     (32 bits)|
 * +-------------------------+
 * <p>
 * Hash tree
 * +-------------------------+
 * | layer address  (32 bits)|
 * +-------------------------+
 * | tree address   (64 bits)|
 * +-------------------------+
 * | type = 2 	    (32 bits)|
 * +-------------------------+
 * | Padding        (32 bits)|
 * +-------------------------+
 * | tree height    (32 bits)|
 * +-------------------------+
 * | tree index     (32 bits)|
 * +-------------------------+
 * | keyAndMask     (32 bits)|
 * +-------------------------+
 */
public class Adrs
{
	public static final int LENGTH = 32;

	public enum Type
	{
		OTS(0), LTree(1), HashTree(2);
		final int id;

		Type(final int id)
		{
			this.id = id;
		}

		public int getId()
		{
			return this.id;
		}
	}

	private final byte[] buffer = new byte[32];
	private final ByteBuffer byteBuffer = ByteBuffer.wrap(this.buffer);
	private final int offset1 = 0;
	private final int offset2 = 4;
	private final int offset3 = 12;
	private final int offset4 = 16;
	private final int offset5 = 20;
	private final int offset6 = 24;
	private final int offset7 = 28;

	private Type enumType;

	public Adrs()
	{
		Arrays.fill(this.buffer, (byte) 0);
	}

	public void clearTypedFields()
	{
		for(int i = this.offset4; i < this.buffer.length; i++)
			this.buffer[i] = 0;
	}

	/* Buffer 1 */

	public void setLayerAddress(final int layerAddress)
	{
		this.byteBuffer.position(this.offset1);
		this.byteBuffer.putInt(layerAddress);
	}

	/* Buffer 2 */

	public void setTreeAddress(final int treeAddress)
	{
		this.byteBuffer.position(this.offset2);
		this.byteBuffer.putInt(treeAddress);
	}

	/* Buffer 3 */

	public Adrs setType(final Type type)
	{
		this.byteBuffer.position(this.offset3);
		this.byteBuffer.putInt(type.getId());
		this.enumType = type;
		clearTypedFields();
		return this;
	}

	/* Buffer 4 */

	public void setOTSAddress(final int otsAddress)
	{
		if(this.enumType != Type.OTS)
			throw new IllegalStateException("Invalid type (required " + Type.OTS + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset4);
		this.byteBuffer.putInt(otsAddress);
	}

	public void setLTreeAddress(final int ltreeAddress)
	{
		if(this.enumType != Type.LTree)
			throw new IllegalStateException("Invalid type (required " + Type.LTree + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset4);
		this.byteBuffer.putInt(ltreeAddress);
	}

	public void setPadding(final int padding)
	{
		if(this.enumType != Type.HashTree)
			throw new IllegalStateException("Invalid type (required " + Type.HashTree + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset4);
		this.byteBuffer.putInt(padding);
	}

	/* Buffer 5 */

	public int getChainAddress()
	{
		if(this.enumType != Type.OTS)
			throw new IllegalStateException("Invalid type (required " + Type.OTS + " but was " + this.enumType + ")");

		this.byteBuffer.position(this.offset5);
		return this.byteBuffer.getInt();
	}

	public void setChainAddress(final int chainAddress)
	{
		if(this.enumType != Type.OTS)
			throw new IllegalStateException("Invalid type (required " + Type.OTS + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset5);
		this.byteBuffer.putInt(chainAddress);
	}

	public int getTreeHeight()
	{
		if(this.enumType != Type.LTree && this.enumType != Type.HashTree)
			throw new IllegalStateException("Invalid type (required " + Type.LTree + " or " + Type.HashTree + " but was " + this.enumType + ")");

		this.byteBuffer.position(this.offset5);
		return this.byteBuffer.getInt();
	}

	public void setTreeHeight(final int treeHeight)
	{
		if(treeHeight < 0)
			throw new IllegalArgumentException("Tree height cannot be negative");

		if(this.enumType != Type.LTree && this.enumType != Type.HashTree)
			throw new IllegalStateException("Invalid type (required " + Type.LTree + " or " + Type.HashTree + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset5);
		this.byteBuffer.putInt(treeHeight);
	}

	/* Buffer 6 */

	public void setHashAddress(final int hashAddress)
	{
		if(this.enumType != Type.OTS)
			throw new IllegalStateException("Invalid type (required " + Type.OTS + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset6);
		this.byteBuffer.putInt(hashAddress);
	}

	public int getTreeIndex()
	{
		if(this.enumType != Type.LTree && this.enumType != Type.HashTree)
			throw new IllegalStateException("Invalid type (required " + Type.LTree + " or " + Type.HashTree + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset6);
		return this.byteBuffer.getInt();
	}

	public void setTreeIndex(final int treeIndex)
	{
		if(treeIndex < 0)
			throw new IllegalArgumentException("Tree index cannot be negative");

		if(this.enumType != Type.LTree && this.enumType != Type.HashTree)
			throw new IllegalStateException("Invalid type (required " + Type.LTree + " or " + Type.HashTree + " but was " + this.enumType + ")");
		this.byteBuffer.position(this.offset6);
		this.byteBuffer.putInt(treeIndex);
	}

	/* Buffer 7 */

	public void setKeyAndMask(final int keyAndMask)
	{
		this.byteBuffer.position(this.offset7);
		this.byteBuffer.putInt(keyAndMask);
	}

	public byte[] toBytes()
	{
		return Arrays.copyOf(this.buffer, this.buffer.length);
	}
}
