package io.ortis.jqbit;

import java.math.BigInteger;

public abstract class Utils
{
	private final static char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

	public static String toBase16(final byte[] bytes)
	{
		return toBase16(bytes, 0, bytes.length);
	}

	public static String toBase16(final byte[] bytes, final int offset, final int length)
	{
		char[] hexChars = new char[length << 1];
		for(int j = 0; j < length; j++)
		{
			int v = bytes[j + offset] & 0xFF;
			hexChars[j * 2] = HEX_CHARS[v >>> 4];
			hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static byte[] zToBytes(final int value, final int length)
	{
		final byte[] data = BigInteger.valueOf(value).toByteArray();

		final int diff = data.length - length;

		if(diff > 0)
		{// data is too long - we assume there is leading zeroes
			final byte[] datap = new byte[length];
			System.arraycopy(data, diff, datap, 0, length);
			return  datap;
		}
		else if(diff < 0)
		{// data is too short - we fill with zeroes
			final byte[] datap = new byte[length];
			System.arraycopy(data, 0, datap, -diff, data.length);
			return  datap;
		}
		else
			return data;
	}

	public static BigInteger bytesToUnsignedZ(final byte[] value)
	{
		return bytesToUnsignedZ(value, 0, value.length);
	}

	public static BigInteger bytesToUnsignedZ(final byte[] value, final int offset, final int length)
	{
		//Use hex String to read value as unsigned Z
		return new BigInteger(toBase16(value, offset, length), 16);
	}

}
