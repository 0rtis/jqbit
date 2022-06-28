package io.ortis.jqbit;

import java.util.Random;

public class TestUtils
{
	private static final Random DETERMINISTIC_RANDOM = new Random(42);

	public static Random getDeterministicRandom()
	{
		return DETERMINISTIC_RANDOM;
	}

	public static byte[] fromBase16(final String hex)
	{
		final int len = hex.length();

		if(len % 2 != 0)
			throw new IllegalArgumentException("Invalid string length");

		byte[] data = new byte[len >> 1];
		for(int i = 0; i < len; i += 2)
		{
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}

		return data;
	}
}
