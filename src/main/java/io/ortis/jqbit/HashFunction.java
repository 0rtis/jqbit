package io.ortis.jqbit;


public interface HashFunction
{
	int digestLength();

	Instance newInstance();

	public static interface Instance
	{
		/**
		 *
		 * @param data
		 * @return self
		 * @throws HashFunctionException
		 */
		Instance update(final byte[] data) throws HashFunctionException;

		/**
		 *
		 * @param data
		 * @param offset
		 * @param length
		 * @return self
		 * @throws HashFunctionException
		 */
		Instance update(final byte[] data, final int offset, final int length) throws HashFunctionException;

		byte[] digest(final byte[] destination) throws HashFunctionException;

		public static class HashFunctionException extends Exception
		{
			public HashFunctionException(final String s)
			{
				super(s);
			}

			public HashFunctionException(final Throwable throwable)
			{
				super(throwable);
			}

			public HashFunctionException(final String s, final Throwable throwable)
			{
				super(s, throwable);
			}
		}
	}

}
