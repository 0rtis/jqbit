package io.ortis.jqbit.xmss;

import io.ortis.jqbit.HashFunction;
import io.ortis.jqbit.Utils;
import io.ortis.jqbit.wotsp.Adrs;
import io.ortis.jqbit.wotsp.WOTSpConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Implementation of the eXtended Merkle Signature Scheme (XMSS).
 * <p>
 * XMSS is based on WOTS+ and share similar properties but is stateful and can be used multiple times.
 * Here, stateful means that the secret key changes over time.
 * <p>
 * See RFC 8391 for more details.
 */
public class XMSS
{
	public static class KeyPair
	{
		private final XMSSPrivateKey privateKey;
		private final XMSSPublicKey publicKey;
		private final XMSSTree tree;

		public KeyPair(final XMSSPrivateKey privateKey, final XMSSPublicKey publicKey, final XMSSTree tree)
		{
			this.privateKey = privateKey;
			this.publicKey = publicKey;
			this.tree = tree;
		}

		public XMSSPrivateKey getPrivateKey()
		{
			return this.privateKey;
		}

		public XMSSPublicKey getPublicKey()
		{
			return this.publicKey;
		}

		public XMSSTree getTree()
		{
			return this.tree;
		}
	}

	public static KeyPair keyPair(final XMSSConfig config, final byte[] wotspCompactPrivateKeys, final byte[] privateSeed, final byte[] publicSeed,
			final boolean storeTree, final int parallelism) throws HashFunction.Instance.HashFunctionException, ExecutionException, InterruptedException
	{
		final int wotspCount = config.getWotspCount();
		final int n = config.getWOTSPConfig().getN();

		if(wotspCompactPrivateKeys.length != config.getCompactedWOTSPPrivateKeysLength())
			throw new IllegalArgumentException(
					"Invalid WOTS+ private keys length (expected wotsp count=" + wotspCount + ", expected private key length=" + (wotspCount * n) + ")");

		final XMSSTree xmssTree;
		final byte[] root;

		if(parallelism <= 1)
		{
			if(storeTree)
			{
				final byte[] xmssFlatTree = new byte[config.getTreeNodeCount() * n];
				XMSSRFC.treeHash(config, 0, config.getH(), wotspCompactPrivateKeys, 0, publicSeed, new Adrs(), xmssFlatTree, 0);
				root = new byte[n];
				XMSSRFC.readRoot(config, xmssFlatTree, 0, root, 0);
				xmssTree = new XMSSTree(config.getH(), config.getWOTSPConfig().getN(), xmssFlatTree);
				if(!Arrays.equals(root, xmssTree.getRoot()))
					throw new RuntimeException("Tree root mismatch (read=" + Utils.toBase16(root) + ", tree=" + Utils.toBase16(xmssTree.getRoot()) + ")");
			}
			else
			{
				xmssTree = null;
				root = XMSSRFC.computeRoot(config, wotspCompactPrivateKeys, 0, publicSeed);
			}
		}
		else
		{
			final ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(parallelism, new ThreadFactory()
			{
				private final AtomicInteger count = new AtomicInteger(0);

				@Override
				public Thread newThread(final Runnable runnable)
				{
					final Thread thread = new Thread(runnable);
					thread.setName(TreeHash.class.getSimpleName() + "-" + this.count.getAndIncrement());
					return thread;
				}
			});

			final TreeHash treeHash = new TreeHash(parallelism, config, wotspCompactPrivateKeys, 0, publicSeed);
			final List<Future<TreeHash.TreeHashTask>> futures = new ArrayList<>();
			for(final TreeHash.TreeHashTask task : treeHash.buildTasks(storeTree, new ArrayList<>()))
			{
				final Future<TreeHash.TreeHashTask> future = executor.submit(task);
				futures.add(future);
			}

			for(final Future<TreeHash.TreeHashTask> future : futures)
				future.get();

			xmssTree = treeHash.toXMSSTree();
			root = xmssTree.getRoot();
		}

		final XMSSPrivateKey privateKey = new XMSSPrivateKey(0, wotspCompactPrivateKeys, privateSeed, root, publicSeed);
		final XMSSPublicKey publicKey = new XMSSPublicKey(config.getOid(), root, publicSeed);
		return new KeyPair(privateKey, publicKey, xmssTree);
	}

	/**
	 * XMSS Signature = wotsp index + r randomness + wotsp signature + authentication path
	 * </p>
	 * <b>The XMSS private key index must be incremented after calling this method !</b>
	 *
	 * @param config:         XMSS parameters
	 * @param msg:            message to sign
	 * @param xmssPrivateKey: XMSS private key
	 * @param xmssTree:       (optional) XMSS Tree
	 */
	public static XMSSSignature sign(final XMSSConfig config, final byte[] msg, final XMSSPrivateKey xmssPrivateKey, final XMSSTree xmssTree)
			throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getWOTSPConfig().getN();
		final int keyLength = config.getWOTSPConfig().getKeyLength();
		final int h = config.getH();

		if(msg.length != n)
			throw new IllegalArgumentException("Message must be " + n + " bytes long");

		final byte[] r = new byte[n];
		final byte[] wotspSign = new byte[keyLength];
		final byte[] auth = new byte[h * n];

		final int idx = xmssPrivateKey.getNextIdx();
		if(idx >= config.getWotspCount())
			throw new IllegalArgumentException("WOTS+ leaves have been exhausted");

		final byte[] xmssFlatTree = xmssTree == null ? null : xmssTree.flatTree();
		if(xmssFlatTree != null && xmssFlatTree.length != config.getTreeNodeCount() * n)
			throw new IllegalArgumentException("XMMS flat tree length must be " + (config.getTreeNodeCount() * n));

		XMSSRFC.xmssSign(config, msg, idx, xmssPrivateKey.wotspCompactPrivateKeys(), 0, xmssPrivateKey.privateSeed(), xmssPrivateKey.root(),
				xmssPrivateKey.publicSeed(), xmssFlatTree, 0, r, 0, wotspSign, 0, auth, 0);

		return new XMSSSignature(idx, r, wotspSign, auth);
	}

	public static boolean verify(final XMSSConfig config, final byte[] msg, final XMSSSignature signature, final XMSSPublicKey publicKey)
			throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getWOTSPConfig().getN();
		if(msg.length != n)
			throw new IllegalArgumentException("Message must be " + n + " bytes long");

		if(signature.wotspIndex() < 0)
			throw new IllegalArgumentException("WOTS+ leave index cannot be negative");

		if(signature.wotspIndex() >= config.getWotspCount())
			throw new IllegalArgumentException("WOTS+ index " + signature.wotspIndex() + " is outside leaves range " + config.getWotspCount());

		return XMSSRFC.xmssVerify(config, msg, signature.wotspIndex(), signature.rRandomness(), signature.wotspSignature(), signature.authenticationPath(),
				publicKey.root(), publicKey.publicSeed());
	}

	public static Integer oidSHA256(final int h)
	{
		Integer oid = null;
		switch(h)
		{
			case 10:
				oid = 1;
				break;
			case 16:
				oid = 2;
				break;
			case 20:
				oid = 3;
				break;
		}

		return oid;
	}

	public static Integer oidSHA512(final int h)
	{
		Integer oid = null;
		switch(h)
		{
			case 10:
				oid = 4;
				break;
			case 16:
				oid = 5;
				break;
			case 20:
				oid = 6;
				break;
		}

		return oid;
	}

	public static XMSSConfig config(final Integer oid, final int h, final WOTSpConfig wotspConfig)
	{
		if(h <= 0)
			throw new IllegalArgumentException("H must be greater than 0");

		return new XMSSConfig(oid == null ? 0 : oid, wotspConfig, h);
	}
}
