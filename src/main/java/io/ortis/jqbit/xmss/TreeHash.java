package io.ortis.jqbit.xmss;


import io.ortis.jqbit.Utils;
import io.ortis.jqbit.wotsp.Adrs;

import java.util.Collection;
import java.util.concurrent.Callable;

/**
 * Split XMMS Tree computation into independent tasks that can be processed by multiple {@link Thread}.
 * For small values of H, the regular single-thread implementation {@link XMSSRFC#treeHash} should be preferred
 * as the multi-thead implementation add some fixed overhead to the computation.
 */
public class TreeHash
{
	private final int parallelism;
	private final XMSSConfig config;
	private final byte[] wotspCompactPrivateKeys;
	private final int wotspCompactPrivateKeysOffset;
	private final byte[] publicSeed;

	private final Node[][] tree;
	private final Object lock = new Object();

	public TreeHash(final int parallelism, final XMSSConfig config, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,
			final byte[] publicSeed)
	{
		this.parallelism = parallelism;
		this.config = config;
		this.wotspCompactPrivateKeys = wotspCompactPrivateKeys;
		this.wotspCompactPrivateKeysOffset = wotspCompactPrivateKeysOffset;
		this.publicSeed = publicSeed;

		final int h = this.config.getH();
		/* Store a tree where nodes at the top (leaves) are at level 0 and the node at the bottom (root) is at level h */
		this.tree = new Node[h + 1][];
		for(int i = 0; i < this.tree.length; i++)
			this.tree[i] = new Node[XMSSRFC.pow2(h - i)];

	}

	public <D extends Collection<TreeHashTask>> D buildTasks(final boolean storeTree, final D destination)
	{
		final int h = this.config.getH();
		final int leaveCount = this.config.getWotspCount();

		// compute the number of leaves per task (must be a power of 2)
		int batch = -1;
		for(int i = 1; i < h; i++)
		{
			final int lpt = XMSSRFC.pow2(i);
			final int totalLeaves = lpt * this.parallelism;
			if(totalLeaves >= leaveCount)
				break;

			batch = lpt;
		}

		if(batch <= 0)
			batch = 2;

		final int leavesPerTask = batch;
		if(leavesPerTask % 2 != 0)
			throw new RuntimeException("Leaves per task must be even");

		if(leavesPerTask <= 0 || (leavesPerTask & (leavesPerTask - 1)) != 0)
			throw new RuntimeException("Leaves per task must be a power of 2");

		final int taskCount = leaveCount / leavesPerTask;

		int rootLevel = -1;
		for(int p = 1; p <= h; p++)

			if(XMSSRFC.pow2(p) == leavesPerTask)
			{
				rootLevel = p;
				break;
			}

		if(rootLevel <= 0)
			throw new RuntimeException("Root level must be greater than 0");

		int count = 0;
		for(int l = 0; l < leaveCount; l += leavesPerTask)
		{
			final TreeHashTask task = new TreeHashTask(this, l, rootLevel, storeTree);
			destination.add(task);
			count++;
		}

		if(taskCount != count)
			throw new RuntimeException("Unexpected number of tasks");

		return destination;
	}

	public XMSSTree toXMSSTree()
	{
		final int h = this.config.getH();
		final int n = this.config.getWOTSPConfig().getN();
		final byte[] flatTree = new byte[(this.config.getWotspCount() * 2 - 1) * this.config.getWOTSPConfig().getN()];
		for(int treeHeight = 0; treeHeight < this.tree.length; treeHeight++)
		{

			final Node[] level = this.tree[treeHeight];
			for(int treeIndex = 0; treeIndex < level.length; treeIndex++)
			{
				final Node node = level[treeIndex];
				final int index = XMSSRFC.flatTreeIndex(treeHeight, treeIndex, 0, h, n);
				System.arraycopy(node.value(), 0, flatTree, index, n);
			}
		}

		return new XMSSTree(h, n, flatTree);
	}

	public int getParallelism()
	{
		return this.parallelism;
	}

	public XMSSConfig getConfig()
	{
		return this.config;
	}

	public static class TreeHashTask implements Callable<TreeHashTask>
	{
		private final TreeHash treeHash;

		private final int startLeaveIndex;
		private final int rootNodeLevel;
		private final boolean storeTree;

		private final byte[] tree;
		private final Adrs adrs;

		public TreeHashTask(final TreeHash treeHash, final int startLeaveIndex, final int rootNodeLevel, final boolean storeTree)
		{
			this.treeHash = treeHash;
			this.startLeaveIndex = startLeaveIndex;
			this.rootNodeLevel = rootNodeLevel;
			this.storeTree = storeTree;

			if(this.storeTree)
				this.tree = new byte[(XMSSRFC.pow2(this.rootNodeLevel) * 2 - 1) * this.treeHash.config.getWOTSPConfig().getN()];
			else
				this.tree = null;
			this.adrs = new Adrs();
		}

		@Override
		public TreeHashTask call() throws  Exception
		{
			final XMSSConfig config = this.treeHash.getConfig();
			final int h = config.getH();
			final int n = config.getWOTSPConfig().getN();

			// compute task tree
			final byte[] root = XMSSRFC.treeHash(config, this.startLeaveIndex, this.rootNodeLevel, this.treeHash.wotspCompactPrivateKeys,
					this.treeHash.wotspCompactPrivateKeysOffset, this.treeHash.publicSeed, this.adrs, this.tree, 0);

			final int fullTreeRootIndex = this.startLeaveIndex / XMSSRFC.pow2(this.rootNodeLevel);

			if(this.storeTree)
			{
				for(int treeHeight = 0; treeHeight <= this.rootNodeLevel; treeHeight++)
				{
					final int count = XMSSRFC.pow2(this.rootNodeLevel - treeHeight);
					int fullTreeIndex = this.startLeaveIndex / XMSSRFC.pow2(treeHeight);

					for(int treeIndex = 0; treeIndex < count; treeIndex++)
					{

						final int localFlatTreeIndex = XMSSRFC.flatTreeIndex(treeHeight, treeIndex, 0, this.rootNodeLevel, n);
						final byte[] nodeValue = new byte[n];
						System.arraycopy(this.tree, localFlatTreeIndex, nodeValue, 0, nodeValue.length);
						final Node node = new Node(nodeValue, treeHeight, fullTreeIndex);

						synchronized(this.treeHash.lock)
						{
							if(this.treeHash.tree[treeHeight][fullTreeIndex] != null)
								throw new IllegalStateException("Tree node " + node + " already set");

							this.treeHash.tree[node.getHeight()][node.getIndex()] = node;
							fullTreeIndex++;
						}
					}
				}
			}
			else
			{
				final Node node = new Node(root, this.rootNodeLevel, fullTreeRootIndex);
				synchronized(this.treeHash.lock)
				{
					if(this.treeHash.tree[node.getHeight()][node.getIndex()] != null)
						throw new IllegalStateException("Tree node " + node + " already set");
					this.treeHash.tree[node.getHeight()][node.getIndex()] = node;
				}
			}

			if(this.rootNodeLevel > 0)
			{
				// check if mother node is set. If not, check if sibling node is set.
				Node localRoot;
				Node siblingRoot;

				synchronized(this.treeHash.lock)
				{
					localRoot = this.treeHash.tree[this.rootNodeLevel][fullTreeRootIndex];
					tree:
					while(localRoot.getHeight() < h)
					{
						if(this.treeHash.tree[localRoot.getHeight() + 1][localRoot.getIndex() / 2] != null)
							break tree;// mother node already set

						final boolean localLeft = localRoot.getIndex() % 2 == 0;

						if(localLeft)
							siblingRoot = this.treeHash.tree[localRoot.getHeight()][localRoot.getIndex() + 1];
						else
							siblingRoot = this.treeHash.tree[localRoot.getHeight()][localRoot.getIndex() - 1];

						if(siblingRoot == null)
							break tree;// sibling node not available

						// compute mother node
						this.adrs.setTreeHeight(localRoot.getHeight());

						final byte[] left;
						final byte[] right;
						if(localLeft)
						{
							left = localRoot.value();
							right = siblingRoot.value();

							// adjust index depending on node position (in randhash(), node is always on the right before merging but not here)
							this.adrs.setTreeIndex(localRoot.getIndex() >> 1);
						}
						else
						{
							left = siblingRoot.value();
							right = localRoot.value();

							this.adrs.setTreeIndex((localRoot.getIndex() - 1) >> 1);
						}

						final byte[] motherValue = new byte[n];
						XMSSRFC.randHash(config, left, 0, right, 0, this.treeHash.publicSeed, this.adrs, motherValue, 0);

						final Node mother = new Node(motherValue, localRoot.getHeight() + 1, localRoot.getIndex() / 2);
						this.treeHash.tree[mother.getHeight()][mother.getIndex()] = mother;
						localRoot = mother;
					}
				}
			}

			return this;
		}
	}

	public static class Node
	{
		private final byte[] value;
		private final int height;
		private final int index;

		public Node(final byte[] value, final int height, final int index)
		{
			this.value = value;
			this.height = height;
			this.index = index;
		}

		public byte[] value()
		{
			return this.value;
		}

		public int getHeight()
		{
			return this.height;
		}

		public int getIndex()
		{
			return this.index;
		}

		@Override
		public String toString()
		{
			return getClass().getSimpleName() + "{" +
				   "value=" + Utils.toBase16(this.value) +
				   ", height=" + this.height +
				   ", index=" + this.index +
				   "}";
		}
	}
}
