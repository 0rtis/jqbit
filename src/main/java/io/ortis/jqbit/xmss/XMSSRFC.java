package io.ortis.jqbit.xmss;

import io.ortis.jqbit.HashFunction;
import io.ortis.jqbit.Utils;
import io.ortis.jqbit.wotsp.Adrs;
import io.ortis.jqbit.wotsp.WOTSpConfig;
import io.ortis.jqbit.wotsp.WOTSpRFC;

import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedList;

/**
 * Implementation of the eXtended Merkle Signature Scheme (XMSS) as specified in the RFC 8391.
 * <p>
 * Private Key = idx || wots+ private keyS || SK_PRF || root || SEED
 * Public Key = OID || root || SEED;
 * <p>
 * See RFC 8391 for more details.
 */
public class XMSSRFC
{
	public static class TreeNode
	{
		private final byte[] value;
		private final int height;

		public TreeNode(final byte[] value, final int height)
		{
			this.value = value;
			this.height = height;
		}

		public byte[] value()
		{
			return this.value;
		}

		public int getHeight()
		{
			return this.height;
		}


		@Override
		public String toString()
		{
			return getClass().getSimpleName() + "{" +
				   "value=" + Utils.toBase16(this.value) +
				   ", height=" + this.height +
				   "}";
		}
	}

	/**
	 * From RFC 8391:
	 * <p>
	 * The full XMSS signature verification is depicted below (Algorithm
	 * 14). It handles message compression, delegates the root computation
	 * to XMSS_rootFromSig, and compares the result to the value in the
	 * public key. XMSS_verify takes as input an XMSS signature Sig, a
	 * message M, and an XMSS public key PK. XMSS_verify returns true if
	 * and only if Sig is a valid signature on M under public key PK.
	 * Otherwise, it returns false.
	 *
	 * @param config:         XMSS parameters
	 * @param msg:            signed message
	 * @param idx:            index of the WOTS+ leave
	 * @param r:              XMSS signature randomness
	 * @param wotspSignature: WOTS+ signature
	 * @param auth:           authentication path
	 * @param root:           public root of the XMSS
	 * @param publicSeed:     public byte array of length N sampled from a secure source of randomness
	 */
	public static boolean xmssVerify(final XMSSConfig config, final byte[] msg, final int idx, final byte[] r, final byte[] wotspSignature,
			final byte[] auth, final byte[] root, final byte[] publicSeed) throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getWOTSPConfig().getN();
		final byte[] rRootIdx = new byte[3 * n];
		final byte[] msgp = new byte[n];


		final Adrs adrs = new Adrs();

		/* byte[n] M’ = H_msg(r || getRoot(PK) || (toByte(idx_sig, n)), M) */
		System.arraycopy(r, 0, rRootIdx, 0, n);
		System.arraycopy(root, 0, rRootIdx, n, n);
		System.arraycopy(Utils.zToBytes(idx, n), 0, rRootIdx, 2 * n, n);
		hmsg(config, rRootIdx, msg, msgp, 0);

		/* byte[n] node = XMSS_rootFromSig(idx_sig, sig_ots, auth, M’,	getSEED(PK), ADRS); */
		final byte[] node = rootFromSig(config, msgp, idx, wotspSignature, auth, publicSeed, adrs);

		return Arrays.equals(root, node);
	}

	/**
	 * From RFC 8391:
	 * <p>
	 * An XMSS signature is verified by first computing the message digest
	 * using randomness r, index idx_sig, the root from PK and message M.
	 * Then the used WOTS+ public key pk_ots is computed from the WOTS+
	 * signature using WOTS_pkFromSig. The WOTS+ public key in turn is used
	 * to compute the corresponding leaf using an L-tree. The leaf,
	 * together with index idx_sig and authentication path auth is used to
	 * compute an alternative root value for the tree. The verification
	 * succeeds if and only if the computed root value matches the one in
	 * the XMSS public key. In any other case, it MUST return fail.
	 * As for signature generation, we split verification into two parts to
	 * allow for reuse in the XMSS^MT description. The steps also needed
	 * for XMSS^MT are done by the function XMSS_rootFromSig (Algorithm 13).
	 * XMSS_verify (Algorithm 14) calls XMSS_rootFromSig as a subroutine and
	 * handles the XMSS-specific steps.
	 *
	 * @param config:         XMSS parameters
	 * @param msg:            signed message
	 * @param idx:            index of the WOTS+ leave
	 * @param wotspSignature: WOTS+ signature
	 * @param auth:           authentication path
	 * @param publicSeed:     public byte array of length N sampled from a secure source of randomness
	 * @param adrs:           data structure
	 */
	public static byte[] rootFromSig(final XMSSConfig config, final byte[] msg, final int idx, final byte[] wotspSignature, final byte[] auth, final byte[] publicSeed,
			final Adrs adrs) throws HashFunction.Instance.HashFunctionException
	{
		final int h = config.getH();
		final int n = config.getWOTSPConfig().getN();

		final byte[] wotspPublicKey = new byte[config.getWOTSPConfig().getKeyLength()];
		final byte[] node0 = new byte[n];
		final byte[] node1 = new byte[n];

		adrs.setType(Adrs.Type.OTS);// Type = OTS hash address
		adrs.setOTSAddress(idx);


		/* pk_ots = WOTS_pkFromSig(sig_ots, M’, SEED, ADRS) */
		WOTSpRFC.signatureToPublicKey(config.getWOTSPConfig(), msg, wotspSignature, publicSeed, adrs, wotspPublicKey, 0);

		adrs.setType(Adrs.Type.LTree);// Type = L-tree address
		adrs.setLTreeAddress(idx);

		/* node[0] = ltree(pk_ots, SEED, ADRS); */
		ltree(config, wotspPublicKey, publicSeed, adrs, node0, 0);

		adrs.setType(Adrs.Type.HashTree);// Type = hash tree address
		adrs.setTreeIndex(idx);

		for(int k = 0; k < h; k++)
		{
			adrs.setTreeHeight(k);
			final int twoPowK = pow2(k);

			//if((WOTSPRFC.floorDiv(idx, twoPowK) % 2) == 0)
			if((WOTSpRFC.floorDiv(idx, twoPowK) & 1) == 0)
			{
				//adrs.setTreeIndex(adrs.getTreeIndex() / 2);
				adrs.setTreeIndex(adrs.getTreeIndex() >> 1);
				/* node[1] = RAND_HASH(node[0], auth[k], SEED, ADRS) */
				randHash(config, node0, 0, auth, k * n, publicSeed, adrs, node1, 0);
			}
			else
			{
				//adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
				adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1);
				/* node[1] = RAND_HASH(auth[k], node[0], SEED, ADRS) */
				randHash(config, auth, k * n, node0, 0, publicSeed, adrs, node1, 0);
			}

			/* node[0] = node[1] */
			//node0 = node1;
			System.arraycopy(node1, 0, node0, 0, n);
		}

		return node0;
	}

	/**
	 * <b>The index of the WOTS+ leave MUST be incremented in the XMSS private key after calling this method</b>
	 * <p>
	 * From RFC 8391:
	 * <p>
	 * The algorithm XMSS_sign (Algorithm 12) described below calculates an
	 * updated private key SK and a signature on a message M. XMSS_sign
	 * takes as input a message M of arbitrary length and an XMSS private
	 * key SK. It returns the byte string containing the concatenation of
	 * the updated private key SK and the signature Sig.
	 *
	 * @param config:                              XMSS parameters
	 * @param msg:                                 message to sign
	 * @param idx:                                 index of the WOTS+ leave
	 * @param wotspCompactPrivateKeys:             compacted WOTS+ private keys
	 * @param wotspCompactPrivateKeysOffset:       byte array offset
	 * @param skPrf:                               public byte array of length N sampled from a secure source of randomness
	 * @param root:                                public root of the XMSS
	 * @param publicSeed:                          public byte array of length N sampled from a secure source of randomness
	 * @param xmssTree:                            XMSS Tree
	 * @param xmssTreeOffset:                      XMSS Tree offset
	 * @param rRandomnessDestination:              byte array with at least N slot available to store randomness r
	 * @param rRandomnessDestinationOffset:        byte array offset
	 * @param wotspSignatureDestination:           byte array with at least LEN * N slot available to store WOTS+ Signature
	 * @param wotspSignatureDestinationOffset:     byte array offset
	 * @param authenticationPathDestination:       byte array with at least H * N slot available to store Authentication Path
	 * @param authenticationPathDestinationOffset: byte array offset
	 */
	public static void xmssSign(final XMSSConfig config, final byte[] msg, final int idx, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,
			final byte[] skPrf, final byte[] root, final byte[] publicSeed, final byte[] xmssTree, final int xmssTreeOffset, final byte[] rRandomnessDestination,
			final int rRandomnessDestinationOffset, final byte[] wotspSignatureDestination, final int wotspSignatureDestinationOffset,
			final byte[] authenticationPathDestination, final int authenticationPathDestinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final int n = config.getWOTSPConfig().getN();

		final byte[] rRootIdx = new byte[3 * n];
		final byte[] msgp = new byte[n];

		/* byte[n] r = PRF(getSK_PRF(SK), toByte(idx_sig, 32)) */
		WOTSpRFC.prf(config.getWOTSPConfig(), skPrf, 0, skPrf.length, Utils.zToBytes(idx, 32), 0, 32, rRootIdx, 0);

		/* byte[n] M’ = H_msg(r || getRoot(SK) || (toByte(idx_sig, n)), M) */
		System.arraycopy(root, 0, rRootIdx, n, n);
		System.arraycopy(Utils.zToBytes(idx, n), 0, rRootIdx, 2 * n, n);
		hmsg(config, rRootIdx, msg, msgp, 0);

		/* Sig = idx_sig || r || treeSig(M’, SK, idx_sig, ADRS) */
		System.arraycopy(rRootIdx, 0, rRandomnessDestination, rRandomnessDestinationOffset, n);
		treeSig(config, msgp, idx, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, publicSeed, new Adrs(), xmssTree, xmssTreeOffset, wotspSignatureDestination,
				wotspSignatureDestinationOffset, authenticationPathDestination, authenticationPathDestinationOffset);
	}

	/**
	 * From RFC 8391:
	 * <p>
	 * For the computation of the internal n-byte nodes of a Merkle tree,
	 * the subroutine treeHash (Algorithm 9) accepts an XMSS private key SK
	 * (including seed SEED), an unsigned integer s (the start index), an
	 * unsigned integer t (the target node height), and an address ADRS that
	 * encodes the address of the containing tree. For the height of a node
	 * within a tree, counting starts with the leaves at height zero. The
	 * treeHash algorithm returns the root node of a tree of height t with
	 * the leftmost leaf being the hash of the WOTS+ pk with index s. It is
	 * REQUIRED that s % 2^t = 0, i.e., that the leaf at index s is a
	 * leftmost leaf of a sub-tree of height t. Otherwise, the hash-
	 * addressing scheme fails. The treeHash algorithm described here uses
	 * a stack holding up to (t - 1) nodes, with the usual stack functions
	 * push() and pop(). We furthermore assume that the height of a node
	 * (an unsigned integer) is stored alongside a node’s value (an n-byte
	 * string) on the stack.
	 * <p>
	 * Sig = sig_ots || auth;
	 *
	 * @param config:                              XMSS parameters
	 * @param msg:                                 message to sign
	 * @param idx:                                 index of the WOTS+ leave
	 * @param wotspCompactPrivateKeys:             compacted WOTS+ private keys
	 * @param wotspCompactPrivateKeysOffset:       byte array offset
	 * @param publicSeed:                          public byte array of length N sampled from a secure source of randomness
	 * @param adrs:                                data structure
	 * @param xmssTree:                            XMSS Tree
	 * @param xmssTreeOffset:                      XMSS Tree offset
	 * @param wotspSignatureDestination:           byte array with at least (LEN * N) slot available to store WOTS+ Signature
	 * @param wotspSignatureDestinationOffset:     byte array offset
	 * @param authenticationPathDestination:       byte array with at least (H * N) slot available to store Authentication Path
	 * @param authenticationPathDestinationOffset: byte array offset
	 */
	public static void treeSig(final XMSSConfig config, final byte[] msg, final int idx, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,
			final byte[] publicSeed, final Adrs adrs, final byte[] xmssTree, final int xmssTreeOffset, final byte[] wotspSignatureDestination,
			final int wotspSignatureDestinationOffset, final byte[] authenticationPathDestination, final int authenticationPathDestinationOffset)
			throws HashFunction.Instance.HashFunctionException
	{
		/* auth = buildAuth(SK, idx_sig, ADRS) */
		if(xmssTree == null)
			computeAuth(config, idx, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, publicSeed, adrs, authenticationPathDestination,
					authenticationPathDestinationOffset);
		else
			readAuth(config, idx, xmssTree, xmssTreeOffset, authenticationPathDestination, authenticationPathDestinationOffset);

		adrs.setType(Adrs.Type.OTS); // Type = OTS hash address
		adrs.setOTSAddress(idx);

		/* sig_ots = WOTS_sign(getWOTS_SK(SK, idx_sig),M’, getSEED(SK), adrs) */
		final byte[] wotsPrivateKey = new byte[config.getWOTSPConfig().getKeyLength()];
		inflateCompactWOTSPPrivateKey(config, idx, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, wotsPrivateKey, 0);

		WOTSpRFC.sign(config.getWOTSPConfig(), msg, wotsPrivateKey, publicSeed, adrs, wotspSignatureDestination, wotspSignatureDestinationOffset);
	}

	/**
	 * In memory authentication path computation. The XMSS tree is build,
	 * then the authentication path is computed.
	 * <p>
	 * From RFC 8391:
	 * <p>
	 * To compute the XMSS signature of a message M with an XMSS private
	 * key, the signer first computes a randomized message digest using a
	 * random value r, idx_sig, the index of the WOTS+ key pair to be used,
	 * and the root value from the public key as key. Then, a WOTS+
	 * signature of the message digest is computed using the next unused
	 * WOTS+ private key. Next, the authentication path is computed.
	 * Finally, the private key is updated, i.e., idx is incremented. An
	 * implementation MUST NOT output the signature before the private key
	 * is updated.
	 * The node values of the authentication path MAY be computed in any
	 * way. This computation is assumed to be performed by the subroutine
	 * buildAuth for the function XMSS_sign (Algorithm 12). The fastest
	 * alternative is to store all tree nodes and set the array in the
	 * signature by copying the respective nodes. The least storage-
	 * intensive alternative is to recompute all nodes for each signature
	 * online using the treeHash algorithm (Algorithm 9). Several
	 * algorithms exist in between, with different time/storage trade-offs.
	 * For an overview, see [BDS09]. A further approach can be found in
	 * [KMN14]. Note that the details of this procedure are not relevant to
	 * interoperability; it is not necessary to know any of these details in
	 * order to perform the signature verification operation. The following
	 * version of buildAuth is given for completeness. It is a simple
	 * example for understanding, but extremely inefficient. The use of one
	 * of the alternative algorithms is strongly RECOMMENDED.
	 * Given an XMSS private key SK, all nodes in a tree are determined.
	 * Their values are defined in terms of treeHash (Algorithm 9).
	 *
	 * @param config:                        XMSS parameters
	 * @param idx:                           index of the WOTS+ leave
	 * @param wotspCompactPrivateKeys:       compacted WOTS+ private keys
	 * @param wotspCompactPrivateKeysOffset: byte array offset
	 * @param publicSeed:                    public byte array of length N sampled from a secure source of randomness
	 * @param adrs:                          data structure
	 * @param destination:                   byte array with at least H * N slot available to store the authentication path
	 * @param destinationOffset:             byte array offset
	 */
	public static void computeAuth(final XMSSConfig config, final int idx, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,
			final byte[] publicSeed, final Adrs adrs, final byte[] destination, final int destinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final int h = config.getH();

		for(int j = 0; j < h; j++)
		{
			/* k = floor(i / (2^j)) XOR 1 */
			final int twoPowJ = pow2(j);
			final int k = WOTSpRFC.floorDiv(idx, twoPowJ) ^ 1;

			/* auth[j] = treeHash(SK, k * 2^j, j, ADRS) */
			final byte[] node = treeHash(config, k * twoPowJ, j, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, publicSeed, adrs, null, -1);
			System.arraycopy(node, 0, destination, destinationOffset + j * node.length, node.length);
		}
	}

	public static void readAuth(final XMSSConfig config, final int idx,
			//final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,		final byte[] publicSeed, final Adrs adrs,
			final byte[] xmssTree, final int xmssTreeOffset, final byte[] destination, final int destinationOffset)
	{
		final int h = config.getH();
		final int n = config.getWOTSPConfig().getN();

		for(int j = 0; j < h; j++)
		{
			/* k = floor(i / (2^j)) XOR 1 */
			final int twoPowJ = pow2(j);
			final int k = WOTSpRFC.floorDiv(idx, twoPowJ) ^ 1;

			final int treeIndex = k;
			final int flatTreeIndex = flatTreeIndex(j, treeIndex, 0, h, n);
			System.arraycopy(xmssTree, xmssTreeOffset + flatTreeIndex, destination, destinationOffset + j * n, n);
			// final byte [] node = new  byte[n];
			// System.arraycopy(destination, destinationOffset+j*n, node, 0, node.length);

			/* auth[j] = treeHash(SK, k * 2^j, j, ADRS)
			final byte[] nodep = treeHash(config, k * twoPowJ, j, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, publicSeed, adrs, null, -1);
			if(!Arrays.equals(node, nodep))
				System.out.println(); */
		}
	}

	/**
	 * Compute the root of the XMSS tree
	 *
	 * @param config:                        XMSS parameters
	 * @param wotspCompactPrivateKeys:       compacted WOTS+ private keys
	 * @param wotspCompactPrivateKeysOffset: byte array offset
	 * @param publicSeed:                    public byte array of length N sampled from a secure source of randomness
	 */
	public static byte[] computeRoot(final XMSSConfig config, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset, final byte[] publicSeed)
			throws HashFunction.Instance.HashFunctionException
	{
		final int h = config.getH();
		final Adrs adrs = new Adrs();
		return treeHash(config, 0, h, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, publicSeed, adrs, null, -1);
	}

	/**
	 * Read the root of the XMSS tree
	 *
	 * @param config:            XMSS parameters
	 * @param xmssTree:          XMSS Tree
	 * @param xmssTreeOffset:    XMSS Tree offset
	 * @param destination:       byte array with at least N slots available to store the root node
	 * @param destinationOffset: byte array offset
	 */
	public static void readRoot(final XMSSConfig config, final byte[] xmssTree, final int xmssTreeOffset, final byte[] destination, final int destinationOffset)
	{
		final int h = config.getH();
		final int n = config.getWOTSPConfig().getN();
		final int nodes = config.getTreeNodeCount();

		System.arraycopy(xmssTree, (nodes - 1) * n, destination, destinationOffset, n);
	}

	/**
	 * From RFC 8391:
	 * <p>
	 * For the computation of the internal n-byte nodes of a Merkle tree,
	 * the subroutine treeHash (Algorithm 9) accepts an XMSS private key SK
	 * (including seed SEED), an unsigned integer s (the start index), an
	 * unsigned integer t (the target node height), and an address ADRS that
	 * encodes the address of the containing tree. For the height of a node
	 * within a tree, counting starts with the leaves at height zero. The
	 * treeHash algorithm returns the root node of a tree of height t with
	 * the leftmost leaf being the hash of the WOTS+ pk with index s. It is
	 * REQUIRED that s % 2^t = 0, i.e., that the leaf at index s is a
	 * leftmost leaf of a sub-tree of height t. Otherwise, the hash-
	 * addressing scheme fails. The treeHash algorithm described here uses
	 * a stack holding up to (t - 1) nodes, with the usual stack functions
	 * push() and pop(). We furthermore assume that the height of a node
	 * (an unsigned integer) is stored alongside a node’s value (an n-byte
	 * string) on the stack.
	 *
	 * @param config:                        XMSS parameters
	 * @param s:                             start leave index
	 * @param t:                             target root node height
	 * @param wotspCompactPrivateKeys:       compacted WOTS+ private keys
	 * @param wotspCompactPrivateKeysOffset: byte array offset
	 * @param publicSeed:                    public byte array of length N sampled from a secure source of randomness
	 * @param adrs:                          data structure
	 * @param xmssTreeDestination:           (optional) byte array with at least 2^t - 1 slots available to store the tree (set to null to not store)
	 * @param xmssTreeDestinationOffset:     byte array offset
	 */

	public static byte[] treeHash(final XMSSConfig config, final int s, final int t, final byte[] wotspCompactPrivateKeys, final int wotspCompactPrivateKeysOffset,
			final byte[] publicSeed, final Adrs adrs, final byte[] xmssTreeDestination, final int xmssTreeDestinationOffset)
			throws HashFunction.Instance.HashFunctionException
	{
		if(s % (1 << t) != 0)
			throw new IllegalArgumentException("Inputs must verify s % 2^t == 0");

		final int twoPowT = pow2(t);

		final WOTSpConfig wotspConfig = config.getWOTSPConfig();
		final int n = wotspConfig.getN();

		final byte[] node = new byte[n];
		final byte[] sk = new byte[config.getWOTSPConfig().getKeyLength()];
		final byte[] pk = new byte[config.getWOTSPConfig().getKeyLength()];
		final Deque<TreeNode> stack = new LinkedList<>(); // LIFO structure
		for(int i = 0; i < twoPowT; i++)
		{
			adrs.setType(Adrs.Type.OTS);// Type = OTS hash address

			final int si = s + i;
			adrs.setOTSAddress(si);

			/* pk = WOTS_genPK(getWOTS_SK(SK, s + i), SEED, ADRS); */
			inflateCompactWOTSPPrivateKey(config, si, wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset, sk, 0);
			WOTSpRFC.publicKey(wotspConfig, sk, publicSeed, adrs, pk, 0);

			adrs.setType(Adrs.Type.LTree);    // Type = L-tree address
			adrs.setLTreeAddress(si);

			/* node = ltree(pk, SEED, ADRS) */

			ltree(config, pk, publicSeed, adrs, node, 0);

			adrs.setType(Adrs.Type.HashTree);    // Type = hash tree address
			adrs.setTreeHeight(0);
			adrs.setTreeIndex(si);

			TreeNode treeNode = new TreeNode(Arrays.copyOf(node, node.length), adrs.getTreeHeight());

			//System.arraycopy(node, 0, destination, i * n, n);
			if(xmssTreeDestination != null)
				System.arraycopy(node, 0, xmssTreeDestination, xmssTreeDestinationOffset + flatTreeIndex(treeNode.getHeight(), si, s, t, n), n);

			//while(Top node on Stack has same height t’as node )
			while(!stack.isEmpty() && stack.peek().getHeight() == treeNode.getHeight())
			{
				//adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
				adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1);
				/* node = RAND_HASH(Stack.pop(), node, SEED, ADRS) */
				randHash(config, stack.poll().value(), 0, treeNode.value(), 0, publicSeed, adrs, node, 0);
				adrs.setTreeHeight(adrs.getTreeHeight() + 1);

				treeNode = new TreeNode(Arrays.copyOf(node, node.length), adrs.getTreeHeight());
				if(xmssTreeDestination != null)
					System.arraycopy(node, 0, xmssTreeDestination,
							xmssTreeDestinationOffset + flatTreeIndex(treeNode.getHeight(), adrs.getTreeIndex(), s, t, n), n);
				//System.arraycopy(node, 0, destination, skip all previous level + adrs.getTreeIndex() * n, n);
			}
			/* Stack.push(node) */
			stack.push(treeNode);
		}

		if(stack.size() != 1)
			throw new RuntimeException("Stake size must be 1");

		/* return Stack.pop() */
		return stack.poll().value();
	}

	public static int flatTreeIndex(final int treeHeight, int treeIndex, final int s, final int h, final int n)
	{
		treeIndex = treeIndex - s / pow2(treeHeight);

		if(treeIndex < 0)
			throw new RuntimeException("Bad index");

		int index = 0;
		for(int i = 0; i < treeHeight; i++)
			index += pow2(h - i);

		return (index + treeIndex) * n;

	}

	/**
	 * From RFC 8391:
	 * <p>
	 * To compute the leaves of the binary hash tree, a so-called L-tree is
	 * used. An L-tree is an unbalanced binary hash tree, distinct but
	 * similar to the main XMSS binary hash tree. The algorithm ltree
	 * (Algorithm 8) takes as input a WOTS+ public key pk and compresses it
	 * to a single n-byte value pk[0]. It also takes as input an L-tree
	 * address ADRS that encodes the address of the L-tree and the seed
	 * SEED.
	 *
	 * @param config:            XMSS parameters
	 * @param wotsPublicKey:     WOTS+ public key
	 * @param publicSeed:        public byte array of length N sampled from a secure source of randomness
	 * @param adrs:              data structure
	 * @param destination:       byte array with at least N slot available to store the compressed WOTS+ public key
	 * @param destinationOffset: byte array offset
	 */
	public static void ltree(final XMSSConfig config, final byte[] wotsPublicKey, final byte[] publicSeed, final Adrs adrs, final byte[] destination,
			final int destinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final WOTSpConfig wotspConfig = config.getWOTSPConfig();
		final int len = wotspConfig.getLen();
		final int n = wotspConfig.getN();

		final byte[] pk = new byte[wotspConfig.getKeyLength()];
		System.arraycopy(wotsPublicKey, 0, pk, 0, pk.length);

		int lenp = len;
		adrs.setTreeHeight(0);
		while(lenp > 1)
		{
			for(int i = 0; i < WOTSpRFC.floorDiv(lenp, 2); i++)
			{
				final int in = i * n;
				final int index = 2 * in;
				adrs.setTreeIndex(i);

				/* pk[i] = RAND_HASH(pk[2i],pk[2 i + 1],SEED, ADRS) */
				randHash(config, pk, index, pk, index + n, publicSeed, adrs, pk, in);
			}

			if(lenp % 2 == 1)
			{
				/* pk[floor(lenp / 2)] = pk[lenp - 1] */
				System.arraycopy(pk, (lenp - 1) * n, pk, WOTSpRFC.floorDiv(lenp, 2) * n, n);
			}
			lenp = WOTSpRFC.ceilDiv(lenp, 2);
			adrs.setTreeHeight(adrs.getTreeHeight() + 1);
		}
		System.arraycopy(pk, 0, destination, destinationOffset, n);
	}

	/**
	 * From RFC 8391:
	 * <p>
	 * To improve readability, we introduce a function RAND_HASH(LEFT,
	 * RIGHT, SEED, ADRS) (Algorithm 7) that does the randomized hashing in
	 * the tree. It takes as input two n-byte values LEFT and RIGHT that
	 * represent the left and the right halves of the hash function input,
	 * the seed SEED used as key for PRF, and the address ADRS of this hash
	 * function call. RAND_HASH first uses PRF with SEED and ADRS to
	 * generate a key KEY and n-byte bitmasks BM_0, BM_1. Then, it returns
	 * the randomized hash H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1)).
	 *
	 * @param config:            XMSS parameters
	 * @param left:              left node
	 * @param leftOffset:        left node offset
	 * @param right:             right node
	 * @param rightOffset:       right node offset
	 * @param publicSeed:        public byte array of length N sampled from a secure source of randomness
	 * @param adrs:              data structure
	 * @param destination:       byte array with at least N slot available to store the hash
	 * @param destinationOffset: byte array offset
	 */
	public static void randHash(final XMSSConfig config, final byte[] left, final int leftOffset, final byte[] right, final int rightOffset, final byte[] publicSeed,
			final Adrs adrs, final byte[] destination, final int destinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final WOTSpConfig wotspConfig = config.getWOTSPConfig();
		final int n = wotspConfig.getN();
		final byte[] key = new byte[n];
		final byte[] bm0 = new byte[n];
		final byte[] bm1 = new byte[n];
		final byte[] xorLeftRightBm = new byte[2 * n];

		adrs.setKeyAndMask(0);

		/* KEY = PRF(SEED, ADRS) */
		WOTSpRFC.prf(wotspConfig, publicSeed, 0, publicSeed.length, adrs.toBytes(), 0, Adrs.LENGTH, key, 0);

		adrs.setKeyAndMask(1);

		/* BM_0 = PRF(SEED, ADRS) */
		WOTSpRFC.prf(wotspConfig, publicSeed, 0, publicSeed.length, adrs.toBytes(), 0, Adrs.LENGTH, bm0, 0);

		adrs.setKeyAndMask(2);

		/* BM_1 = PRF(SEED, ADRS) */
		WOTSpRFC.prf(wotspConfig, publicSeed, 0, publicSeed.length, adrs.toBytes(), 0, Adrs.LENGTH, bm1, 0);

		/* H(KEY, (LEFT XOR BM_0) || (RIGHT XOR BM_1)) */
		for(int i = 0; i < n; i++)
			xorLeftRightBm[i] = (byte) (left[leftOffset + i] ^ bm0[i]);

		for(int i = 0; i < n; i++)
			xorLeftRightBm[n + i] = (byte) (right[rightOffset + i] ^ bm1[i]);

		h(config, key, xorLeftRightBm, destination, destinationOffset);
	}

	/**
	 * From RFC 8391: H: SHA2-256(toByte(1, 32) || KEY || M)
	 * <p>
	 * can be generalized to H = Hash(toByte(1, N) + KEY + M).
	 */
	public static void h(final XMSSConfig config, final byte[] key, final byte[] m, final byte[] destination, final int destinationOffset)
			throws HashFunction.Instance.HashFunctionException
	{
		WOTSpRFC.functionTemplate(config.getWOTSPConfig(), 1, key, 0, key.length, m, 0, m.length, destination, destinationOffset);
	}

	/**
	 * From RFC 8391: H_msg: SHA2-256(toByte(2, 32) || KEY || M)
	 * <p>
	 * can be generalized to H_msg = Hash(toByte(2, N) + KEY + M).
	 */
	public static void hmsg(final XMSSConfig config, final byte[] key, final byte[] m, final byte[] destination, final int destinationOffset)
			throws HashFunction.Instance.HashFunctionException
	{
		WOTSpRFC.functionTemplate(config.getWOTSPConfig(), 2, key, 0, key.length, m, 0, m.length, destination, destinationOffset);
	}

	public static void inflateCompactWOTSPPrivateKey(final XMSSConfig config, final int idx, final byte[] wotspCompactPrivateKeys,
			final int wotspCompactPrivateKeysOffset, final byte[] destination, final int destinationOffset) throws HashFunction.Instance.HashFunctionException
	{
		final int offset = idx * config.getWOTSPConfig().getN();
		WOTSpRFC.inflatePrivateKey(config.getWOTSPConfig(), wotspCompactPrivateKeys, wotspCompactPrivateKeysOffset + offset, destination, destinationOffset);
	}

	public static int pow2(final int power)
	{
		return 1 << power;
		/*long value = 1;
		for(int i = 0; i < power; i++)
		{
			value *= 2;
		}

		return BigInteger.valueOf(value).intValueExact();

		 */
	}
}
