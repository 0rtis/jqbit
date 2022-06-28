package io.ortis.jqbit.xmss;


import io.ortis.jqbit.wotsp.WOTSpConfig;

public class XMSSConfig
{
	private final int oid;
	private final WOTSpConfig wotspConfig;
	private final int h;

	private final int wotspCount;
	private final int compactedWOTSPPrivateKeysLength;
	private final int authLength;
	private final int signatureLength;
	private final int treeNodeCount;

	public XMSSConfig(final int oid, final WOTSpConfig wotspConfig, final int h)
	{
		this.oid = oid;
		this.wotspConfig = wotspConfig;

		this.h = h;
		if(this.h <= 0)
			throw new IllegalArgumentException("H must be greater than 0");

		final int n = this.wotspConfig.getN();

		this.wotspCount = XMSSRFC.pow2(this.h);
		this.compactedWOTSPPrivateKeysLength = this.wotspCount * n;

		this.authLength = this.h * n;
		this.signatureLength = 4 /* idx */ + n /* randomness r */ + this.wotspConfig.getKeyLength() /* wots+ signature */ + this.authLength;
		this.treeNodeCount = (2 * this.wotspCount) - 1;
	}

	public int getOid()
	{
		return this.oid;
	}

	public WOTSpConfig getWOTSPConfig()
	{
		return this.wotspConfig;
	}

	public int getH()
	{
		return this.h;
	}

	public int getWotspCount()
	{
		return this.wotspCount;
	}

	public int getCompactedWOTSPPrivateKeysLength()
	{
		return this.compactedWOTSPPrivateKeysLength;
	}

	public int getWOTSPSignatureLength()
	{
		return this.wotspConfig.getKeyLength();
	}

	public int getAuthLength()
	{
		return this.authLength;
	}

	public int getSignatureLength()
	{
		return this.signatureLength;
	}

	public int getTreeNodeCount()
	{
		return this.treeNodeCount;
	}
}
