import * as anchor from "@anchor-lang/core";
import { Program, BN } from "@anchor-lang/core";
import { Prophet } from "../target/types/prophet";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  Ed25519Program,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  getAccount,
  getAssociatedTokenAddress,
} from "@solana/spl-token";
import { assert } from "chai";
import * as nacl from "tweetnacl";

describe("prophet-invariants", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Prophet as Program<Prophet>;
  const authority = provider.wallet;
  const admin = (provider.wallet as anchor.Wallet).payer;

  let quoteMint: PublicKey;
  const oracle = Keypair.generate();
  const traderA = Keypair.generate();
  const traderB = Keypair.generate();

  const DECIMALS = 6;

  const asNum = (v: any): number => (typeof v === "number" ? v : v.toNumber());

  const deriveMarket = (resolver: Buffer, openTs: BN) => {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("market"), resolver, openTs.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  };

  const deriveOrder = (market: PublicKey, owner: PublicKey, seq: BN) => {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("order"), market.toBuffer(), owner.toBuffer(), seq.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  };

  const derivePosition = (market: PublicKey, owner: PublicKey) => {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("position"), market.toBuffer(), owner.toBuffer()],
      program.programId
    )[0];
  };

  const deriveNotaryConfig = (adminPk: PublicKey) => {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("notary_config"), adminPk.toBuffer()],
      program.programId
    )[0];
  };

  const createManualEd25519Ix = (
    message: Buffer,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): TransactionInstruction => {
    const pkOffset = 16;
    const sigOffset = 48;
    const msgOffset = 112;
    const msgLen = message.length;

    const header = Buffer.alloc(16);
    header.writeUInt8(1, 0);
    header.writeUInt8(0, 1);
    header.writeUInt16LE(sigOffset, 2);
    header.writeUInt16LE(0xffff, 4);
    header.writeUInt16LE(pkOffset, 6);
    header.writeUInt16LE(0xffff, 8);
    header.writeUInt16LE(msgOffset, 10);
    header.writeUInt16LE(msgLen, 12);
    header.writeUInt16LE(0xffff, 14);

    return new TransactionInstruction({
      programId: Ed25519Program.programId,
      keys: [],
      data: Buffer.concat([header, Buffer.from(publicKey), Buffer.from(signature), message]),
    });
  };

  const ensureNotaryConfig = async (notaryKeys: PublicKey[]): Promise<{ notaryConfig: PublicKey; version: BN }> => {
    const notaryConfig = deriveNotaryConfig(admin.publicKey);
    const existing = await provider.connection.getAccountInfo(notaryConfig);

    if (existing) {
      await program.methods
        .updateNotaryConfig(1, notaryKeys)
        .accounts({
          notaryConfig,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();
    } else {
      await program.methods
        .initializeNotaryConfig(1, notaryKeys)
        .accounts({
          notaryConfig,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();
    }

    const cfgAcc = await program.account.notaryConfig.fetch(notaryConfig);
    return { notaryConfig, version: new BN(cfgAcc.version.toString()) };
  };

  const getChainTime = async (): Promise<number | null> => {
    const slot = await provider.connection.getSlot();
    return provider.connection.getBlockTime(slot);
  };

  const getSafeChainNow = async (timeoutMs = 15000): Promise<number> => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const t = await getChainTime();
      if (t !== null) return t;
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("Timeout waiting for valid chain time");
  };

  const waitUntilChainTimeGE = async (target: number, timeoutMs = 20000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const current = await getChainTime();
      if (current !== null && current >= target) return;
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`Timeout waiting for chain time >= ${target}`);
  };

  const fetchOrderOrNull = async (order: PublicKey): Promise<any | null> => {
    try {
      return await program.account.order.fetch(order);
    } catch (_e) {
      return null;
    }
  };

  const assertVaultEquation = async (vaultKey: PublicKey, positions: any[], orders: Array<any | null>) => {
    const vaultAcct = await getAccount(provider.connection, vaultKey);
    const vaultBal = BigInt(vaultAcct.amount.toString());

    let sumOrderEscrow = BigInt(0);
    for (const o of orders) {
      if (o) sumOrderEscrow += BigInt(o.escrowRemainingAtoms.toString());
    }

    let sumRefunds = BigInt(0);
    let sumYes = new BN(0);
    let sumNo = new BN(0);
    for (const p of positions) {
      sumRefunds += BigInt(p.pendingRefundsAtoms.toString());
      sumYes = sumYes.add(p.yesSharesAtoms);
      sumNo = sumNo.add(p.noSharesAtoms);
    }

    assert.isTrue(sumYes.eq(sumNo), `Mirror invariant failed: YES=${sumYes.toString()} NO=${sumNo.toString()}`);

    const openInterest = BigInt(sumYes.toString());
    const expected = sumOrderEscrow + sumRefunds + openInterest;

    assert.equal(
      vaultBal,
      expected,
      `Vault Eq Failed: Act=${vaultBal} Exp=${expected} (Escrow=${sumOrderEscrow}, Ref=${sumRefunds}, OI=${openInterest})`
    );
  };

  before(async () => {
    await provider.connection.requestAirdrop(oracle.publicKey, 10e9);
    await provider.connection.requestAirdrop(traderA.publicKey, 10e9);
    await provider.connection.requestAirdrop(traderB.publicKey, 10e9);
    await new Promise((r) => setTimeout(r, 2000));

    quoteMint = await createMint(
      provider.connection,
      (authority as any).payer,
      authority.publicKey,
      null,
      DECIMALS
    );

    const ataA = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (authority as any).payer,
      quoteMint,
      traderA.publicKey
    );
    const ataB = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (authority as any).payer,
      quoteMint,
      traderB.publicKey
    );

    await mintTo(provider.connection, (authority as any).payer, quoteMint, ataA.address, authority.publicKey, 1_000_000);
    await mintTo(provider.connection, (authority as any).payer, quoteMint, ataB.address, authority.publicKey, 1_000_000);
  });

  it("invariant: counters, vault equation, bounded claim, no double-claim", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xc1);
    const openTs = new BN(safeNow - 100);
    const lockTs = new BN(safeNow + 400);
    const resolveTs = new BN(safeNow + 400);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);
    const ataA = await getAssociatedTokenAddress(quoteMint, traderA.publicKey);
    const { notaryConfig } = await ensureNotaryConfig([oracle.publicKey]);

    await program.methods
      .initializeMarketV2([...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096)
      .accounts({
        market: marketKey,
        authority: authority.publicKey,
        oracleAuthority: oracle.publicKey,
        quoteMint,
        quoteVault: vaultKey,
        notaryConfig,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .rpc();

    const seqA = new BN(0);
    const seqB = new BN(1);

    const orderA = deriveOrder(marketKey, traderA.publicKey, seqA);
    const orderB = deriveOrder(marketKey, traderB.publicKey, seqB);
    const posA = derivePosition(marketKey, traderA.publicKey);
    const posB = derivePosition(marketKey, traderB.publicKey);

    await program.methods
      .placeOrder(seqA, { buyYes: {} }, 60_000_000, new BN(100))
      .accounts({
        market: marketKey,
        order: orderA,
        position: posA,
        owner: traderA.publicKey,
        ownerQuoteAta: ataA,
        quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([traderA])
      .rpc();

    let market = await program.account.market.fetch(marketKey);
    assert.equal(asNum((market as any).openOrdersTotal), 1);

    const ataB = await getAssociatedTokenAddress(quoteMint, traderB.publicKey);
    await program.methods
      .placeOrder(seqB, { buyNo: {} }, 60_000_000, new BN(50))
      .accounts({
        market: marketKey,
        order: orderB,
        position: posB,
        owner: traderB.publicKey,
        ownerQuoteAta: ataB,
        quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([traderB])
      .rpc();

    market = await program.account.market.fetch(marketKey);
    assert.equal(asNum((market as any).openOrdersTotal), 2);

    await program.methods
      .matchOrders(new BN(50))
      .accounts({
        market: marketKey,
        orderYes: orderA,
        orderNo: orderB,
        positionYes: posA,
        positionNo: posB,
        ownerYes: traderA.publicKey,
        ownerNo: traderB.publicKey,
        marketQuoteVault: vaultKey,
      })
      .rpc();

    market = await program.account.market.fetch(marketKey);
    assert.equal(asNum((market as any).openOrdersTotal), 1);

    const pAAfterMatch = await program.account.position.fetch(posA);
    const pBAfterMatch = await program.account.position.fetch(posB);
    assert.equal(asNum((pAAfterMatch as any).openOrders), 1);
    assert.equal(asNum((pBAfterMatch as any).openOrders), 0);

    const oAAfterMatch = await fetchOrderOrNull(orderA);
    const oBAfterMatch = await fetchOrderOrNull(orderB);
    assert.isNotNull(oAAfterMatch, "YES order should remain partially open");
    assert.isNull(oBAfterMatch, "NO order should be closed after full fill");

    await assertVaultEquation(vaultKey, [pAAfterMatch, pBAfterMatch], [oAAfterMatch, oBAfterMatch]);

    await program.methods
      .cancelOrder()
      .accounts({ market: marketKey, order: orderA, position: posA, owner: traderA.publicKey })
      .signers([traderA])
      .rpc();

    market = await program.account.market.fetch(marketKey);
    assert.equal(asNum((market as any).openOrdersTotal), 0);

    const pABeforeClaim = await program.account.position.fetch(posA);
    assert.equal(pABeforeClaim.pendingRefundsAtoms.toNumber(), 30);

    const balPre = (await getAccount(provider.connection, ataA)).amount;
    await program.methods
      .claimRefunds(new BN(1_000_000))
      .accounts({
        market: marketKey,
        position: posA,
        owner: traderA.publicKey,
        quoteVault: vaultKey,
        ownerQuoteAta: ataA,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([traderA])
      .rpc();
    const balPost = (await getAccount(provider.connection, ataA)).amount;

    assert.equal(Number(balPost) - Number(balPre), 30, "claim_refunds must be bounded by pending_refunds_atoms");

    const pAAfterClaim = await program.account.position.fetch(posA);
    const pBAfterClaim = await program.account.position.fetch(posB);
    assert.equal(pAAfterClaim.pendingRefundsAtoms.toNumber(), 0);

    let secondClaimFailed = false;
    try {
      await program.methods
        .claimRefunds(new BN(1))
        .accounts({
          market: marketKey,
          position: posA,
          owner: traderA.publicKey,
          quoteVault: vaultKey,
          ownerQuoteAta: ataA,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([traderA])
        .rpc();
    } catch (_e) {
      secondClaimFailed = true;
    }
    assert.isTrue(secondClaimFailed, "second claim_refunds should fail when no refunds remain");

    await assertVaultEquation(vaultKey, [pAAfterClaim, pBAfterClaim], []);
  });

  it("invariant: redeem cannot pay twice", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xc2);
    const openTs = new BN(safeNow - 50);
    const lockTs = new BN(safeNow + 5);
    const resolveTs = new BN(safeNow + 6);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);
    const { notaryConfig, version } = await ensureNotaryConfig([oracle.publicKey]);

    await program.methods
      .initializeMarketV2([...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096)
      .accounts({
        market: marketKey,
        authority: authority.publicKey,
        oracleAuthority: oracle.publicKey,
        quoteMint,
        quoteVault: vaultKey,
        notaryConfig,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .rpc();

    const ataA = await getAssociatedTokenAddress(quoteMint, traderA.publicKey);
    const ataB = await getAssociatedTokenAddress(quoteMint, traderB.publicKey);

    const seqA = new BN(0);
    const seqB = new BN(1);
    const orderA = deriveOrder(marketKey, traderA.publicKey, seqA);
    const orderB = deriveOrder(marketKey, traderB.publicKey, seqB);
    const posA = derivePosition(marketKey, traderA.publicKey);
    const posB = derivePosition(marketKey, traderB.publicKey);

    await program.methods
      .placeOrder(seqA, { buyYes: {} }, 50_000_000, new BN(40))
      .accounts({
        market: marketKey,
        order: orderA,
        position: posA,
        owner: traderA.publicKey,
        ownerQuoteAta: ataA,
        quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([traderA])
      .rpc();

    await program.methods
      .placeOrder(seqB, { buyNo: {} }, 50_000_000, new BN(40))
      .accounts({
        market: marketKey,
        order: orderB,
        position: posB,
        owner: traderB.publicKey,
        ownerQuoteAta: ataB,
        quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([traderB])
      .rpc();

    await program.methods
      .matchOrders(new BN(40))
      .accounts({
        market: marketKey,
        orderYes: orderA,
        orderNo: orderB,
        positionYes: posA,
        positionNo: posB,
        ownerYes: traderA.publicKey,
        ownerNo: traderB.publicKey,
        marketQuoteVault: vaultKey,
      })
      .rpc();

    await waitUntilChainTimeGE(resolveTs.toNumber());

    const proofHash = Buffer.alloc(32, 9);
    const publicInputsHash = Buffer.alloc(32, 7);
    const msg = Buffer.concat([
      Buffer.from("PROPHET_RESOLVE_V2"),
      program.programId.toBuffer(),
      marketKey.toBuffer(),
      notaryConfig.toBuffer(),
      resolverHash,
      openTs.toArrayLike(Buffer, "le", 8),
      resolveTs.toArrayLike(Buffer, "le", 8),
      version.toArrayLike(Buffer, "le", 8),
      Buffer.from([1]),
      proofHash,
      publicInputsHash,
    ]);
    const sig = nacl.sign.detached(msg, oracle.secretKey);
    const ed25519Ix = createManualEd25519Ix(msg, sig, oracle.publicKey.toBuffer());
    const resolveIx = await program.methods
      .resolveMarketThreshold({ yes: {} } as any, [...proofHash], [...publicInputsHash])
      .accounts({
        market: marketKey,
        notaryConfig,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();
    await provider.sendAndConfirm(new Transaction().add(ed25519Ix).add(resolveIx), []);

    const balA1 = (await getAccount(provider.connection, ataA)).amount;
    await program.methods
      .redeem()
      .accounts({
        market: marketKey,
        position: posA,
        owner: traderA.publicKey,
        quoteVault: vaultKey,
        ownerQuoteAta: ataA,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([traderA])
      .rpc();
    const balA2 = (await getAccount(provider.connection, ataA)).amount;
    assert.equal(Number(balA2) - Number(balA1), 40, "winner should receive payout once");

    const balA3Pre = (await getAccount(provider.connection, ataA)).amount;
    try {
      await program.methods
        .redeem()
        .accounts({
          market: marketKey,
          position: posA,
          owner: traderA.publicKey,
          quoteVault: vaultKey,
          ownerQuoteAta: ataA,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([traderA])
        .rpc();
    } catch (_e) {
      // Also acceptable for this invariant: reject a second redeem.
    }
    const balA3Post = (await getAccount(provider.connection, ataA)).amount;
    assert.equal(Number(balA3Post) - Number(balA3Pre), 0, "second redeem must not pay again");

    const pAFinal = await program.account.position.fetch(posA);
    assert.equal(pAFinal.yesSharesAtoms.toNumber(), 0);
    assert.equal(pAFinal.noSharesAtoms.toNumber(), 0);
  });
});
