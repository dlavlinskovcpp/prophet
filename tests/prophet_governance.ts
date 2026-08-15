import * as anchor from "@anchor-lang/core";
import { BN, Program } from "@anchor-lang/core";
import { Prophet } from "../target/types/prophet";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createMint,
  getAccount,
  getAssociatedTokenAddress,
  getOrCreateAssociatedTokenAccount,
  mintTo,
} from "@solana/spl-token";
import { assert } from "chai";

describe("prophet-governance", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Prophet as Program<Prophet>;
  const admin = (provider.wallet as anchor.Wallet).payer;

  const deriveMarket = (resolver: Buffer, openTs: BN) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("market"), resolver, openTs.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  const deriveOrder = (market: PublicKey, owner: PublicKey, seq: BN) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("order"), market.toBuffer(), owner.toBuffer(), seq.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  const derivePosition = (market: PublicKey, owner: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("position"), market.toBuffer(), owner.toBuffer()],
      program.programId
    )[0];

  const deriveNotaryConfig = (adminPk: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("notary_config"), adminPk.toBuffer()],
      program.programId
    )[0];

  const ensureNotaryConfig = async (configAdmin: Keypair, notaryKeys: PublicKey[], threshold = 1) => {
    const notaryConfig = deriveNotaryConfig(configAdmin.publicKey);
    const existing = await provider.connection.getAccountInfo(notaryConfig);

    if (existing) {
      await program.methods
        .updateNotaryConfig(threshold, notaryKeys)
        .accounts({
          notaryConfig,
          admin: configAdmin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([configAdmin])
        .rpc();
    } else {
      await program.methods
        .initializeNotaryConfig(threshold, notaryKeys)
        .accounts({
          notaryConfig,
          admin: configAdmin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([configAdmin])
        .rpc();
    }

    return notaryConfig;
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

  const airdrop = async (pk: PublicKey, lamports: number) => {
    const sig = await provider.connection.requestAirdrop(pk, lamports);
    await provider.connection.confirmTransaction(sig, "confirmed");
  };

  const fetchOrderOrNull = async (order: PublicKey): Promise<any | null> => {
    try {
      return await program.account.order.fetch(order);
    } catch {
      return null;
    }
  };

  it("supports transfer authority, lock/unlock, schedule update, and permissionless status sync", async () => {
    const newAuthority = Keypair.generate();
    const outsider = Keypair.generate();
    const trader = Keypair.generate();

    await airdrop(newAuthority.publicKey, 2e9);
    await airdrop(outsider.publicKey, 2e9);
    await airdrop(trader.publicKey, 2e9);

    const quoteMint = await createMint(provider.connection, admin, admin.publicKey, null, 6);
    const traderAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      trader.publicKey
    );
    await mintTo(provider.connection, admin, quoteMint, traderAta.address, admin.publicKey, 1_000_000);

    const now = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xd1);
    const openTs = new BN(now - 5);
    const lockTs = new BN(now + 20);
    const resolveTs = new BN(now + 30);
    const market = deriveMarket(resolverHash, openTs);
    const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);
    const notaryConfig = await ensureNotaryConfig(admin, [admin.publicKey]);

    await program.methods
      .initializeMarketV2(
        [...resolverHash],
        openTs,
        lockTs,
        resolveTs,
        new BN(1),
        new BN(1),
        32,
        4096
      )
      .accounts({
        market,
        authority: admin.publicKey,
        oracleAuthority: admin.publicKey,
        quoteMint,
        quoteVault,
        notaryConfig,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([admin])
      .rpc();

    let threw = false;
    try {
      await (program.methods as any)
        .lockMarket()
        .accounts({ market, authority: outsider.publicKey })
        .signers([outsider])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "non-authority should not be able to lock");

    await (program.methods as any)
      .transferMarketAuthority(newAuthority.publicKey)
      .accounts({ market, authority: admin.publicKey })
      .signers([admin])
      .rpc();

    let marketAcc = await program.account.market.fetch(market);
    assert.equal(marketAcc.authority.toBase58(), newAuthority.publicKey.toBase58());

    threw = false;
    try {
      await (program.methods as any)
        .lockMarket()
        .accounts({ market, authority: admin.publicKey })
        .signers([admin])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "old authority should lose control after transfer");

    await (program.methods as any)
      .lockMarket()
      .accounts({ market, authority: newAuthority.publicKey })
      .signers([newAuthority])
      .rpc();

    marketAcc = await program.account.market.fetch(market);
    assert.equal(marketAcc.status.locked !== undefined, true);

    const order = deriveOrder(market, trader.publicKey, new BN(0));
    const position = derivePosition(market, trader.publicKey);
    threw = false;
    try {
      await program.methods
        .placeOrder(new BN(0), { buyYes: {} }, 60_000_000, new BN(10))
        .accounts({
          market,
          order,
          position,
          owner: trader.publicKey,
          ownerQuoteAta: traderAta.address,
          quoteVault,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([trader])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "locked market should reject new orders");

    await (program.methods as any)
      .unlockMarket()
      .accounts({ market, authority: newAuthority.publicKey })
      .signers([newAuthority])
      .rpc();

    const newLockTs = new BN(now + 12);
    const newResolveTs = new BN(now + 18);
    await (program.methods as any)
      .updateMarketSchedule(newLockTs, newResolveTs)
      .accounts({ market, authority: newAuthority.publicKey })
      .signers([newAuthority])
      .rpc();

    marketAcc = await program.account.market.fetch(market);
    assert.equal(marketAcc.status.open !== undefined, true);
    assert.equal(marketAcc.lockTs.toNumber(), newLockTs.toNumber());
    assert.equal(marketAcc.resolveTs.toNumber(), newResolveTs.toNumber());

    await waitUntilChainTimeGE(newLockTs.toNumber());
    await (program.methods as any).syncMarketStatus().accounts({ market }).rpc();

    marketAcc = await program.account.market.fetch(market);
    assert.equal(marketAcc.status.locked !== undefined, true, "sync should materialize locked status");
  });

  it("requires zero open orders for schedule update and supports authority emergency invalid resolution", async () => {
    const authority = Keypair.generate();
    const outsider = Keypair.generate();
    const trader = Keypair.generate();

    await airdrop(authority.publicKey, 2e9);
    await airdrop(outsider.publicKey, 2e9);
    await airdrop(trader.publicKey, 2e9);

    const quoteMint = await createMint(provider.connection, admin, admin.publicKey, null, 6);
    const traderAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      trader.publicKey
    );
    await mintTo(provider.connection, admin, quoteMint, traderAta.address, admin.publicKey, 1_000_000);

    const now = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xd2);
    const openTs = new BN(now - 5);
    const lockTs = new BN(now + 25);
    const resolveTs = new BN(now + 40);
    const market = deriveMarket(resolverHash, openTs);
    const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);
    const notaryConfig = await ensureNotaryConfig(authority, [authority.publicKey]);

    await program.methods
      .initializeMarketV2(
        [...resolverHash],
        openTs,
        lockTs,
        resolveTs,
        new BN(1),
        new BN(1),
        32,
        4096
      )
      .accounts({
        market,
        authority: authority.publicKey,
        oracleAuthority: authority.publicKey,
        quoteMint,
        quoteVault,
        notaryConfig,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([authority])
      .rpc();

    const order = deriveOrder(market, trader.publicKey, new BN(0));
    const position = derivePosition(market, trader.publicKey);
    await program.methods
      .placeOrder(new BN(0), { buyYes: {} }, 60_000_000, new BN(10))
      .accounts({
        market,
        order,
        position,
        owner: trader.publicKey,
        ownerQuoteAta: traderAta.address,
        quoteVault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([trader])
      .rpc();

    let threw = false;
    try {
      await (program.methods as any)
        .updateMarketSchedule(new BN(now + 50), new BN(now + 60))
        .accounts({ market, authority: authority.publicKey })
        .signers([authority])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "schedule update must fail while open orders remain");

    const proofHash = Buffer.alloc(32, 7);
    const publicInputsHash = Buffer.alloc(32, 8);

    threw = false;
    try {
      await (program.methods as any)
        .emergencyResolveInvalid(Array.from(proofHash), Array.from(publicInputsHash))
        .accounts({ market, authority: outsider.publicKey })
        .signers([outsider])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "outsider should not be able to emergency resolve");

    threw = false;
    try {
      await (program.methods as any)
        .emergencyResolveInvalid(Array.from(proofHash), Array.from(publicInputsHash))
        .accounts({ market, authority: authority.publicKey })
        .signers([authority])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "market must be manually locked before emergency resolve");

    await (program.methods as any)
      .lockMarket()
      .accounts({ market, authority: authority.publicKey })
      .signers([authority])
      .rpc();

    await (program.methods as any)
      .emergencyResolveInvalid(Array.from(proofHash), Array.from(publicInputsHash))
      .accounts({ market, authority: authority.publicKey })
      .signers([authority])
      .rpc();

    const marketAcc = await program.account.market.fetch(market);
    assert.equal(marketAcc.status.resolved !== undefined, true);
    assert.equal(marketAcc.outcome.invalid !== undefined, true);
    assert.deepEqual(marketAcc.proofHash, Array.from(proofHash));
    assert.deepEqual(marketAcc.publicInputsHash, Array.from(publicInputsHash));
  });

  it("supports protocol fee config, taker fee accrual, treasury withdrawal, and reserve refunds", async () => {
    const authority = Keypair.generate();
    const treasury = Keypair.generate();
    const makerYes = Keypair.generate();
    const takerNo = Keypair.generate();
    const canceller = Keypair.generate();

    await airdrop(authority.publicKey, 2e9);
    await airdrop(treasury.publicKey, 2e9);
    await airdrop(makerYes.publicKey, 2e9);
    await airdrop(takerNo.publicKey, 2e9);
    await airdrop(canceller.publicKey, 2e9);

    const quoteMint = await createMint(provider.connection, admin, admin.publicKey, null, 6);
    const makerYesAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      makerYes.publicKey
    );
    const takerNoAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      takerNo.publicKey
    );
    const cancellerAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      canceller.publicKey
    );
    const treasuryAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      treasury.publicKey
    );

    await mintTo(provider.connection, admin, quoteMint, makerYesAta.address, admin.publicKey, 1_000_000);
    await mintTo(provider.connection, admin, quoteMint, takerNoAta.address, admin.publicKey, 1_000_000);
    await mintTo(provider.connection, admin, quoteMint, cancellerAta.address, admin.publicKey, 1_000_000);

    const now = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xd3);
    const openTs = new BN(now - 5);
    const lockTs = new BN(now + 40);
    const resolveTs = new BN(now + 60);
    const market = deriveMarket(resolverHash, openTs);
    const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);
    const notaryConfig = await ensureNotaryConfig(authority, [authority.publicKey]);

    await program.methods
      .initializeMarketV2(
        [...resolverHash],
        openTs,
        lockTs,
        resolveTs,
        new BN(1),
        new BN(1),
        32,
        4096
      )
      .accounts({
        market,
        authority: authority.publicKey,
        oracleAuthority: authority.publicKey,
        quoteMint,
        quoteVault,
        notaryConfig,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([authority])
      .rpc();

    let invalidRecipientRejected = false;
    try {
      await (program.methods as any)
        .setMarketFeeConfig(market, 500)
        .accounts({ market, authority: authority.publicKey })
        .signers([authority])
        .rpc();
    } catch {
      invalidRecipientRejected = true;
    }
    assert.equal(
      invalidRecipientRejected,
      true,
      "the market vault authority must not be accepted as its own fee recipient"
    );

    await (program.methods as any)
      .setMarketFeeConfig(treasury.publicKey, 500)
      .accounts({ market, authority: authority.publicKey })
      .signers([authority])
      .rpc();

    let marketAcc = (await program.account.market.fetch(market)) as any;
    assert.equal(marketAcc.protocolFeeBps, 500);
    assert.equal(marketAcc.feeRecipient.toBase58(), treasury.publicKey.toBase58());

    const makerOrder = deriveOrder(market, makerYes.publicKey, new BN(0));
    const makerPosition = derivePosition(market, makerYes.publicKey);
    await program.methods
      .placeOrder(new BN(0), { buyYes: {} }, 60_000_000, new BN(100))
      .accounts({
        market,
        order: makerOrder,
        position: makerPosition,
        owner: makerYes.publicKey,
        ownerQuoteAta: makerYesAta.address,
        quoteVault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([makerYes])
      .rpc();

    const makerOrderAcc = (await program.account.order.fetch(makerOrder)) as any;
    assert.equal(makerOrderAcc.escrowRemainingAtoms.toNumber(), 60);
    assert.equal(makerOrderAcc.feeRemainingAtoms.toNumber(), 3);

    let threw = false;
    try {
      await (program.methods as any)
        .setMarketFeeConfig(authority.publicKey, 250)
        .accounts({ market, authority: authority.publicKey })
        .signers([authority])
        .rpc();
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "fee config must freeze after the first order");

    const takerOrder = deriveOrder(market, takerNo.publicKey, new BN(1));
    const takerPosition = derivePosition(market, takerNo.publicKey);
    await program.methods
      .placeOrder(new BN(1), { buyNo: {} }, 55_000_000, new BN(100))
      .accounts({
        market,
        order: takerOrder,
        position: takerPosition,
        owner: takerNo.publicKey,
        ownerQuoteAta: takerNoAta.address,
        quoteVault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([takerNo])
      .rpc();

    const takerOrderAcc = (await program.account.order.fetch(takerOrder)) as any;
    assert.equal(takerOrderAcc.escrowRemainingAtoms.toNumber(), 45);
    assert.equal(takerOrderAcc.feeRemainingAtoms.toNumber(), 3);

    await program.methods
      .matchOrders(new BN(100))
      .accounts({
        market,
        orderYes: makerOrder,
        orderNo: takerOrder,
        positionYes: makerPosition,
        positionNo: takerPosition,
        ownerYes: makerYes.publicKey,
        ownerNo: takerNo.publicKey,
        marketQuoteVault: quoteVault,
      })
      .rpc();

    assert.equal(await fetchOrderOrNull(makerOrder), null, "maker order should close on full fill");
    assert.equal(await fetchOrderOrNull(takerOrder), null, "taker order should close on full fill");

    const makerPositionAcc = (await program.account.position.fetch(makerPosition)) as any;
    const takerPositionAcc = (await program.account.position.fetch(takerPosition)) as any;
    assert.equal(makerPositionAcc.yesSharesAtoms.toNumber(), 100);
    assert.equal(makerPositionAcc.pendingRefundsAtoms.toNumber(), 3, "maker gets unused fee reserve back");
    assert.equal(takerPositionAcc.noSharesAtoms.toNumber(), 100);
    assert.equal(
      takerPositionAcc.pendingRefundsAtoms.toNumber(),
      6,
      "taker gets price improvement plus unused fee reserve back"
    );

    marketAcc = (await program.account.market.fetch(market)) as any;
    assert.equal(marketAcc.accruedProtocolFeesAtoms.toNumber(), 2, "only taker execution should accrue fees");
    assert.equal(marketAcc.openOrdersTotal, 0);

    let vaultAccount = await getAccount(provider.connection, quoteVault);
    assert.equal(Number(vaultAccount.amount), 111);

    await (program.methods as any)
      .withdrawProtocolFees(new BN(999))
      .accounts({
        market,
        authority: authority.publicKey,
        quoteVault,
        feeRecipientQuoteAta: treasuryAta.address,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([authority])
      .rpc();

    marketAcc = (await program.account.market.fetch(market)) as any;
    assert.equal(marketAcc.accruedProtocolFeesAtoms.toNumber(), 0);

    const treasuryTokenAccount = await getAccount(provider.connection, treasuryAta.address);
    assert.equal(Number(treasuryTokenAccount.amount), 2);

    vaultAccount = await getAccount(provider.connection, quoteVault);
    assert.equal(Number(vaultAccount.amount), 109);

    const cancelOrder = deriveOrder(market, canceller.publicKey, new BN(2));
    const cancelPosition = derivePosition(market, canceller.publicKey);
    await program.methods
      .placeOrder(new BN(2), { buyYes: {} }, 50_000_000, new BN(10))
      .accounts({
        market,
        order: cancelOrder,
        position: cancelPosition,
        owner: canceller.publicKey,
        ownerQuoteAta: cancellerAta.address,
        quoteVault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([canceller])
      .rpc();

    const cancelOrderAcc = (await program.account.order.fetch(cancelOrder)) as any;
    assert.equal(cancelOrderAcc.escrowRemainingAtoms.toNumber(), 5);
    assert.equal(cancelOrderAcc.feeRemainingAtoms.toNumber(), 1);

    await program.methods
      .cancelOrder()
      .accounts({
        market,
        order: cancelOrder,
        position: cancelPosition,
        owner: canceller.publicKey,
      })
      .signers([canceller])
      .rpc();

    const cancelPositionAcc = (await program.account.position.fetch(cancelPosition)) as any;
    assert.equal(cancelPositionAcc.pendingRefundsAtoms.toNumber(), 6, "cancel should refund escrow plus fee reserve");
  });
});
