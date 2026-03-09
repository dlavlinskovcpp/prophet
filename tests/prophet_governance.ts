import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { Prophet } from "../target/types/prophet";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createMint,
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
});
