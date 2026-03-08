import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
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
import { TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, createMint, getOrCreateAssociatedTokenAccount, mintTo, getAccount, getAssociatedTokenAddress } from "@solana/spl-token";
import { assert } from "chai";
import * as nacl from "tweetnacl";

describe("prophet-mvp-oracle-v0.2-e2e-final-robust", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Prophet as Program<Prophet>;
  const authority = provider.wallet;

  let quoteMint: PublicKey;
  const relayer = Keypair.generate(); 
  const oracle = Keypair.generate();
  
  const traderA = Keypair.generate(); 
  const traderB = Keypair.generate(); 

  const DECIMALS = 6;

  // --- HELPERS ---

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

  // Strictly returns chain time or null
  const getChainTime = async (): Promise<number | null> => {
      const slot = await provider.connection.getSlot();
      const time = await provider.connection.getBlockTime(slot);
      return time;
  };

  // Ensure we get a valid chain timestamp, waiting if necessary
  const getSafeChainNow = async (timeoutMs = 15000): Promise<number> => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
          const t = await getChainTime();
          if (t !== null) return t;
          await new Promise(r => setTimeout(r, 500));
      }
      throw new Error("Timeout waiting for valid chain time");
  };

  const waitUntilChainTimeGE = async (target: number, timeoutMs = 15000) => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
          const current = await getChainTime();
          if (current !== null && current >= target) return;
          await new Promise(r => setTimeout(r, 500));
      }
      throw new Error(`Timeout waiting for chain time >= ${target}`);
  };

  const sendAndConfirm = async (tx: Transaction, signer: Keypair) => {
      const latest = await provider.connection.getLatestBlockhash();
      tx.recentBlockhash = latest.blockhash;
      tx.feePayer = signer.publicKey;
      tx.sign(signer);
      
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      
      const conf = await provider.connection.confirmTransaction({
        signature: sig,
        blockhash: latest.blockhash,
        lastValidBlockHeight: latest.lastValidBlockHeight,
      });

      if (conf.value.err) {
          throw new Error("Transaction failed: " + JSON.stringify(conf.value.err));
      }
      return sig;
  };

  const assertMirror = (yesTotal: BN, noTotal: BN) => {
      assert.isTrue(yesTotal.eq(noTotal), `Mirror invariant failed: YES=${yesTotal.toString()} NO=${noTotal.toString()}`);
  };

  const assertVaultEquation = async (vaultKey: PublicKey, positions: any[], orders: any[]) => {
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

      assertMirror(sumYes, sumNo);
      
      const openInterest = BigInt(sumYes.toString());
      const expected = sumOrderEscrow + sumRefunds + openInterest;
      
      assert.equal(vaultBal, expected, 
          `Vault Eq Failed: Act=${vaultBal} Exp=${expected} (Escrow=${sumOrderEscrow}, Ref=${sumRefunds}, OI=${openInterest})`);
  };

  const createManualEd25519Ix = (
      message: Buffer,
      signature: Uint8Array,
      publicKey: Uint8Array,
      indexes?: { sigIx?: number; pkIx?: number; msgIx?: number }
  ) => {
      const pkOffset = 16;
      const sigOffset = 48;
      const msgOffset = 112;
      const msgLen = message.length;
      const sigIx = indexes?.sigIx ?? 0xFFFF;
      const pkIx = indexes?.pkIx ?? 0xFFFF;
      const msgIx = indexes?.msgIx ?? 0xFFFF;
      
      const buffer = Buffer.alloc(16 + 32 + 64 + msgLen);
      
      buffer.writeUInt8(1, 0); 
      buffer.writeUInt8(0, 1); 
      buffer.writeUInt16LE(sigOffset, 2);
      buffer.writeUInt16LE(sigIx, 4); 
      buffer.writeUInt16LE(pkOffset, 6);
      buffer.writeUInt16LE(pkIx, 8); 
      buffer.writeUInt16LE(msgOffset, 10);
      buffer.writeUInt16LE(msgLen, 12);
      buffer.writeUInt16LE(msgIx, 14); 
      
      buffer.set(publicKey, pkOffset);
      buffer.set(signature, sigOffset);
      buffer.set(message, msgOffset);
      
      return new TransactionInstruction({
          keys: [],
          programId: Ed25519Program.programId,
          data: buffer
      });
  };

  before(async () => {
    try {
        await provider.connection.requestAirdrop(relayer.publicKey, 10e9);
        await provider.connection.requestAirdrop(oracle.publicKey, 10e9);
        await provider.connection.requestAirdrop(traderA.publicKey, 10e9);
        await provider.connection.requestAirdrop(traderB.publicKey, 10e9);
        
        await new Promise(r => setTimeout(r, 2000));
        
        quoteMint = await createMint(provider.connection, (authority as any).payer, authority.publicKey, null, DECIMALS);

        const ataA = await getOrCreateAssociatedTokenAccount(provider.connection, (authority as any).payer, quoteMint, traderA.publicKey);
        const ataB = await getOrCreateAssociatedTokenAccount(provider.connection, (authority as any).payer, quoteMint, traderB.publicKey);
        
        await mintTo(provider.connection, (authority as any).payer, quoteMint, ataA.address, authority.publicKey, 1_000_000);
        await mintTo(provider.connection, (authority as any).payer, quoteMint, ataB.address, authority.publicKey, 1_000_000);

    } catch(e) {
        console.log("Setup failed:", e);
        throw e;
    }
  });

  // --------------------------------------------------------------------------
  // GOLDEN TEST A: Standard Match (100 vs 50 @ 0.60)
  // --------------------------------------------------------------------------
  it("Golden Vector A: Standard Match (100 vs 50 @ 0.60)", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA1);
    const openTs = new BN(safeNow - 100);
    const lockTs = new BN(safeNow + 1000); 
    const resolveTs = new BN(safeNow + 1000);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    // Alice: BuyYes 100 @ 0.60
    const seqA = new BN(0);
    const orderA = deriveOrder(marketKey, traderA.publicKey, seqA);
    const posA = derivePosition(marketKey, traderA.publicKey);
    const ataA = await getAssociatedTokenAddress(quoteMint, traderA.publicKey);

    await program.methods.placeOrder(
        seqA, { buyYes: {} }, 60_000_000, new BN(100)
    ).accounts({
        market: marketKey, order: orderA, position: posA,
        owner: traderA.publicKey, ownerQuoteAta: ataA, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderA]).rpc();

    let oA = await program.account.order.fetch(orderA);
    assert.equal(oA.escrowRemainingAtoms.toNumber(), 60, "Alice Escrow Mismatch");

    // Bob: BuyNo 50 @ 0.60
    const seqB = new BN(1);
    const orderB = deriveOrder(marketKey, traderB.publicKey, seqB);
    const posB = derivePosition(marketKey, traderB.publicKey);
    const ataB = await getAssociatedTokenAddress(quoteMint, traderB.publicKey);

    await program.methods.placeOrder(
        seqB, { buyNo: {} }, 60_000_000, new BN(50)
    ).accounts({
        market: marketKey, order: orderB, position: posB,
        owner: traderB.publicKey, ownerQuoteAta: ataB, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderB]).rpc();

    let oB = await program.account.order.fetch(orderB);
    assert.equal(oB.escrowRemainingAtoms.toNumber(), 20, "Bob Escrow Mismatch");

    let vaultBal = (await getAccount(provider.connection, vaultKey)).amount;
    assert.equal(vaultBal.toString(), "80", "Vault Pre-Match Mismatch");

    // Match 50
    await program.methods.matchOrders(new BN(50)).accounts({
        market: marketKey, orderYes: orderA, orderNo: orderB,
        positionYes: posA, positionNo: posB,
        ownerYes: traderA.publicKey, ownerNo: traderB.publicKey,
        marketQuoteVault: vaultKey
    }).rpc();

    oA = await program.account.order.fetch(orderA);
    assert.equal(oA.qtyRemainingAtoms.toNumber(), 50, "Alice Qty Mismatch");
    assert.equal(oA.escrowRemainingAtoms.toNumber(), 30, "Alice Rem Escrow Mismatch");

    try {
        await program.account.order.fetch(orderB);
        assert.fail("Bob's order should be closed");
    } catch(e) {
        assert.ok(true);
    }

    const pA = await program.account.position.fetch(posA);
    const pB = await program.account.position.fetch(posB);
    assert.equal(pA.yesSharesAtoms.toNumber(), 50, "Alice Shares Mismatch");
    assert.equal(pB.noSharesAtoms.toNumber(), 50, "Bob Shares Mismatch");
    assert.equal(pA.pendingRefundsAtoms.toNumber(), 0, "Alice Refund Mismatch");
    assert.equal(pB.pendingRefundsAtoms.toNumber(), 0, "Bob Refund Mismatch");

    vaultBal = (await getAccount(provider.connection, vaultKey)).amount;
    assert.equal(vaultBal.toString(), "80", "Vault Post-Match Mismatch");
  });

  // --------------------------------------------------------------------------
  // GOLDEN TEST B: Dust Refund (3 vs 3)
  // --------------------------------------------------------------------------
  it("Golden Vector B: Dust Refund (3 vs 3 @ 0.60)", async () => {
    const safeNow = await getSafeChainNow();
    const resolverB = Buffer.alloc(32, 0xA2);
    const openTs = new BN(safeNow - 100);
    const lockTs = new BN(safeNow + 1000);
    const resolveTs = new BN(safeNow + 1000);

    const marketKey = deriveMarket(resolverB, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverB], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const seqA = new BN(0);
    const orderA = deriveOrder(marketKey, traderA.publicKey, seqA);
    const posA = derivePosition(marketKey, traderA.publicKey);
    const ataA = await getAssociatedTokenAddress(quoteMint, traderA.publicKey);

    await program.methods.placeOrder(
        seqA, { buyYes: {} }, 60_000_000, new BN(3)
    ).accounts({
        market: marketKey, order: orderA, position: posA,
        owner: traderA.publicKey, ownerQuoteAta: ataA, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderA]).rpc();

    const seqB = new BN(1);
    const orderB = deriveOrder(marketKey, traderB.publicKey, seqB);
    const posB = derivePosition(marketKey, traderB.publicKey);
    const ataB = await getAssociatedTokenAddress(quoteMint, traderB.publicKey);

    await program.methods.placeOrder(
        seqB, { buyNo: {} }, 60_000_000, new BN(3)
    ).accounts({
        market: marketKey, order: orderB, position: posB,
        owner: traderB.publicKey, ownerQuoteAta: ataB, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderB]).rpc();

    await program.methods.matchOrders(new BN(3)).accounts({
        market: marketKey, orderYes: orderA, orderNo: orderB,
        positionYes: posA, positionNo: posB,
        ownerYes: traderA.publicKey, ownerNo: traderB.publicKey,
        marketQuoteVault: vaultKey
    }).rpc();

    const pA = await program.account.position.fetch(posA);
    assert.equal(pA.pendingRefundsAtoms.toNumber(), 1, "Alice Dust Refund Missing");
    
    const pB = await program.account.position.fetch(posB);
    assert.equal(pB.pendingRefundsAtoms.toNumber(), 0, "Bob Refund Incorrect");

    try { await program.account.order.fetch(orderA); assert.fail(); } catch(e){ assert.ok(true); }
    try { await program.account.order.fetch(orderB); assert.fail(); } catch(e){ assert.ok(true); }

    let vaultBal = (await getAccount(provider.connection, vaultKey)).amount;
    assert.equal(vaultBal.toString(), "4", "Vault Dust Mismatch");
  });

  // --------------------------------------------------------------------------
  // Legacy Flow: Resolve Market via Oracle Signer
  // --------------------------------------------------------------------------
  it("Legacy Flow: Resolve Market via Oracle Signer", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA3);
    const openTs = new BN(safeNow - 100);
    const lockTs = new BN(safeNow - 50);
    const resolveTs = new BN(safeNow - 50);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    await program.methods.resolveMarket({ yes: {} }, [...resolverHash], [...resolverHash])
      .accounts({ market: marketKey, oracleAuthority: oracle.publicKey })
      .signers([oracle])
      .rpc();

    const m = await program.account.market.fetch(marketKey);
    assert.deepEqual(m.status, { resolved: {} });
  });

  // --------------------------------------------------------------------------
  // Signed Flow: Resolve Market via Ed25519 Signature
  // --------------------------------------------------------------------------
  it("Signed Flow: Resolve Market via Ed25519 Signature", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA4);
    const openTs = new BN(safeNow - 200);
    const lockTs = new BN(safeNow - 50);
    const resolveTs = new BN(safeNow - 50);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const proof = Buffer.alloc(32, 1);
    const pi = Buffer.alloc(32, 2);
    const outcomeIdx = 1; 
    
    const msg = Buffer.concat([
        Buffer.from("PROPHET_RESOLVE_V1"),
        marketKey.toBuffer(),
        resolverHash,
        openTs.toArrayLike(Buffer, "le", 8),
        Buffer.from([outcomeIdx]),
        proof,
        pi
    ]);

    const sig = nacl.sign.detached(msg, oracle.secretKey);
    const ed25519Ix = createManualEd25519Ix(msg, sig, oracle.publicKey.toBuffer());

    const resolveIx = await program.methods.resolveMarketSigned(
        { yes: {} }, [...proof], [...pi], [...sig]
    ).accounts({
        market: marketKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(ed25519Ix).add(resolveIx);
    await sendAndConfirm(tx, relayer);

    const m = await program.account.market.fetch(marketKey);
    assert.deepEqual(m.status, { resolved: {} });
    assert.deepEqual(m.proofHash, [...proof]);
  });

  // --------------------------------------------------------------------------
  // Signed Flow: Immediate-Previous Ed25519 Window
  // --------------------------------------------------------------------------
  it("Signed Flow: Requires the immediately previous ed25519 ix to match", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA7);
    const openTs = new BN(safeNow - 220);
    const lockTs = new BN(safeNow - 50);
    const resolveTs = new BN(safeNow - 50);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const proof = Buffer.alloc(32, 11);
    const pi = Buffer.alloc(32, 12);
    const outcomeIdx = 1;

    const goodMsg = Buffer.concat([
      Buffer.from("PROPHET_RESOLVE_V1"),
      marketKey.toBuffer(),
      resolverHash,
      openTs.toArrayLike(Buffer, "le", 8),
      Buffer.from([outcomeIdx]),
      proof,
      pi
    ]);
    const goodSig = nacl.sign.detached(goodMsg, oracle.secretKey);
    const edGood = createManualEd25519Ix(goodMsg, goodSig, oracle.publicKey.toBuffer());

    const decoyProof = Buffer.alloc(32, 13);
    const decoyMsg = Buffer.concat([
      Buffer.from("PROPHET_RESOLVE_V1"),
      marketKey.toBuffer(),
      resolverHash,
      openTs.toArrayLike(Buffer, "le", 8),
      Buffer.from([outcomeIdx]),
      decoyProof,
      pi
    ]);
    const decoySig = nacl.sign.detached(decoyMsg, oracle.secretKey);
    const edDecoy = createManualEd25519Ix(decoyMsg, decoySig, oracle.publicKey.toBuffer());

    const resolveIx = await program.methods.resolveMarketSigned(
      { yes: {} }, [...proof], [...pi], [...goodSig]
    ).accounts({
      market: marketKey,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(edGood).add(edDecoy).add(resolveIx);
    let threw = false;
    try {
      await sendAndConfirm(tx, relayer);
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "expected failure when latest ed25519 ix is a decoy");
  });

  // --------------------------------------------------------------------------
  // Signed Flow: Reject Cross-Instruction Ed25519 Indexes
  // --------------------------------------------------------------------------
  it("Signed Flow: Rejects ed25519 ix that references other instruction indexes", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA8);
    const openTs = new BN(safeNow - 240);
    const lockTs = new BN(safeNow - 50);
    const resolveTs = new BN(safeNow - 50);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const proof = Buffer.alloc(32, 14);
    const pi = Buffer.alloc(32, 15);
    const outcomeIdx = 1;
    const msg = Buffer.concat([
      Buffer.from("PROPHET_RESOLVE_V1"),
      marketKey.toBuffer(),
      resolverHash,
      openTs.toArrayLike(Buffer, "le", 8),
      Buffer.from([outcomeIdx]),
      proof,
      pi
    ]);
    const sig = nacl.sign.detached(msg, oracle.secretKey);

    const ed25519Ix = createManualEd25519Ix(
      msg,
      sig,
      oracle.publicKey.toBuffer(),
      { sigIx: 0, pkIx: 0, msgIx: 0 }
    );

    const resolveIx = await program.methods.resolveMarketSigned(
      { yes: {} }, [...proof], [...pi], [...sig]
    ).accounts({
      market: marketKey,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(ed25519Ix).add(resolveIx);
    let threw = false;
    try {
      await sendAndConfirm(tx, relayer);
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "expected failure for non-self ed25519 index references");
  });

  // --------------------------------------------------------------------------
  // Signed Flow: Stale Signature Payload
  // --------------------------------------------------------------------------
  it("Signed Flow: Fails when a stale signature is reused with new payload hashes", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA9);
    const openTs = new BN(safeNow - 260);
    const lockTs = new BN(safeNow - 50);
    const resolveTs = new BN(safeNow - 50);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTs, resolveTs, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const proofA = Buffer.alloc(32, 21);
    const piA = Buffer.alloc(32, 22);
    const proofB = Buffer.alloc(32, 23); // stale-signature mismatch target
    const outcomeIdx = 1;

    const msgA = Buffer.concat([
      Buffer.from("PROPHET_RESOLVE_V1"),
      marketKey.toBuffer(),
      resolverHash,
      openTs.toArrayLike(Buffer, "le", 8),
      Buffer.from([outcomeIdx]),
      proofA,
      piA
    ]);
    const sigA = nacl.sign.detached(msgA, oracle.secretKey);
    const ed25519Ix = createManualEd25519Ix(msgA, sigA, oracle.publicKey.toBuffer());

    const resolveIx = await program.methods.resolveMarketSigned(
      { yes: {} }, [...proofB], [...piA], [...sigA]
    ).accounts({
      market: marketKey,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(ed25519Ix).add(resolveIx);
    let threw = false;
    try {
      await sendAndConfirm(tx, relayer);
    } catch {
      threw = true;
    }
    assert.equal(threw, true, "expected stale signature payload mismatch to fail");
  });
  
  // --------------------------------------------------------------------------
  // Signed Flow: Replay Failure
  // --------------------------------------------------------------------------
  it("Signed Flow: Replay Fails (Market Mismatch)", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xA5);
    const openTsA = new BN(safeNow - 300);
    const marketKeyA = deriveMarket(resolverHash, openTsA);
    const vaultKeyA = await getAssociatedTokenAddress(quoteMint, marketKeyA, true);
    await program.methods.initializeMarket(
      [...resolverHash], openTsA, openTsA, openTsA, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKeyA, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKeyA, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const openTsB = new BN(safeNow - 400);
    const marketKeyB = deriveMarket(resolverHash, openTsB);
    const vaultKeyB = await getAssociatedTokenAddress(quoteMint, marketKeyB, true);
    await program.methods.initializeMarket(
      [...resolverHash], openTsB, openTsB, openTsB, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKeyB, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKeyB, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const proof = Buffer.alloc(32, 1);
    const pi = Buffer.alloc(32, 2);
    const outcomeIdx = 1;
    const msgA = Buffer.concat([
        Buffer.from("PROPHET_RESOLVE_V1"),
        marketKeyA.toBuffer(),
        resolverHash,
        openTsA.toArrayLike(Buffer, "le", 8),
        Buffer.from([outcomeIdx]),
        proof,
        pi
    ]);
    const sigA = nacl.sign.detached(msgA, oracle.secretKey);

    const ed25519Ix = createManualEd25519Ix(msgA, sigA, oracle.publicKey.toBuffer());

    const resolveIx = await program.methods.resolveMarketSigned(
        { yes: {} }, [...proof], [...pi], [...sigA]
    ).accounts({
        market: marketKeyB, 
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(ed25519Ix).add(resolveIx);
    try {
        await sendAndConfirm(tx, relayer);
        assert.fail("Should have failed Replay");
    } catch (e) {
        assert.ok(true);
    }
  });

  // --------------------------------------------------------------------------
  // Signed Flow: Too Early Failure
  // --------------------------------------------------------------------------
  it("Signed Flow: Fails Too Early", async () => {
      const safeNow = await getSafeChainNow();
      const openTs = new BN(safeNow);
      const resolverHash = Buffer.alloc(32, 0xA6);
      const resolveTs = new BN(safeNow + 1000);
      
      const marketKey = deriveMarket(resolverHash, openTs);
      const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

      await program.methods.initializeMarket(
        [...resolverHash], openTs, resolveTs, resolveTs, new BN(1), new BN(1), 32, 4096
      ).accounts({
        market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
        quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
      }).rpc();

      const proof = Buffer.alloc(32, 1);
      const pi = Buffer.alloc(32, 2);
      const outcomeIdx = 1;
      
      const msg = Buffer.concat([
          Buffer.from("PROPHET_RESOLVE_V1"),
          marketKey.toBuffer(),
          resolverHash,
          openTs.toArrayLike(Buffer, "le", 8),
          Buffer.from([outcomeIdx]),
          proof,
          pi
      ]);

      const sig = nacl.sign.detached(msg, oracle.secretKey);
      const ed25519Ix = createManualEd25519Ix(msg, sig, oracle.publicKey.toBuffer());

      const resolveIx = await program.methods.resolveMarketSigned(
          { yes: {} }, [...proof], [...pi], [...sig]
      ).accounts({
          market: marketKey,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
      }).instruction();

      const tx = new Transaction().add(ed25519Ix).add(resolveIx);
      try {
          await sendAndConfirm(tx, relayer);
          assert.fail("Should have failed TooEarly");
      } catch (e) {
          assert.ok(true);
      }
  });

  // --------------------------------------------------------------------------
  // E2E: Full Lifecycle Test (Exact Math & Robust)
  // --------------------------------------------------------------------------
  it("E2E: Place -> Match (Partial) -> Cancel -> Claim -> Resolve Signed -> Redeem", async () => {
    const safeNow = await getSafeChainNow();
    const resolverHash = Buffer.alloc(32, 0xB1); 
    const openTs = new BN(safeNow - 100);
    const lockTsE2E = new BN(safeNow + 15);
    const resolveTsE2E = new BN(safeNow + 15);

    const marketKey = deriveMarket(resolverHash, openTs);
    const vaultKey = await getAssociatedTokenAddress(quoteMint, marketKey, true);

    await program.methods.initializeMarket(
      [...resolverHash], openTs, lockTsE2E, resolveTsE2E, new BN(1), new BN(1), 32, 4096
    ).accounts({
      market: marketKey, authority: authority.publicKey, oracleAuthority: oracle.publicKey,
      quoteMint, quoteVault: vaultKey, systemProgram: SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID, associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID
    }).rpc();

    const ataA = await getAssociatedTokenAddress(quoteMint, traderA.publicKey);
    const ataB = await getAssociatedTokenAddress(quoteMint, traderB.publicKey);

    // Place Orders
    const seqA = new BN(0);
    const orderA = deriveOrder(marketKey, traderA.publicKey, seqA);
    const posA = derivePosition(marketKey, traderA.publicKey);
    await program.methods.placeOrder(seqA, { buyYes: {} }, 60_000_000, new BN(100)).accounts({
        market: marketKey, order: orderA, position: posA, owner: traderA.publicKey,
        ownerQuoteAta: ataA, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderA]).rpc();

    const seqB = new BN(1);
    const orderB = deriveOrder(marketKey, traderB.publicKey, seqB);
    const posB = derivePosition(marketKey, traderB.publicKey);
    await program.methods.placeOrder(seqB, { buyNo: {} }, 60_000_000, new BN(50)).accounts({
        market: marketKey, order: orderB, position: posB, owner: traderB.publicKey,
        ownerQuoteAta: ataB, quoteVault: vaultKey,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId
    }).signers([traderB]).rpc();

    // Match 20
    await program.methods.matchOrders(new BN(20)).accounts({
        market: marketKey, orderYes: orderA, orderNo: orderB,
        positionYes: posA, positionNo: posB,
        ownerYes: traderA.publicKey, ownerNo: traderB.publicKey,
        marketQuoteVault: vaultKey
    }).rpc();

    // --- CHECKPOINT 1: Post Match ---
    {
        const pA = await program.account.position.fetch(posA);
        const pB = await program.account.position.fetch(posB);
        const oA = await program.account.order.fetch(orderA);
        const oB = await program.account.order.fetch(orderB);
        
        assert.equal(pA.yesSharesAtoms.toNumber(), 20);
        assert.equal(pB.noSharesAtoms.toNumber(), 20);
        assert.equal(oA.qtyRemainingAtoms.toNumber(), 80);
        assert.equal(oA.escrowRemainingAtoms.toNumber(), 48); // 60 - 12
        assert.equal(oB.qtyRemainingAtoms.toNumber(), 30);
        assert.equal(oB.escrowRemainingAtoms.toNumber(), 12); // 20 - 8
        assert.equal(pA.pendingRefundsAtoms.toNumber(), 0);
        assert.equal(pB.pendingRefundsAtoms.toNumber(), 0);

        await assertVaultEquation(vaultKey, [pA, pB], [oA, oB]);
    }

    // Cancel Remaining
    await program.methods.cancelOrder().accounts({
        market: marketKey, order: orderA, position: posA, owner: traderA.publicKey
    }).signers([traderA]).rpc();
    
    await program.methods.cancelOrder().accounts({
        market: marketKey, order: orderB, position: posB, owner: traderB.publicKey
    }).signers([traderB]).rpc();

    // --- CHECKPOINT 2: Post Cancel ---
    {
        const pA = await program.account.position.fetch(posA);
        const pB = await program.account.position.fetch(posB);
        
        assert.equal(pA.pendingRefundsAtoms.toNumber(), 48);
        assert.equal(pB.pendingRefundsAtoms.toNumber(), 12);
        
        await assertVaultEquation(vaultKey, [pA, pB], []);
    }

    // Claim Refunds
    const balA_pre = (await getAccount(provider.connection, ataA)).amount;
    const balB_pre = (await getAccount(provider.connection, ataB)).amount;

    await program.methods.claimRefunds(new BN(48)).accounts({
        market: marketKey, position: posA, owner: traderA.publicKey,
        quoteVault: vaultKey, ownerQuoteAta: ataA, tokenProgram: TOKEN_PROGRAM_ID
    }).signers([traderA]).rpc();

    await program.methods.claimRefunds(new BN(12)).accounts({
        market: marketKey, position: posB, owner: traderB.publicKey,
        quoteVault: vaultKey, ownerQuoteAta: ataB, tokenProgram: TOKEN_PROGRAM_ID
    }).signers([traderB]).rpc();

    // --- CHECKPOINT 3: Post Claim ---
    {
        const balA_post = (await getAccount(provider.connection, ataA)).amount;
        const balB_post = (await getAccount(provider.connection, ataB)).amount;
        
        assert.equal(Number(balA_post) - Number(balA_pre), 48);
        assert.equal(Number(balB_post) - Number(balB_pre), 12);

        const pA = await program.account.position.fetch(posA);
        const pB = await program.account.position.fetch(posB);
        
        assert.equal(pA.pendingRefundsAtoms.toNumber(), 0);
        assert.equal(pB.pendingRefundsAtoms.toNumber(), 0);
        
        await assertVaultEquation(vaultKey, [pA, pB], []);
    }

    // Wait & Resolve Signed
    await waitUntilChainTimeGE(resolveTsE2E.toNumber());

    const proof = Buffer.alloc(32, 1);
    const pi = Buffer.alloc(32, 2);
    const outcomeIdx = 1; // YES
    
    const msg = Buffer.concat([
        Buffer.from("PROPHET_RESOLVE_V1"),
        marketKey.toBuffer(),
        resolverHash,
        openTs.toArrayLike(Buffer, "le", 8),
        Buffer.from([outcomeIdx]),
        proof,
        pi
    ]);
    const sig = nacl.sign.detached(msg, oracle.secretKey);
    const ed25519Ix = createManualEd25519Ix(msg, sig, oracle.publicKey.toBuffer());

    const resolveIx = await program.methods.resolveMarketSigned(
        { yes: {} }, [...proof], [...pi], [...sig]
    ).accounts({
        market: marketKey, instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY
    }).instruction();

    const tx = new Transaction().add(ed25519Ix).add(resolveIx);
    await sendAndConfirm(tx, relayer);

    const m = await program.account.market.fetch(marketKey);
    assert.deepEqual(m.status, { resolved: {} });
    assert.deepEqual(m.outcome, { yes: {} });

    // Redeem
    const balA_redeem_pre = (await getAccount(provider.connection, ataA)).amount;
    await program.methods.redeem().accounts({
        market: marketKey, position: posA, owner: traderA.publicKey,
        quoteVault: vaultKey, ownerQuoteAta: ataA, tokenProgram: TOKEN_PROGRAM_ID
    }).signers([traderA]).rpc();
    const balA_redeem_post = (await getAccount(provider.connection, ataA)).amount;
    
    // A: 20 YES => 20 payout
    assert.equal(Number(balA_redeem_post) - Number(balA_redeem_pre), 20);

    const balB_redeem_pre = (await getAccount(provider.connection, ataB)).amount;
    await program.methods.redeem().accounts({
        market: marketKey, position: posB, owner: traderB.publicKey,
        quoteVault: vaultKey, ownerQuoteAta: ataB, tokenProgram: TOKEN_PROGRAM_ID
    }).signers([traderB]).rpc();
    const balB_redeem_post = (await getAccount(provider.connection, ataB)).amount;
    
    // B: 20 NO => 0 payout
    assert.equal(Number(balB_redeem_post) - Number(balB_redeem_pre), 0);

    // --- CHECKPOINT 4: Final State ---
    {
        const pA = await program.account.position.fetch(posA);
        const pB = await program.account.position.fetch(posB);
        assert.equal(pA.yesSharesAtoms.toNumber(), 0);
        assert.equal(pB.noSharesAtoms.toNumber(), 0);
        
        await assertVaultEquation(vaultKey, [pA, pB], []);
    }
  });
});
