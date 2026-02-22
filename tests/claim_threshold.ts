import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { Prophet } from "../target/types/prophet";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createMint,
  getAssociatedTokenAddress,
  getOrCreateAssociatedTokenAccount,
  mintTo,
} from "@solana/spl-token";
import {
  Ed25519Program,
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { assert } from "chai";
import * as nacl from "tweetnacl";

function createManualEd25519Ix(
  message: Buffer,
  signature: Buffer,
  pubkey: Buffer
): TransactionInstruction {
  const pkOffset = 16;
  const sigOffset = 48;
  const msgOffset = 112;
  const msgLen = message.length;

  const header = Buffer.alloc(16);
  header.writeUInt8(1, 0); // num_sigs
  header.writeUInt8(0, 1); // padding
  header.writeUInt16LE(sigOffset, 2);
  header.writeUInt16LE(0xffff, 4); // sig_ix
  header.writeUInt16LE(pkOffset, 6);
  header.writeUInt16LE(0xffff, 8); // pk_ix
  header.writeUInt16LE(msgOffset, 10);
  header.writeUInt16LE(msgLen, 12);
  header.writeUInt16LE(0xffff, 14); // msg_ix

  const data = Buffer.concat([header, pubkey, signature, message]);
  return new TransactionInstruction({
    programId: Ed25519Program.programId,
    keys: [],
    data,
  });
}

describe("prophet-claim-threshold-notary", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Prophet as Program<Prophet>;

  const deriveNotaryConfig = (admin: PublicKey): PublicKey =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("notary_config"), admin.toBuffer()],
      program.programId
    )[0];

  const deriveClaim = (issuer: PublicKey, claimId: BN): PublicKey =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("claim"), issuer.toBuffer(), claimId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];

  const getChainTime = async (): Promise<number> => {
    const slot = await provider.connection.getSlot();
    const t = await provider.connection.getBlockTime(slot);
    if (t === null) {
      throw new Error("No block time");
    }
    return t;
  };

  const waitUntilChainTimeGE = async (target: number, timeoutMs = 30000): Promise<void> => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const now = await getChainTime();
      if (now >= target) {
        return;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    throw new Error(`Timeout waiting for chain time >= ${target}`);
  };

  const airdrop = async (pk: PublicKey, lamports: number): Promise<void> => {
    const sig = await provider.connection.requestAirdrop(pk, lamports);
    await provider.connection.confirmTransaction(sig, "confirmed");
  };

  const expectFail = async (tx: Transaction, label: string): Promise<void> => {
    let threw = false;
    try {
      await provider.sendAndConfirm(tx, [], { skipPreflight: true });
    } catch (_e) {
      threw = true;
    }
    assert.equal(threw, true, label);
  };

  it("success with exactly t sigs; fail with t-1, duplicate signer, outsider notary, wrong message bytes", async () => {
    const admin = (provider.wallet as anchor.Wallet).payer;
    const issuer = Keypair.generate();
    const passRecipient = Keypair.generate();
    const failRecipient = Keypair.generate();

    const notary1 = Keypair.generate();
    const notary2 = Keypair.generate();
    const notary3 = Keypair.generate();
    const outsider = Keypair.generate();

    await airdrop(issuer.publicKey, 2_000_000_000);

    const threshold = 2;
    const notaryConfig = deriveNotaryConfig(admin.publicKey);
    const existingCfg = await provider.connection.getAccountInfo(notaryConfig);
    if (existingCfg) {
      await program.methods
        .updateNotaryConfig(threshold, [notary1.publicKey, notary2.publicKey, notary3.publicKey])
        .accounts({
          notaryConfig,
          admin: admin.publicKey,
        })
        .signers([admin])
        .rpc();
    } else {
      await program.methods
        .initializeNotaryConfig(threshold, [notary1.publicKey, notary2.publicKey, notary3.publicKey])
        .accounts({
          notaryConfig,
          admin: admin.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([admin])
        .rpc();
    }

    const quoteMint = await createMint(provider.connection, admin, admin.publicKey, null, 6);
    const issuerAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      admin,
      quoteMint,
      issuer.publicKey
    );
    await mintTo(provider.connection, admin, quoteMint, issuerAta.address, admin.publicKey, 10_000_000);

    const now = await getChainTime();
    const resolveTs = new BN(now + 3);
    const bondAtoms = new BN(1_234);
    const proofHash = Buffer.alloc(32, 11);
    const publicInputsHash = Buffer.alloc(32, 12);
    const resolverHashSuccess = Buffer.alloc(32, 21);
    const resolverHashFail = Buffer.alloc(32, 22);
    const outcomeByte = 1; // PASS

    const claimIdSuccess = new BN(Date.now());
    const claimIdFail = claimIdSuccess.add(new BN(1));

    const claimSuccess = deriveClaim(issuer.publicKey, claimIdSuccess);
    const claimFail = deriveClaim(issuer.publicKey, claimIdFail);
    const quoteVaultSuccess = await getAssociatedTokenAddress(quoteMint, claimSuccess, true);
    const quoteVaultFail = await getAssociatedTokenAddress(quoteMint, claimFail, true);

    await (program.methods as any)
      .createClaim(
        claimIdSuccess,
        Array.from(resolverHashSuccess),
        resolveTs,
        bondAtoms,
        passRecipient.publicKey,
        failRecipient.publicKey,
        admin.publicKey,
        notaryConfig
      )
      .accounts({
        claim: claimSuccess,
        issuer: issuer.publicKey,
        quoteMint,
        issuerQuoteAta: issuerAta.address,
        quoteVault: quoteVaultSuccess,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([issuer])
      .rpc();

    await (program.methods as any)
      .createClaim(
        claimIdFail,
        Array.from(resolverHashFail),
        resolveTs,
        bondAtoms,
        passRecipient.publicKey,
        failRecipient.publicKey,
        admin.publicKey,
        notaryConfig
      )
      .accounts({
        claim: claimFail,
        issuer: issuer.publicKey,
        quoteMint,
        issuerQuoteAta: issuerAta.address,
        quoteVault: quoteVaultFail,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([issuer])
      .rpc();

    await waitUntilChainTimeGE(resolveTs.toNumber());

    const buildMsg = (claim: PublicKey, resolverHash: Buffer, claimId: BN, resolveTsValue: BN): Buffer =>
      Buffer.concat([
        Buffer.from("PROPHET_CLAIM_RESOLVE_V2"),
        program.programId.toBuffer(),
        claim.toBuffer(),
        notaryConfig.toBuffer(),
        resolverHash,
        issuer.publicKey.toBuffer(),
        claimId.toArrayLike(Buffer, "le", 8),
        resolveTsValue.toArrayLike(Buffer, "le", 8),
        Buffer.from([outcomeByte]),
        proofHash,
        publicInputsHash,
      ]);

    const buildResolveIx = async (claim: PublicKey) =>
      (program.methods as any)
        .resolveClaimThreshold({ pass: {} }, Array.from(proofHash), Array.from(publicInputsHash))
        .accounts({
          claim,
          notaryConfig,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();

    // success: exactly t signatures
    {
      const msg = buildMsg(claimSuccess, resolverHashSuccess, claimIdSuccess, resolveTs);
      const sig1 = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
      const sig2 = Buffer.from(nacl.sign.detached(msg, notary2.secretKey));
      const ed1 = createManualEd25519Ix(msg, sig1, notary1.publicKey.toBuffer());
      const ed2 = createManualEd25519Ix(msg, sig2, notary2.publicKey.toBuffer());
      const resolveIx = await buildResolveIx(claimSuccess);
      await provider.sendAndConfirm(new Transaction().add(ed1, ed2, resolveIx), [], {
        skipPreflight: true,
      });

      const claimAcc = await (program.account as any).claim.fetch(claimSuccess);
      assert.equal(claimAcc.status.resolved !== undefined, true);
      assert.equal(claimAcc.outcome.pass !== undefined, true);
    }

    const assertFailClaimStillOpen = async () => {
      const claimAcc = await (program.account as any).claim.fetch(claimFail);
      assert.equal(claimAcc.status.open !== undefined, true, "claim should remain open after failed resolve");
      assert.equal(
        claimAcc.outcome.undecided !== undefined,
        true,
        "claim outcome should remain undecided after failed resolve"
      );
    };

    // fail: t-1 signatures
    {
      const msg = buildMsg(claimFail, resolverHashFail, claimIdFail, resolveTs);
      const sig1 = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
      const ed1 = createManualEd25519Ix(msg, sig1, notary1.publicKey.toBuffer());
      const resolveIx = await buildResolveIx(claimFail);
      await expectFail(new Transaction().add(ed1, resolveIx), "expected t-1 signatures to fail");
      await assertFailClaimStillOpen();
    }

    // fail: duplicate signer
    {
      const msg = buildMsg(claimFail, resolverHashFail, claimIdFail, resolveTs);
      const sig1a = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
      const sig1b = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
      const ed1a = createManualEd25519Ix(msg, sig1a, notary1.publicKey.toBuffer());
      const ed1b = createManualEd25519Ix(msg, sig1b, notary1.publicKey.toBuffer());
      const resolveIx = await buildResolveIx(claimFail);
      await expectFail(new Transaction().add(ed1a, ed1b, resolveIx), "expected duplicate signer to fail");
      await assertFailClaimStillOpen();
    }

    // fail: outsider notary
    {
      const msg = buildMsg(claimFail, resolverHashFail, claimIdFail, resolveTs);
      const sigOut = Buffer.from(nacl.sign.detached(msg, outsider.secretKey));
      const sig1 = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
      const edOut = createManualEd25519Ix(msg, sigOut, outsider.publicKey.toBuffer());
      const ed1 = createManualEd25519Ix(msg, sig1, notary1.publicKey.toBuffer());
      const resolveIx = await buildResolveIx(claimFail);
      await expectFail(new Transaction().add(edOut, ed1, resolveIx), "expected outsider notary to fail");
      await assertFailClaimStillOpen();
    }

    // fail: wrong message bytes (tampered resolve_ts)
    {
      const badMsg = buildMsg(
        claimFail,
        resolverHashFail,
        claimIdFail,
        new BN(resolveTs.toNumber() + 123)
      );
      const sig1 = Buffer.from(nacl.sign.detached(badMsg, notary1.secretKey));
      const sig2 = Buffer.from(nacl.sign.detached(badMsg, notary2.secretKey));
      const ed1 = createManualEd25519Ix(badMsg, sig1, notary1.publicKey.toBuffer());
      const ed2 = createManualEd25519Ix(badMsg, sig2, notary2.publicKey.toBuffer());
      const resolveIx = await buildResolveIx(claimFail);
      await expectFail(new Transaction().add(ed1, ed2, resolveIx), "expected wrong message bytes to fail");
      await assertFailClaimStillOpen();
    }
  });
});
