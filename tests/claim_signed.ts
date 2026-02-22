import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { Prophet } from "../target/types/prophet";
import {
  Ed25519Program,
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
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

describe("prophet-claim-signed", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Prophet as Program<Prophet>;
  const zeroPubkey = new PublicKey(new Uint8Array(32));

  const deriveClaim = (issuer: PublicKey, claimId: BN): PublicKey => {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("claim"), issuer.toBuffer(), claimId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
  };

  const getChainTime = async (): Promise<number> => {
    const slot = await provider.connection.getSlot();
    const t = await provider.connection.getBlockTime(slot);
    if (t === null) {
      throw new Error("No block time");
    }
    return t;
  };

  const waitUntilChainTimeGE = async (target: number, timeoutMs = 20000): Promise<void> => {
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

  it("creates, resolves (ed25519 signed), and redeems a claim", async () => {
    const payer = (provider.wallet as anchor.Wallet).payer;
    const issuer = Keypair.generate();
    const oracle = Keypair.generate();
    const passRecipient = Keypair.generate();
    const failRecipient = Keypair.generate();

    await airdrop(issuer.publicKey, 2_000_000_000);
    await airdrop(passRecipient.publicKey, 2_000_000_000);

    const quoteMint = await createMint(provider.connection, payer, payer.publicKey, null, 6);
    const issuerAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      quoteMint,
      issuer.publicKey
    );
    const passAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      quoteMint,
      passRecipient.publicKey
    );
    await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      quoteMint,
      failRecipient.publicKey
    );

    await mintTo(
      provider.connection,
      payer,
      quoteMint,
      issuerAta.address,
      payer.publicKey,
      1_000_000
    );

    const now = await getChainTime();
    const claimId = new BN(42);
    const resolveTs = new BN(now + 2);
    const bondAtoms = new BN(1_234);
    const resolverHash = Buffer.alloc(32, 9);

    const claim = deriveClaim(issuer.publicKey, claimId);
    const claimVault = await getAssociatedTokenAddress(quoteMint, claim, true);

    await (program.methods as any)
      .createClaim(
        claimId,
        Array.from(resolverHash),
        resolveTs,
        bondAtoms,
        passRecipient.publicKey,
        failRecipient.publicKey,
        oracle.publicKey,
        zeroPubkey
      )
      .accounts({
        claim,
        issuer: issuer.publicKey,
        quoteMint,
        issuerQuoteAta: issuerAta.address,
        quoteVault: claimVault,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      })
      .signers([issuer])
      .rpc();

    const claimAfterCreate = await (program.account as any).claim.fetch(claim);
    assert.equal(claimAfterCreate.status.open !== undefined, true);
    assert.equal(claimAfterCreate.outcome.undecided !== undefined, true);

    await waitUntilChainTimeGE(resolveTs.toNumber());

    const proofHash = Buffer.alloc(32, 5);
    const publicInputsHash = Buffer.alloc(32, 7);
    const msg = Buffer.concat([
      Buffer.from("PROPHET_CLAIM_RESOLVE_V1"),
      program.programId.toBuffer(),
      claim.toBuffer(),
      resolverHash,
      issuer.publicKey.toBuffer(),
      claimId.toArrayLike(Buffer, "le", 8),
      resolveTs.toArrayLike(Buffer, "le", 8),
      Buffer.from([1]), // Pass
      proofHash,
      publicInputsHash,
    ]);

    const sig = Buffer.from(nacl.sign.detached(msg, oracle.secretKey));
    const ed25519Ix = createManualEd25519Ix(msg, sig, oracle.publicKey.toBuffer());
    const resolveIx = await (program.methods as any)
      .resolveClaimSigned({ pass: {} }, Array.from(proofHash), Array.from(publicInputsHash), Array.from(sig))
      .accounts({
        claim,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    await provider.sendAndConfirm(new Transaction().add(ed25519Ix, resolveIx), [], {
      skipPreflight: true,
    });

    const claimAfterResolve = await (program.account as any).claim.fetch(claim);
    assert.equal(claimAfterResolve.status.resolved !== undefined, true);
    assert.equal(claimAfterResolve.outcome.pass !== undefined, true);

    await (program.methods as any)
      .redeemClaim()
      .accounts({
        claim,
        recipient: passRecipient.publicKey,
        quoteVault: claimVault,
        recipientQuoteAta: passAta.address,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([passRecipient])
      .rpc();

    const claimAfterRedeem = await (program.account as any).claim.fetch(claim);
    assert.equal(claimAfterRedeem.status.redeemed !== undefined, true);

    const passBal = await getAccount(provider.connection, passAta.address);
    const vaultBal = await getAccount(provider.connection, claimVault);
    assert.equal(passBal.amount.toString(), bondAtoms.toString());
    assert.equal(vaultBal.amount.toString(), "0");
  });
});
