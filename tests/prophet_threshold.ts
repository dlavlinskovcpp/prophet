// tests/prophet_threshold.ts
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
import {
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    createMint,
    getAssociatedTokenAddress,
} from "@solana/spl-token";
import { assert } from "chai";
import * as nacl from "tweetnacl";

const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

function createManualEd25519Ix(message: Buffer, signature: Buffer, pubkey: Buffer): TransactionInstruction {
    // Layout matches Solana ed25519 program instruction format for 1 sig, self-contained.
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

function createNoopMemoIx(): TransactionInstruction {
    return new TransactionInstruction({
        programId: MEMO_PROGRAM_ID,
        keys: [],
        data: Buffer.alloc(0),
    });
}

describe("prophet-threshold-notary", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.Prophet as Program<Prophet>;

    const authority = provider.wallet;

    const deriveNotaryConfig = (admin: PublicKey) => {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("notary_config"), admin.toBuffer()],
            program.programId
        )[0];
    };

    const deriveMarket = (resolver: Buffer, openTs: BN) => {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("market"), resolver, openTs.toArrayLike(Buffer, "le", 8)],
            program.programId
        )[0];
    };

    const getChainTime = async (): Promise<number> => {
        const slot = await provider.connection.getSlot();
        const t = await provider.connection.getBlockTime(slot);
        if (t === null) throw new Error("No block time");
        return t;
    };

    const airdrop = async (pk: PublicKey, lamports: number) => {
        const sig = await provider.connection.requestAirdrop(pk, lamports);
        await provider.connection.confirmTransaction(sig, "confirmed");
    };

    it("success with exactly t sigs; fails with t-1 and duplicates and wrong message and notary not allowed", async () => {
        // --- Setup: notaries + config ---
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const notary3 = Keypair.generate();
        const outsider = Keypair.generate();

        const threshold = 2;

        const notaryConfig = deriveNotaryConfig(admin.publicKey);
        const existing = await provider.connection.getAccountInfo(notaryConfig);

        if (existing) {
            await program.methods
                .updateNotaryConfig(threshold, [notary1.publicKey, notary2.publicKey, notary3.publicKey])
                .accounts({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
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
        const cfgAcc = await program.account.notaryConfig.fetch(notaryConfig);
        const notaryVersion = new BN(cfgAcc.version.toString());

        // --- Setup: quote mint + market (v2) ---
        const decimals = 6;
        const quoteMint = await createMint(
            provider.connection,
            admin,
            admin.publicKey,
            null,
            decimals
        );

        const now = await getChainTime();
        const openTs = new BN(now - 20);
        const lockTs = new BN(now - 10);
        const resolveTs = new BN(now - 1);

        const resolverHash = Buffer.alloc(32, 7);

        const market = deriveMarket(resolverHash, openTs);
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
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
                oracleAuthority: admin.publicKey, // legacy field; unused
                quoteMint,
                quoteVault,
                notaryConfig,
                systemProgram: SystemProgram.programId,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            })
            .signers([admin])
            .rpc();

        // --- Build canonical message V2 ---
        const outcomeIdx = 1; // YES
        const proofHash = Buffer.alloc(32, 1);
        const publicInputsHash = Buffer.alloc(32, 2);

        const msg = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            market.toBuffer(),
            notaryConfig.toBuffer(),
            resolverHash,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersion.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);

        // Helper to build resolve ix
        const buildResolveIx = async () => {
            return program.methods
                .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
                .accounts({
                    market,
                    notaryConfig,
                    instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
                })
                .instruction();
        };

        // --- Case 1: success with exactly t signatures ---
        {
            const sig1 = Buffer.from(nacl.sign.detached(msg, notary1.secretKey));
            const sig2 = Buffer.from(nacl.sign.detached(msg, notary2.secretKey));

            const ed1 = createManualEd25519Ix(msg, sig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(msg, sig2, notary2.publicKey.toBuffer());

            const resolveIx = await buildResolveIx();

            const tx = new Transaction().add(ed1, ed2, resolveIx);
            await provider.sendAndConfirm(tx, [], { skipPreflight: true });

            const marketAcc = await program.account.market.fetch(market);
            assert.equal(marketAcc.status.resolved !== undefined, true);
            assert.equal(marketAcc.outcome.yes !== undefined, true);
        }

        // Re-initialize a fresh market for failure cases (since the above resolved it)
        const market2 = deriveMarket(Buffer.alloc(32, 8), openTs);
        const resolverHash2 = Buffer.alloc(32, 8);
        const quoteVault2 = await getAssociatedTokenAddress(quoteMint, market2, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash2),
                openTs,
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accounts({
                market: market2,
                authority: admin.publicKey,
                oracleAuthority: admin.publicKey,
                quoteMint,
                quoteVault: quoteVault2,
                notaryConfig,
                systemProgram: SystemProgram.programId,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            })
            .signers([admin])
            .rpc();

        const msg2 = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            market2.toBuffer(),
            notaryConfig.toBuffer(),
            resolverHash2,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersion.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);

        const buildResolveIx2 = async () => {
            return program.methods
                .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
                .accounts({
                    market: market2,
                    notaryConfig,
                    instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
                })
                .instruction();
        };

        // --- Case 2: failure with t-1 sigs ---
        {
            const sig1 = Buffer.from(nacl.sign.detached(msg2, notary1.secretKey));
            const ed1 = createManualEd25519Ix(msg2, sig1, notary1.publicKey.toBuffer());
            const resolveIx = await buildResolveIx2();
            const tx = new Transaction().add(ed1, resolveIx);
            let threw = false;
            try {
                await provider.sendAndConfirm(tx, [], { skipPreflight: true });
            } catch (e) {
                threw = true;
            }
            assert.equal(threw, true, "expected t-1 signatures to fail");
        }

        // --- Case 3: failure with duplicate pubkey signatures ---
        {
            const sig1 = Buffer.from(nacl.sign.detached(msg2, notary1.secretKey));
            const sig1b = Buffer.from(nacl.sign.detached(msg2, notary1.secretKey));
            const ed1 = createManualEd25519Ix(msg2, sig1, notary1.publicKey.toBuffer());
            const ed1b = createManualEd25519Ix(msg2, sig1b, notary1.publicKey.toBuffer());
            const resolveIx = await buildResolveIx2();
            const tx = new Transaction().add(ed1, ed1b, resolveIx);
            let threw = false;
            try {
                await provider.sendAndConfirm(tx, [], { skipPreflight: true });
            } catch (e) {
                threw = true;
            }
            assert.equal(threw, true, "expected duplicate notary sigs to fail");
        }

        // --- Case 4: failure with wrong message (tampered resolve_ts) ---
        {
            const badMsg = Buffer.concat([
                Buffer.from("PROPHET_RESOLVE_V2"),
                program.programId.toBuffer(),
                market2.toBuffer(),
                notaryConfig.toBuffer(),
                resolverHash2,
                openTs.toArrayLike(Buffer, "le", 8),
                new BN(resolveTs.toNumber() + 123).toArrayLike(Buffer, "le", 8),
                notaryVersion.toArrayLike(Buffer, "le", 8),
                Buffer.from([outcomeIdx]),
                proofHash,
                publicInputsHash,
            ]);

            const sig1 = Buffer.from(nacl.sign.detached(badMsg, notary1.secretKey));
            const sig2 = Buffer.from(nacl.sign.detached(badMsg, notary2.secretKey));
            const ed1 = createManualEd25519Ix(badMsg, sig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(badMsg, sig2, notary2.publicKey.toBuffer());
            const resolveIx = await buildResolveIx2();
            const tx = new Transaction().add(ed1, ed2, resolveIx);
            let threw = false;
            try {
                await provider.sendAndConfirm(tx, [], { skipPreflight: true });
            } catch (e) {
                threw = true;
            }
            assert.equal(threw, true, "expected wrong message to fail");
        }

        // --- Case 5: failure with notary not in set ---
        {
            const sigOut = Buffer.from(nacl.sign.detached(msg2, outsider.secretKey));
            const sig1 = Buffer.from(nacl.sign.detached(msg2, notary1.secretKey));
            const edOut = createManualEd25519Ix(msg2, sigOut, outsider.publicKey.toBuffer());
            const ed1 = createManualEd25519Ix(msg2, sig1, notary1.publicKey.toBuffer());
            const resolveIx = await buildResolveIx2();
            const tx = new Transaction().add(edOut, ed1, resolveIx);
            let threw = false;
            try {
                await provider.sendAndConfirm(tx, [], { skipPreflight: true });
            } catch (e) {
                threw = true;
            }
            assert.equal(threw, true, "expected outsider notary to fail");
        }
    });

    it("enforces bounded ed25519 scan window for threshold resolution", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notaryConfig = deriveNotaryConfig(admin.publicKey);

        const existing = await provider.connection.getAccountInfo(notaryConfig);
        if (existing) {
            await program.methods
                .updateNotaryConfig(1, [notary1.publicKey])
                .accounts({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
                })
                .signers([admin])
                .rpc();
        } else {
            await program.methods
                .initializeNotaryConfig(1, [notary1.publicKey])
                .accounts({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
                })
                .signers([admin])
                .rpc();
        }
        const cfgAcc = await program.account.notaryConfig.fetch(notaryConfig);
        const notaryVersion = new BN(cfgAcc.version.toString());

        const quoteMint = await createMint(
            provider.connection,
            admin,
            admin.publicKey,
            null,
            6
        );

        const now = await getChainTime();
        const openTs = new BN(now - 40);
        const lockTs = new BN(now - 20);
        const resolveTs = new BN(now - 1);
        const outcomeIdx = 1;
        const proofHash = Buffer.alloc(32, 31);
        const publicInputsHash = Buffer.alloc(32, 32);

        const resolverInside = Buffer.alloc(32, 41);
        const marketInside = deriveMarket(resolverInside, openTs);
        const quoteVaultInside = await getAssociatedTokenAddress(quoteMint, marketInside, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverInside),
                openTs,
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accounts({
                market: marketInside,
                authority: admin.publicKey,
                oracleAuthority: admin.publicKey,
                quoteMint,
                quoteVault: quoteVaultInside,
                notaryConfig,
                systemProgram: SystemProgram.programId,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            })
            .signers([admin])
            .rpc();

        const msgInside = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            marketInside.toBuffer(),
            notaryConfig.toBuffer(),
            resolverInside,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersion.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);
        const sigInside = Buffer.from(nacl.sign.detached(msgInside, notary1.secretKey));
        const edInside = createManualEd25519Ix(msgInside, sigInside, notary1.publicKey.toBuffer());
        const resolveInside = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accounts({
                market: marketInside,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        const txInside = new Transaction().add(edInside);
        for (let i = 0; i < 63; i++) {
            txInside.add(createNoopMemoIx());
        }
        txInside.add(resolveInside);
        await provider.sendAndConfirm(txInside, [], { skipPreflight: true });

        const marketInsideAcc = await program.account.market.fetch(marketInside);
        assert.equal(marketInsideAcc.status.resolved !== undefined, true, "signature inside scan window must resolve");

        const resolverOutside = Buffer.alloc(32, 42);
        const marketOutside = deriveMarket(resolverOutside, openTs);
        const quoteVaultOutside = await getAssociatedTokenAddress(quoteMint, marketOutside, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverOutside),
                openTs,
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accounts({
                market: marketOutside,
                authority: admin.publicKey,
                oracleAuthority: admin.publicKey,
                quoteMint,
                quoteVault: quoteVaultOutside,
                notaryConfig,
                systemProgram: SystemProgram.programId,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            })
            .signers([admin])
            .rpc();

        const msgOutside = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            marketOutside.toBuffer(),
            notaryConfig.toBuffer(),
            resolverOutside,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersion.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);
        const sigOutside = Buffer.from(nacl.sign.detached(msgOutside, notary1.secretKey));
        const edOutside = createManualEd25519Ix(msgOutside, sigOutside, notary1.publicKey.toBuffer());
        const resolveOutside = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accounts({
                market: marketOutside,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        const txOutside = new Transaction().add(edOutside);
        for (let i = 0; i < 64; i++) {
            txOutside.add(createNoopMemoIx());
        }
        txOutside.add(resolveOutside);

        let threw = false;
        try {
            await provider.sendAndConfirm(txOutside, [], { skipPreflight: true });
        } catch {
            threw = true;
        }
        assert.equal(threw, true, "signature outside scan window should fail");

        const marketOutsideAcc = await program.account.market.fetch(marketOutside);
        assert.equal(marketOutsideAcc.status.resolved !== undefined, false);
    });

    it("rejects stale signatures after notary config version bump and accepts fresh signatures", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const notaryConfig = deriveNotaryConfig(admin.publicKey);

        const existing = await provider.connection.getAccountInfo(notaryConfig);
        if (existing) {
            await program.methods
                .updateNotaryConfig(2, [notary1.publicKey, notary2.publicKey])
                .accounts({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
                })
                .signers([admin])
                .rpc();
        } else {
            await program.methods
                .initializeNotaryConfig(2, [notary1.publicKey, notary2.publicKey])
                .accounts({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
                })
                .signers([admin])
                .rpc();
        }
        const cfgBefore = await program.account.notaryConfig.fetch(notaryConfig);
        const notaryVersionBefore = new BN(cfgBefore.version.toString());

        const quoteMint = await createMint(
            provider.connection,
            admin,
            admin.publicKey,
            null,
            6
        );

        const now = await getChainTime();
        const openTs = new BN(now - 60);
        const lockTs = new BN(now - 20);
        const resolveTs = new BN(now - 1);
        const resolverHash = Buffer.alloc(32, 55);
        const market = deriveMarket(resolverHash, openTs);
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
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

        const outcomeIdx = 1;
        const proofHash = Buffer.alloc(32, 61);
        const publicInputsHash = Buffer.alloc(32, 62);
        const msgBefore = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            market.toBuffer(),
            notaryConfig.toBuffer(),
            resolverHash,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersionBefore.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);

        const staleSig1 = Buffer.from(nacl.sign.detached(msgBefore, notary1.secretKey));
        const staleSig2 = Buffer.from(nacl.sign.detached(msgBefore, notary2.secretKey));

        await program.methods
            .updateNotaryConfig(2, [notary1.publicKey, notary2.publicKey])
            .accounts({
                notaryConfig,
                admin: admin.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .signers([admin])
            .rpc();
        const cfgAfter = await program.account.notaryConfig.fetch(notaryConfig);
        const notaryVersionAfter = new BN(cfgAfter.version.toString());
        assert.equal(
            notaryVersionAfter.gt(notaryVersionBefore),
            true,
            "notary config version must bump on update"
        );

        const msgAfter = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            market.toBuffer(),
            notaryConfig.toBuffer(),
            resolverHash,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersionAfter.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);

        const resolveIx = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accounts({
                market,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        {
            const ed1 = createManualEd25519Ix(msgBefore, staleSig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(msgBefore, staleSig2, notary2.publicKey.toBuffer());
            const staleTx = new Transaction().add(ed1, ed2, resolveIx);

            let threw = false;
            try {
                await provider.sendAndConfirm(staleTx, [], { skipPreflight: true });
            } catch {
                threw = true;
            }
            assert.equal(threw, true, "stale signatures from prior notary config version should fail");
        }

        {
            const freshSig1 = Buffer.from(nacl.sign.detached(msgAfter, notary1.secretKey));
            const freshSig2 = Buffer.from(nacl.sign.detached(msgAfter, notary2.secretKey));
            const ed1 = createManualEd25519Ix(msgAfter, freshSig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(msgAfter, freshSig2, notary2.publicKey.toBuffer());
            const freshTx = new Transaction().add(ed1, ed2, resolveIx);

            await provider.sendAndConfirm(freshTx, [], { skipPreflight: true });
            const marketAcc = await program.account.market.fetch(market);
            assert.equal(marketAcc.status.resolved !== undefined, true);
            assert.equal(marketAcc.outcome.yes !== undefined, true);
        }
    });
});
