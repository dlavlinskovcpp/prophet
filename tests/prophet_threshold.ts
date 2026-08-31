// tests/prophet_threshold.ts
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
    getAssociatedTokenAddress,
    getOrCreateAssociatedTokenAccount,
    mintTo,
    getAccount,
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
    // Keep this aligned with programs/prophet/src/state.rs::MAX_ED25519_SCAN.
    const SCAN_WINDOW = 16;

    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.Prophet as Program<Prophet>;

    const authority = provider.wallet;

    const deriveNotaryConfigSnapshot = (admin: PublicKey, version: BN) => {
        const seeds = [Buffer.from("notary_config"), admin.toBuffer()];
        if (version.eqn(1)) {
            return PublicKey.findProgramAddressSync(seeds, program.programId)[0];
        }
        return PublicKey.findProgramAddressSync(
            [...seeds, version.toArrayLike(Buffer, "le", 8)],
            program.programId
        )[0];
    };

    const deriveNotaryConfig = (admin: PublicKey) =>
        deriveNotaryConfigSnapshot(admin, new BN(1));

    const deriveMarket = (creator: PublicKey, resolver: Buffer, openTs: BN, marketNonce: BN) => {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("market"), creator.toBuffer(), resolver, openTs.toArrayLike(Buffer, "le", 8), marketNonce.toArrayLike(Buffer, "le", 8)],
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

    const getChainTime = async (): Promise<number> => {
        const slot = await provider.connection.getSlot();
        const t = await provider.connection.getBlockTime(slot);
        if (t === null) throw new Error("No block time");
        return t;
    };

    const getSafeChainNow = async (timeoutMs = 15000): Promise<number> => {
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            const slot = await provider.connection.getSlot();
            const t = await provider.connection.getBlockTime(slot);
            if (t !== null) return t;
            await new Promise((r) => setTimeout(r, 500));
        }
        throw new Error("Timeout waiting for valid chain time");
    };

    const clockPacer = Keypair.generate().publicKey;

    const ensureClockPacerFunded = async () => {
        if ((await provider.connection.getBalance(clockPacer)) >= 1_000_000) return;
        const sig = await provider.connection.requestAirdrop(clockPacer, 2_000_000);
        await provider.connection.confirmTransaction(sig, "confirmed");
    };

    const waitUntilChainTimeGE = async (target: number, timeoutMs = 45000) => {
        await ensureClockPacerFunded();
        const start = Date.now();
        while (Date.now() - start < timeoutMs) {
            const slot = await provider.connection.getSlot();
            const t = await provider.connection.getBlockTime(slot);
            if (t !== null && t >= target) return;
            await provider.sendAndConfirm(
                new Transaction().add(
                    SystemProgram.transfer({
                        fromPubkey: provider.wallet.publicKey,
                        toPubkey: clockPacer,
                        lamports: 1,
                    })
                )
            );
            await new Promise((r) => setTimeout(r, 250));
        }
        throw new Error(`Timeout waiting for chain time >= ${target}`);
    };

    const airdrop = async (pk: PublicKey, lamports: number) => {
        const sig = await provider.connection.requestAirdrop(pk, lamports);
        await provider.connection.confirmTransaction(sig, "confirmed");
    };

    const createNotaryConfig = async (threshold: number, notaryKeys: PublicKey[]) => {
        const configAdmin = Keypair.generate();
        await airdrop(configAdmin.publicKey, 2e9);
        const notaryConfig = deriveNotaryConfig(configAdmin.publicKey);

        await program.methods
            .initializeNotaryConfig(threshold, notaryKeys)
            .accountsPartial({
                notaryConfig,
                admin: configAdmin.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .signers([configAdmin])
            .rpc();

        const config = await program.account.notaryConfig.fetch(notaryConfig);
        return {
            configAdmin,
            notaryConfig,
            version: new BN(config.version.toString()),
        };
    };

    const fetchOrderOrNull = async (order: PublicKey): Promise<any | null> => {
        try {
            return await program.account.order.fetch(order);
        } catch {
            return null;
        }
    };

    const assertMirror = (yesTotal: BN, noTotal: BN) => {
        assert.isTrue(
            yesTotal.eq(noTotal),
            `Mirror invariant failed: YES=${yesTotal.toString()} NO=${noTotal.toString()}`
        );
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

        assertMirror(sumYes, sumNo);

        const openInterest = BigInt(sumYes.toString());
        const expected = sumOrderEscrow + sumRefunds + openInterest;

        assert.equal(
            vaultBal,
            expected,
            `Vault Eq Failed: Act=${vaultBal} Exp=${expected} (Escrow=${sumOrderEscrow}, Ref=${sumRefunds}, OI=${openInterest})`
        );
    };

    it("success with exactly t sigs; fails with t-1 and duplicates and wrong message and notary not allowed", async () => {
        // --- Setup: notaries + config ---
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const outsider = Keypair.generate();

        const threshold = 2;

        const { notaryConfig, version: notaryVersion } = await createNotaryConfig(
            threshold,
            [notary1.publicKey, notary2.publicKey]
        );

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

        const market = deriveMarket(admin.publicKey, resolverHash, openTs, new BN(resolverHash[0]));
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
                openTs,
                new BN(resolverHash[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market,
                creator: admin.publicKey,
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
                .accountsPartial({
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
        const market2 = deriveMarket(admin.publicKey, Buffer.alloc(32, 8), openTs, new BN(8));
        const resolverHash2 = Buffer.alloc(32, 8);
        const quoteVault2 = await getAssociatedTokenAddress(quoteMint, market2, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash2),
                openTs,
                new BN(resolverHash2[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market: market2,
                creator: admin.publicKey,
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
                .accountsPartial({
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

        // --- Case 6: zero cryptographic evidence hashes are rejected ---
        const assertZeroEvidenceRejected = async (badProofHash: Buffer, badPublicInputsHash: Buffer) => {
            const badMsg = Buffer.concat([
                Buffer.from("PROPHET_RESOLVE_V2"),
                program.programId.toBuffer(),
                market2.toBuffer(),
                notaryConfig.toBuffer(),
                resolverHash2,
                openTs.toArrayLike(Buffer, "le", 8),
                resolveTs.toArrayLike(Buffer, "le", 8),
                notaryVersion.toArrayLike(Buffer, "le", 8),
                Buffer.from([outcomeIdx]),
                badProofHash,
                badPublicInputsHash,
            ]);
            const sig1 = Buffer.from(nacl.sign.detached(badMsg, notary1.secretKey));
            const sig2 = Buffer.from(nacl.sign.detached(badMsg, notary2.secretKey));
            const ed1 = createManualEd25519Ix(badMsg, sig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(badMsg, sig2, notary2.publicKey.toBuffer());
            const resolveIx = await program.methods
                .resolveMarketThreshold({ yes: {} } as any, Array.from(badProofHash), Array.from(badPublicInputsHash))
                .accountsPartial({
                    market: market2,
                    notaryConfig,
                    instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
                })
                .instruction();
            let threw = false;
            try {
                await provider.sendAndConfirm(new Transaction().add(ed1, ed2, resolveIx), [], {
                    skipPreflight: true,
                });
            } catch {
                threw = true;
            }
            assert.equal(threw, true, "expected zero settlement evidence hash to fail");
        };
        await assertZeroEvidenceRejected(Buffer.alloc(32), publicInputsHash);
        await assertZeroEvidenceRejected(proofHash, Buffer.alloc(32));
        await assertZeroEvidenceRejected(Buffer.alloc(32), Buffer.alloc(32));
    });

    it("enforces bounded ed25519 scan window for threshold resolution", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const { notaryConfig, version: notaryVersion } = await createNotaryConfig(
            2,
            [notary1.publicKey, notary2.publicKey]
        );

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
        const marketInside = deriveMarket(admin.publicKey, resolverInside, openTs, new BN(resolverInside[0]));
        const quoteVaultInside = await getAssociatedTokenAddress(quoteMint, marketInside, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverInside),
                openTs,
                new BN(resolverInside[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market: marketInside,
                creator: admin.publicKey,
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
        const sigInside2 = Buffer.from(nacl.sign.detached(msgInside, notary2.secretKey));
        const edInside = createManualEd25519Ix(msgInside, sigInside, notary1.publicKey.toBuffer());
        const edInside2 = createManualEd25519Ix(msgInside, sigInside2, notary2.publicKey.toBuffer());
        const resolveInside = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market: marketInside,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        const txInside = new Transaction().add(edInside, edInside2);
        for (let i = 0; i < SCAN_WINDOW - 2; i++) {
            txInside.add(createNoopMemoIx());
        }
        txInside.add(resolveInside);
        await provider.sendAndConfirm(txInside, [], { skipPreflight: true });

        const marketInsideAcc = await program.account.market.fetch(marketInside);
        assert.equal(marketInsideAcc.status.resolved !== undefined, true, "signature inside scan window must resolve");

        const resolverOutside = Buffer.alloc(32, 42);
        const marketOutside = deriveMarket(admin.publicKey, resolverOutside, openTs, new BN(resolverOutside[0]));
        const quoteVaultOutside = await getAssociatedTokenAddress(quoteMint, marketOutside, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverOutside),
                openTs,
                new BN(resolverOutside[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market: marketOutside,
                creator: admin.publicKey,
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
        const sigOutside2 = Buffer.from(nacl.sign.detached(msgOutside, notary2.secretKey));
        const edOutside = createManualEd25519Ix(msgOutside, sigOutside, notary1.publicKey.toBuffer());
        const edOutside2 = createManualEd25519Ix(msgOutside, sigOutside2, notary2.publicKey.toBuffer());
        const resolveOutside = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market: marketOutside,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        const txOutside = new Transaction().add(edOutside, edOutside2);
        for (let i = 0; i < SCAN_WINDOW; i++) {
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

    it("keeps v1 immutable across v2 rotation and resolves each market with its pinned snapshot", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const rotatedNotary1 = Keypair.generate();
        const rotatedNotary2 = Keypair.generate();
        const {
            configAdmin,
            notaryConfig,
            version: notaryVersionBefore,
        } = await createNotaryConfig(2, [notary1.publicKey, notary2.publicKey]);
        assert.equal(notaryVersionBefore.toNumber(), 1);

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
        const market = deriveMarket(admin.publicKey, resolverHash, openTs, new BN(resolverHash[0]));
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
                openTs,
                new BN(resolverHash[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market,
                creator: admin.publicKey,
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

        let mutationRejected = false;
        try {
            await program.methods
                .updateNotaryConfig(2, [rotatedNotary1.publicKey, rotatedNotary2.publicKey])
                .accountsPartial({
                    notaryConfig,
                    admin: configAdmin.publicKey,
                })
                .signers([configAdmin])
                .rpc();
        } catch {
            mutationRejected = true;
        }
        assert.equal(mutationRejected, true, "historical notary snapshot mutation must fail closed");

        const cfgV1After = await program.account.notaryConfig.fetch(notaryConfig);
        assert.equal(cfgV1After.version.toNumber(), 1);
        assert.equal(cfgV1After.threshold, 2);
        assert.equal(cfgV1After.notaryKeys[0].toBase58(), notary1.publicKey.toBase58());
        assert.equal(cfgV1After.notaryKeys[1].toBase58(), notary2.publicKey.toBase58());

        const notaryVersionAfter = new BN(2);
        const notaryConfigV2 = deriveNotaryConfigSnapshot(configAdmin.publicKey, notaryVersionAfter);
        await (program.methods as any)
            .rotateNotaryConfig(
                notaryVersionAfter,
                2,
                [rotatedNotary1.publicKey, rotatedNotary2.publicKey]
            )
            .accountsPartial({
                previousNotaryConfig: notaryConfig,
                newNotaryConfig: notaryConfigV2,
                admin: configAdmin.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .signers([configAdmin])
            .rpc();

        const cfgV2 = await program.account.notaryConfig.fetch(notaryConfigV2);
        assert.equal(cfgV2.version.toNumber(), 2);
        assert.equal(cfgV2.threshold, 2);
        assert.equal(cfgV2.notaryKeys[0].toBase58(), rotatedNotary1.publicKey.toBase58());
        assert.equal(cfgV2.notaryKeys[1].toBase58(), rotatedNotary2.publicKey.toBase58());

        const resolveV1Ix = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();
        {
            const ed1 = createManualEd25519Ix(msgBefore, staleSig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(msgBefore, staleSig2, notary2.publicKey.toBuffer());
            await provider.sendAndConfirm(
                new Transaction().add(ed1, ed2, resolveV1Ix),
                [],
                { skipPreflight: true }
            );
            const marketV1Acc = await program.account.market.fetch(market);
            assert.equal(marketV1Acc.status.resolved !== undefined, true);
            assert.equal(marketV1Acc.outcome.yes !== undefined, true);
        }

        const resolverHashV2 = Buffer.alloc(32, 56);
        const marketV2 = deriveMarket(admin.publicKey, resolverHashV2, openTs, new BN(resolverHashV2[0]));
        const quoteVaultV2 = await getAssociatedTokenAddress(quoteMint, marketV2, true);
        await program.methods
            .initializeMarketV2(
                Array.from(resolverHashV2),
                openTs,
                new BN(resolverHashV2[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market: marketV2,
                creator: admin.publicKey,
                oracleAuthority: admin.publicKey,
                quoteMint,
                quoteVault: quoteVaultV2,
                notaryConfig: notaryConfigV2,
                systemProgram: SystemProgram.programId,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
            })
            .signers([admin])
            .rpc();

        const staleMessageForV2 = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            marketV2.toBuffer(),
            notaryConfig.toBuffer(),
            resolverHashV2,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersionBefore.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);
        const staleV2Sig1 = Buffer.from(nacl.sign.detached(staleMessageForV2, notary1.secretKey));
        const staleV2Sig2 = Buffer.from(nacl.sign.detached(staleMessageForV2, notary2.secretKey));

        const msgAfter = Buffer.concat([
            Buffer.from("PROPHET_RESOLVE_V2"),
            program.programId.toBuffer(),
            marketV2.toBuffer(),
            notaryConfigV2.toBuffer(),
            resolverHashV2,
            openTs.toArrayLike(Buffer, "le", 8),
            resolveTs.toArrayLike(Buffer, "le", 8),
            notaryVersionAfter.toArrayLike(Buffer, "le", 8),
            Buffer.from([outcomeIdx]),
            proofHash,
            publicInputsHash,
        ]);

        const resolveIx = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market: marketV2,
                notaryConfig: notaryConfigV2,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        {
            const ed1 = createManualEd25519Ix(staleMessageForV2, staleV2Sig1, notary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(staleMessageForV2, staleV2Sig2, notary2.publicKey.toBuffer());
            const staleTx = new Transaction().add(ed1, ed2, resolveIx);

            let threw = false;
            try {
                await provider.sendAndConfirm(staleTx, [], { skipPreflight: true });
            } catch {
                threw = true;
            }
            assert.equal(threw, true, "v1 snapshot bytes must not authorize a market pinned to v2");
            const unresolved = await program.account.market.fetch(marketV2);
            assert.equal(unresolved.status.resolved !== undefined, false);
        }

        {
            const freshSig1 = Buffer.from(nacl.sign.detached(msgAfter, rotatedNotary1.secretKey));
            const freshSig2 = Buffer.from(nacl.sign.detached(msgAfter, rotatedNotary2.secretKey));
            const ed1 = createManualEd25519Ix(msgAfter, freshSig1, rotatedNotary1.publicKey.toBuffer());
            const ed2 = createManualEd25519Ix(msgAfter, freshSig2, rotatedNotary2.publicKey.toBuffer());
            const freshTx = new Transaction().add(ed1, ed2, resolveIx);

            await provider.sendAndConfirm(freshTx, [], { skipPreflight: true });
            const marketAcc = await program.account.market.fetch(marketV2);
            assert.equal(marketAcc.status.resolved !== undefined, true);
            assert.equal(marketAcc.outcome.yes !== undefined, true);
        }
    });

    it("E2E: Place -> Match (Partial) -> Cancel -> Claim -> Resolve Threshold -> Redeem", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const traderA = Keypair.generate();
        const traderB = Keypair.generate();

        await airdrop(traderA.publicKey, 2e9);
        await airdrop(traderB.publicKey, 2e9);

        const { notaryConfig, version: notaryVersion } = await createNotaryConfig(
            2,
            [notary1.publicKey, notary2.publicKey]
        );

        const quoteMint = await createMint(
            provider.connection,
            admin,
            admin.publicKey,
            null,
            6
        );
        const ataA = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            admin,
            quoteMint,
            traderA.publicKey
        );
        const ataB = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            admin,
            quoteMint,
            traderB.publicKey
        );
        await mintTo(provider.connection, admin, quoteMint, ataA.address, admin.publicKey, 1_000_000);
        await mintTo(provider.connection, admin, quoteMint, ataB.address, admin.publicKey, 1_000_000);

        const safeNow = await getSafeChainNow();
        const resolverHash = Buffer.alloc(32, 71);
        const openTs = new BN(safeNow - 100);
        const lockTs = new BN(safeNow + 15);
        const resolveTs = new BN(safeNow + 15);

        const market = deriveMarket(admin.publicKey, resolverHash, openTs, new BN(resolverHash[0]));
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
                openTs,
                new BN(resolverHash[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market,
                creator: admin.publicKey,
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

        const seqA = new BN(0);
        const seqB = new BN(1);
        const orderA = deriveOrder(market, traderA.publicKey, seqA);
        const orderB = deriveOrder(market, traderB.publicKey, seqB);
        const posA = derivePosition(market, traderA.publicKey);
        const posB = derivePosition(market, traderB.publicKey);

        await program.methods
            .placeOrder(seqA, { buyYes: {} }, 60_000_000, new BN(100))
            .accountsPartial({
                market,
                order: orderA,
                position: posA,
                owner: traderA.publicKey,
                ownerQuoteAta: ataA.address,
                quoteVault,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
            })
            .signers([traderA])
            .rpc();

        await program.methods
            .placeOrder(seqB, { buyNo: {} }, 60_000_000, new BN(50))
            .accountsPartial({
                market,
                order: orderB,
                position: posB,
                owner: traderB.publicKey,
                ownerQuoteAta: ataB.address,
                quoteVault,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
            })
            .signers([traderB])
            .rpc();

        await program.methods
            .matchOrders(new BN(20))
            .accountsPartial({
                market,
                orderYes: orderA,
                orderNo: orderB,
                positionYes: posA,
                positionNo: posB,
                ownerYes: traderA.publicKey,
                ownerNo: traderB.publicKey,
                marketQuoteVault: quoteVault,
            })
            .rpc();

        {
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);
            const oA = await program.account.order.fetch(orderA);
            const oB = await program.account.order.fetch(orderB);

            assert.equal(pA.yesSharesAtoms.toNumber(), 20);
            assert.equal(pB.noSharesAtoms.toNumber(), 20);
            assert.equal(oA.qtyRemainingAtoms.toNumber(), 80);
            assert.equal(oA.escrowRemainingAtoms.toNumber(), 48);
            assert.equal(oB.qtyRemainingAtoms.toNumber(), 30);
            assert.equal(oB.escrowRemainingAtoms.toNumber(), 12);
            assert.equal(pA.pendingRefundsAtoms.toNumber(), 0);
            assert.equal(pB.pendingRefundsAtoms.toNumber(), 0);

            await assertVaultEquation(quoteVault, [pA, pB], [oA, oB]);
        }

        await program.methods
            .cancelOrder()
            .accountsPartial({
                market,
                order: orderA,
                position: posA,
                owner: traderA.publicKey,
            })
            .signers([traderA])
            .rpc();

        await program.methods
            .cancelOrder()
            .accountsPartial({
                market,
                order: orderB,
                position: posB,
                owner: traderB.publicKey,
            })
            .signers([traderB])
            .rpc();

        {
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);
            const oA = await fetchOrderOrNull(orderA);
            const oB = await fetchOrderOrNull(orderB);

            assert.equal(oA, null);
            assert.equal(oB, null);
            assert.equal(pA.pendingRefundsAtoms.toNumber(), 48);
            assert.equal(pB.pendingRefundsAtoms.toNumber(), 12);

            await assertVaultEquation(quoteVault, [pA, pB], []);
        }

        const balAClaimPre = (await getAccount(provider.connection, ataA.address)).amount;
        const balBClaimPre = (await getAccount(provider.connection, ataB.address)).amount;

        await program.methods
            .claimRefunds(new BN(48))
            .accountsPartial({
                market,
                position: posA,
                owner: traderA.publicKey,
                quoteVault,
                ownerQuoteAta: ataA.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderA])
            .rpc();

        await program.methods
            .claimRefunds(new BN(12))
            .accountsPartial({
                market,
                position: posB,
                owner: traderB.publicKey,
                quoteVault,
                ownerQuoteAta: ataB.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderB])
            .rpc();

        {
            const balAClaimPost = (await getAccount(provider.connection, ataA.address)).amount;
            const balBClaimPost = (await getAccount(provider.connection, ataB.address)).amount;
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);

            assert.equal(Number(balAClaimPost) - Number(balAClaimPre), 48);
            assert.equal(Number(balBClaimPost) - Number(balBClaimPre), 12);
            assert.equal(pA.pendingRefundsAtoms.toNumber(), 0);
            assert.equal(pB.pendingRefundsAtoms.toNumber(), 0);

            await assertVaultEquation(quoteVault, [pA, pB], []);
        }

        await waitUntilChainTimeGE(resolveTs.toNumber());

        const outcomeIdx = 1;
        const proofHash = Buffer.alloc(32, 72);
        const publicInputsHash = Buffer.alloc(32, 73);
        const resolveMsg = Buffer.concat([
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

        const sig1 = Buffer.from(nacl.sign.detached(resolveMsg, notary1.secretKey));
        const sig2 = Buffer.from(nacl.sign.detached(resolveMsg, notary2.secretKey));
        const ed1 = createManualEd25519Ix(resolveMsg, sig1, notary1.publicKey.toBuffer());
        const ed2 = createManualEd25519Ix(resolveMsg, sig2, notary2.publicKey.toBuffer());
        const resolveIx = await program.methods
            .resolveMarketThreshold({ yes: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        await provider.sendAndConfirm(new Transaction().add(ed1, ed2, resolveIx), [], {
            skipPreflight: true,
        });

        const marketAcc = await program.account.market.fetch(market);
        assert.equal(marketAcc.status.resolved !== undefined, true);
        assert.equal(marketAcc.outcome.yes !== undefined, true);
        assert.deepEqual(marketAcc.proofHash, Array.from(proofHash));

        const balARedeemPre = (await getAccount(provider.connection, ataA.address)).amount;
        await program.methods
            .redeem()
            .accountsPartial({
                market,
                position: posA,
                owner: traderA.publicKey,
                quoteVault,
                ownerQuoteAta: ataA.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderA])
            .rpc();
        const balARedeemPost = (await getAccount(provider.connection, ataA.address)).amount;
        assert.equal(Number(balARedeemPost) - Number(balARedeemPre), 20);

        let repeatedRedeemThrew = false;
        try {
            await program.methods
                .redeem()
                .accountsPartial({
                    market,
                    position: posA,
                    owner: traderA.publicKey,
                    quoteVault,
                    ownerQuoteAta: ataA.address,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([traderA])
                .rpc();
        } catch {
            repeatedRedeemThrew = true;
        }
        assert.equal(repeatedRedeemThrew, true, "expected repeated redeem to fail");

        const balBRedeemPre = (await getAccount(provider.connection, ataB.address)).amount;
        await program.methods
            .redeem()
            .accountsPartial({
                market,
                position: posB,
                owner: traderB.publicKey,
                quoteVault,
                ownerQuoteAta: ataB.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderB])
            .rpc();
        const balBRedeemPost = (await getAccount(provider.connection, ataB.address)).amount;
        assert.equal(Number(balBRedeemPost) - Number(balBRedeemPre), 0);

        {
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);

            assert.equal(pA.yesSharesAtoms.toNumber(), 0);
            assert.equal(pB.noSharesAtoms.toNumber(), 0);

            await assertVaultEquation(quoteVault, [pA, pB], []);
        }
    });

    it("E2E: Resolve Threshold Invalid -> split redemption evenly", async () => {
        const admin = (provider.wallet as anchor.Wallet).payer;
        const notary1 = Keypair.generate();
        const notary2 = Keypair.generate();
        const traderA = Keypair.generate();
        const traderB = Keypair.generate();
        const notaryConfig = deriveNotaryConfig(admin.publicKey);

        await airdrop(traderA.publicKey, 2e9);
        await airdrop(traderB.publicKey, 2e9);

        const existing = await provider.connection.getAccountInfo(notaryConfig);
        if (existing) {
            await program.methods
                .updateNotaryConfig(2, [notary1.publicKey, notary2.publicKey])
                .accountsPartial({
                    notaryConfig,
                    admin: admin.publicKey,
                })
                .signers([admin])
                .rpc();
        } else {
            await program.methods
                .initializeNotaryConfig(2, [notary1.publicKey, notary2.publicKey])
                .accountsPartial({
                    notaryConfig,
                    admin: admin.publicKey,
                    systemProgram: SystemProgram.programId,
                })
                .signers([admin])
                .rpc();
        }
        const cfg = await program.account.notaryConfig.fetch(notaryConfig);
        const notaryVersion = new BN(cfg.version.toString());

        const quoteMint = await createMint(
            provider.connection,
            admin,
            admin.publicKey,
            null,
            6
        );
        const ataA = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            admin,
            quoteMint,
            traderA.publicKey
        );
        const ataB = await getOrCreateAssociatedTokenAccount(
            provider.connection,
            admin,
            quoteMint,
            traderB.publicKey
        );
        await mintTo(provider.connection, admin, quoteMint, ataA.address, admin.publicKey, 1_000_000);
        await mintTo(provider.connection, admin, quoteMint, ataB.address, admin.publicKey, 1_000_000);

        const safeNow = await getSafeChainNow();
        const resolverHash = Buffer.alloc(32, 74);
        const openTs = new BN(safeNow - 100);
        const lockTs = new BN(safeNow + 8);
        const resolveTs = new BN(safeNow + 8);

        const market = deriveMarket(admin.publicKey, resolverHash, openTs, new BN(resolverHash[0]));
        const quoteVault = await getAssociatedTokenAddress(quoteMint, market, true);

        await program.methods
            .initializeMarketV2(
                Array.from(resolverHash),
                openTs,
                new BN(resolverHash[0]),
                lockTs,
                resolveTs,
                new BN(1),
                new BN(1),
                32,
                4096
            )
            .accountsPartial({
                market,
                creator: admin.publicKey,
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

        const seqA = new BN(0);
        const seqB = new BN(1);
        const orderA = deriveOrder(market, traderA.publicKey, seqA);
        const orderB = deriveOrder(market, traderB.publicKey, seqB);
        const posA = derivePosition(market, traderA.publicKey);
        const posB = derivePosition(market, traderB.publicKey);

        await program.methods
            .placeOrder(seqA, { buyYes: {} }, 60_000_000, new BN(20))
            .accountsPartial({
                market,
                order: orderA,
                position: posA,
                owner: traderA.publicKey,
                ownerQuoteAta: ataA.address,
                quoteVault,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
            })
            .signers([traderA])
            .rpc();

        await program.methods
            .placeOrder(seqB, { buyNo: {} }, 60_000_000, new BN(20))
            .accountsPartial({
                market,
                order: orderB,
                position: posB,
                owner: traderB.publicKey,
                ownerQuoteAta: ataB.address,
                quoteVault,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
            })
            .signers([traderB])
            .rpc();

        await program.methods
            .matchOrders(new BN(20))
            .accountsPartial({
                market,
                orderYes: orderA,
                orderNo: orderB,
                positionYes: posA,
                positionNo: posB,
                ownerYes: traderA.publicKey,
                ownerNo: traderB.publicKey,
                marketQuoteVault: quoteVault,
            })
            .rpc();

        {
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);
            const oA = await fetchOrderOrNull(orderA);
            const oB = await fetchOrderOrNull(orderB);

            assert.equal(pA.yesSharesAtoms.toNumber(), 20);
            assert.equal(pA.noSharesAtoms.toNumber(), 0);
            assert.equal(pB.yesSharesAtoms.toNumber(), 0);
            assert.equal(pB.noSharesAtoms.toNumber(), 20);
            assert.equal(oA, null);
            assert.equal(oB, null);

            await assertVaultEquation(quoteVault, [pA, pB], []);
        }

        await waitUntilChainTimeGE(resolveTs.toNumber());

        const outcomeIdx = 3;
        const proofHash = Buffer.alloc(32, 75);
        const publicInputsHash = Buffer.alloc(32, 76);
        const resolveMsg = Buffer.concat([
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

        const sig1 = Buffer.from(nacl.sign.detached(resolveMsg, notary1.secretKey));
        const sig2 = Buffer.from(nacl.sign.detached(resolveMsg, notary2.secretKey));
        const ed1 = createManualEd25519Ix(resolveMsg, sig1, notary1.publicKey.toBuffer());
        const ed2 = createManualEd25519Ix(resolveMsg, sig2, notary2.publicKey.toBuffer());
        const resolveIx = await program.methods
            .resolveMarketThreshold({ invalid: {} } as any, Array.from(proofHash), Array.from(publicInputsHash))
            .accountsPartial({
                market,
                notaryConfig,
                instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .instruction();

        await provider.sendAndConfirm(new Transaction().add(ed1, ed2, resolveIx), [], {
            skipPreflight: true,
        });

        const marketAcc = await program.account.market.fetch(market);
        assert.equal(marketAcc.status.resolved !== undefined, true);
        assert.equal(marketAcc.outcome.invalid !== undefined, true);

        const balARedeemPre = (await getAccount(provider.connection, ataA.address)).amount;
        await program.methods
            .redeem()
            .accountsPartial({
                market,
                position: posA,
                owner: traderA.publicKey,
                quoteVault,
                ownerQuoteAta: ataA.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderA])
            .rpc();
        const balARedeemPost = (await getAccount(provider.connection, ataA.address)).amount;
        assert.equal(Number(balARedeemPost) - Number(balARedeemPre), 10);

        const balBRedeemPre = (await getAccount(provider.connection, ataB.address)).amount;
        await program.methods
            .redeem()
            .accountsPartial({
                market,
                position: posB,
                owner: traderB.publicKey,
                quoteVault,
                ownerQuoteAta: ataB.address,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([traderB])
            .rpc();
        const balBRedeemPost = (await getAccount(provider.connection, ataB.address)).amount;
        assert.equal(Number(balBRedeemPost) - Number(balBRedeemPre), 10);

        {
            const pA = await program.account.position.fetch(posA);
            const pB = await program.account.position.fetch(posB);

            assert.equal(pA.yesSharesAtoms.toNumber(), 0);
            assert.equal(pB.noSharesAtoms.toNumber(), 0);

            await assertVaultEquation(quoteVault, [pA, pB], []);
        }
    });
});
