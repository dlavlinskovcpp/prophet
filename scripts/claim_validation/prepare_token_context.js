#!/usr/bin/env node
const fs = require("fs");
const { Connection, Keypair } = require("@solana/web3.js");
const { createMint, getOrCreateAssociatedTokenAccount, mintTo } = require("@solana/spl-token");

async function waitAccountVisible(connection, pubkey, label) {
  for (let i = 0; i < 50; i += 1) {
    const info = await connection.getAccountInfo(pubkey, "confirmed");
    if (info) return;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`account not visible after retries: ${label} ${pubkey.toBase58()}`);
}

async function main() {
  const rpcUrl = process.env.RPC_URL;
  const walletPath = process.env.WALLET_PATH;
  const mintedAtoms = Number(process.env.MINTED_ATOMS || "1000000");

  if (!rpcUrl) {
    throw new Error("RPC_URL is required");
  }
  if (!walletPath) {
    throw new Error("WALLET_PATH is required");
  }

  const payer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath, "utf8")))
  );
  const connection = new Connection(rpcUrl, "confirmed");
  const failRecipient = Keypair.generate();

  const quoteMint = await createMint(connection, payer, payer.publicKey, null, 6);
  const issuerAta = await getOrCreateAssociatedTokenAccount(connection, payer, quoteMint, payer.publicKey);
  const failRecipientAta = await getOrCreateAssociatedTokenAccount(
    connection,
    payer,
    quoteMint,
    failRecipient.publicKey
  );

  const airdropSig = await connection.requestAirdrop(failRecipient.publicKey, 1_000_000_000);
  await connection.confirmTransaction(airdropSig, "confirmed");

  await mintTo(connection, payer, quoteMint, issuerAta.address, payer.publicKey, mintedAtoms);

  await waitAccountVisible(connection, quoteMint, "quote_mint");
  await waitAccountVisible(connection, issuerAta.address, "issuer_ata");
  await waitAccountVisible(connection, failRecipientAta.address, "fail_recipient_ata");

  process.stdout.write(
    JSON.stringify({
      quote_mint: quoteMint.toBase58(),
      issuer_ata: issuerAta.address.toBase58(),
      fail_recipient_pubkey: failRecipient.publicKey.toBase58(),
      fail_recipient_secret_b64: Buffer.from(failRecipient.secretKey).toString("base64"),
      fail_recipient_ata: failRecipientAta.address.toBase58(),
      oracle_pubkey: payer.publicKey.toBase58(),
      minted_atoms: mintedAtoms,
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
