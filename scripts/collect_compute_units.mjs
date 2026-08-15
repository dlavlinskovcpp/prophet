#!/usr/bin/env node

const rpcUrl = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
const programId = process.argv[2];

if (!programId) {
  throw new Error("usage: collect_compute_units.mjs <program-id>");
}

let rpcId = 0;
async function rpc(method, params) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  const payload = await response.json();
  if (payload.error) {
    throw new Error(`${method}: ${JSON.stringify(payload.error)}`);
  }
  return payload.result;
}

function snakeCase(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function programMeasurement(transaction) {
  if (transaction?.meta?.err || !transaction.meta.logMessages) return null;

  let instruction = null;
  let activeDepth = null;
  for (const line of transaction.meta.logMessages) {
    const invoke = line.match(/^Program (\S+) invoke \[(\d+)\]$/);
    if (invoke?.[1] === programId) {
      activeDepth = Number(invoke[2]);
      instruction = null;
      continue;
    }

    if (activeDepth !== null) {
      const anchorInstruction = line.match(/^Program log: Instruction: (\S+)$/);
      if (anchorInstruction && instruction === null) {
        instruction = snakeCase(anchorInstruction[1]);
        continue;
      }

      const consumed = line.match(
        new RegExp(`^Program ${programId} consumed (\\d+) of (\\d+) compute units$`)
      );
      if (consumed) {
        return {
          instruction,
          program_compute_units: Number(consumed[1]),
          transaction_compute_units: transaction.meta.computeUnitsConsumed ?? null,
        };
      }
    }
  }
  return null;
}

const signatures = await rpc("getSignaturesForAddress", [programId, { limit: 1000 }]);
const samples = [];
for (const entry of signatures) {
  const transaction = await rpc("getTransaction", [entry.signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
    encoding: "json",
  }]);
  const measurement = programMeasurement(transaction);
  if (measurement?.instruction) {
    samples.push({ signature: entry.signature, ...measurement });
  }
}

const grouped = samples.reduce((result, sample) => {
  (result[sample.instruction] ??= []).push(sample);
  return result;
}, {});
const summary = Object.fromEntries(
  Object.entries(grouped)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([instruction, values]) => {
      const units = values.map((value) => value.program_compute_units).sort((a, b) => a - b);
      return [instruction, {
        samples: units.length,
        min: units[0],
        median: units[Math.floor(units.length / 2)],
        max: units.at(-1),
        all: units,
      }];
    })
);

process.stdout.write(`${JSON.stringify({ program_id: programId, summary }, null, 2)}\n`);
