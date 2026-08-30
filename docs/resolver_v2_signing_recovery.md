# Resolver V2 fixed-role signing recovery

Recovery is role-local. Signer A and signer B each own a separate durable
P0C2 journal and admission replay journal; neither journal, Vault policy, or
private credential may be shared with the other role.

For a completed role-local signature, recovery reuses the durable public
signature. A `SIGNING` marker remains ambiguous after restart and becomes
`UNCERTAIN`; it is never automatically signed again. A replayed admission grant
is rejected in G2 before P0C1 and produces no new signature. Cross-role grants
are rejected in G1 before P0C1.

The retired `resume_2_of_2`/dual-token recovery workflow must not be used. The
coordinator and submitter can handle only public A/B signatures and a local
fee-payer key; they never load signer credentials. Any operator recovery must
run one fixed role at a time under that role's credential policy.
