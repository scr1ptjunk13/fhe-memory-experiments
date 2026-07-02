# BACKLOG — pull the top item each morning. New ideas go to the BOTTOM.

1. `write()`: linear scan — `arr[j] = if_then_else(eq(enc_idx, j), enc_val, arr[j])` + oracle test asserting written slot updated AND untouched slots byte-equal (`mission/days/day-2.md` has the full spec)
2. Hamming, *You and Your Research* → `notes/hamming.md` — 1 page, what applies to me
3. Criterion harness: bench read+write at N ∈ {8,16,32,64,128,256,1024} → CSV committed
4. PROBONITE §1–2 → `notes/probonite.md` — what's the test polynomial; what does blind-rotate rotate by; why is write Θ(N)
5. Plot script (CSV → png), commit plot; honest README paragraph
6. RevoLUT §1–3 → `notes/revolut.md` — API surface (LUT, blind_read, blind_write); true cost of blind_write per call
7. Devlog #1: "Building encrypted RAM for TFHE, in public" (~300 words + oracle-test snippet) → blog + X; intro post in FHE.org Discord + Zama forum
8. Hamlin–Holmgren–Weiss–Wichs §1–3, slow → `notes/hamlin.md` — the rewinding obstacle in my own words
9. `notes/glossary.md` — 12 terms: LWE, RLWE, torus, PBS, blind rotate, sample extract, noise budget, levels, keyswitch, LUT, re-randomization, rewinding obstacle
10. `notes/leakage-question.md` v0 (1–2 pp): what does a k-rewind evaluator learn; why standard ORAM breaks
11. Onion-Ring ORAM §1–3 — skim, half-page note
12. Clone RevoLUT, run examples, scratch test with their `LUT` type
13. Blank-paper self-test; fix what broke; tag `v0.1`; write `week-02.md` (BAA backend + scan-vs-BAA crossover)

---
## Ideas parking lot (Sunday review only — never promoted mid-week)
