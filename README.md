# gatehouse

**The guardrail layer you would otherwise rebuild inside every customer's MCP server.**

An agent platform attaches tools per *server*. The customer's server exposes everything it has:
the refund tool next to the lookup tool, the IBAN next to the name. So the rules that matter in a
regulated deployment (bank changes go to a person, the model never reads a document number, a
retried write never runs twice) end up hand-written into each customer's tool code, or into a
prompt, where a model can talk its way past them.

gatehouse is an MCP proxy that sits between the agent and the customer's MCP server and enforces
those rules in code, from one YAML file:

| | |
|---|---|
| **Profiles** | Each gatehouse instance serves one profile. Tools outside it are not listed and cannot be called. Attaching the profile is the permission grant. |
| **Rules** | `allow`, `deny` or `handoff`, per tool, with conditions on the arguments. First match wins. A handoff returns the reason as data and tells the agent to call its human-handoff tool. |
| **Masking** | Every result is masked before the model sees it: named fields (`iban: last4`, `date_of_birth: drop`) anywhere in the tree, and PII inside free text (IBANs, Luhn-valid card numbers, emails, phone numbers). |
| **Idempotency** | A retried write with the same arguments returns the first result instead of running again. |
| **Audit** | One JSON line per call: profile, tool, masked arguments, decision, rule, latency. |
| **Shadow mode** | `mode: shadow` records what every rule would have done and blocks nothing (results are still masked), so a first rollout can be measured before it is enforced. |
| **Auth** | Checks the bearer key on every request (`MCP_API_KEY`), because the platform does not. |

The customer's tools do not change. The agent's prompt does not change.

## Where it sits

```mermaid
flowchart LR
    subgraph agent["Agent runtime (unchanged)"]
        direction TB
        P["Policies and routines<br/>decide what the agent should do"]
        R["LLM router"]
        M1["mcps: operator-read"]
        M2["mcps: operator-write"]
    end

    subgraph gh["gatehouse, one process per profile"]
        direction TB
        A["1 Bearer check<br/>MCP_API_KEY on every request"]
        F["2 Profile<br/>only granted tools are listed"]
        X["3 Rules<br/>allow, deny or handoff"]
        I["4 Idempotency<br/>a retried write returns the first result"]
        K["5 Mask<br/>fields and PII in free text"]
        L["6 Audit<br/>one JSON line per call"]
        A --> F --> X --> I
        K --> L
    end

    subgraph up["Customer's MCP server (unchanged)"]
        direction TB
        U1["Player accounts"]
        U2["Support desk"]
        U3["KYC provider"]
        U4["Payments"]
    end

    M2 -- "tools/call" --> A
    I -- "allowed call" --> up
    up -- "raw result" --> K
    L -- "masked result" --> M2
    X -. "handoff: needs_human as data,<br/>upstream untouched" .-> M2
```

A call the rules refuse never reaches the customer's systems. A call they allow comes back masked.
Every call leaves one audit line.

## One call, decided

```mermaid
flowchart TD
    C(["tools/call from the agent"]) --> K{"Bearer key valid?"}
    K -- no --> E1["401, nothing runs"]
    K -- yes --> P{"Tool in this profile?"}
    P -- no --> D1["not_allowed, rule: profile<br/>(enforced even in shadow mode)"]
    P -- yes --> R{"First matching rule"}
    R -- "deny or handoff" --> S{"mode: shadow?"}
    S -- no --> D2["return the error as data<br/>handoff names initiate_human_handoff"]
    S -- yes --> Q
    R -- "no match: allow" --> Q{"Same write seen<br/>inside the window?"}
    R -- "rule cannot read an argument" --> D3["deny, fail closed"]
    Q -- yes --> RP["return the first result, run nothing"]
    Q -- no --> UP["call the upstream tool"]
    UP --> MK["mask the result:<br/>named fields, PII in text,<br/>withhold images and files"]
    MK --> OUT(["masked result to the agent"])
    D1 & D2 & D3 & RP & OUT --> AU[("audit.jsonl<br/>masked arguments, decision, rule, ms")]
```

## A handoff, end to end

```mermaid
sequenceDiagram
    autonumber
    participant Player
    participant Agent as Agent (policies, router)
    participant Gate as gatehouse (support-write)
    participant PAM as Player accounts
    participant Human as Support person

    Player->>Agent: "Please pay my winnings to a new IBAN"
    Agent->>Gate: tools/call update_bank_account(P-1001, ES76...)
    Gate->>Gate: rule bank-account-changes-go-to-a-human matches
    Gate-->>Agent: {"error": "needs_human", "rule": "...", "next": "initiate_human_handoff"}
    Note over Gate,PAM: The player account is never called
    Agent->>Human: built-in:initiate_human_handoff(reason)
    Human->>PAM: verifies identity, changes the IBAN
    Agent->>Gate: tools/call get_player(P-1001)
    Gate->>PAM: get_player(P-1001)
    PAM-->>Gate: full record, IBAN, phone, date of birth
    Gate-->>Agent: iban ****5766, phone ****5678, date of birth dropped
```

## Two minutes, no keys

```
pip install -e .
python examples/igaming/demo.py
```

A support agent on a regulated iGaming desk (player accounts, tickets, KYC; all data fake):

```
support-read   sees 3 of 9 upstream tools: get_player, get_ticket, list_transactions
support-write  sees 8 of 9 upstream tools: add_ticket_comment, apply_bonus, close_ticket, get_player, ...

  look up the player                     get_player           -> iban ****1332, phone ****5678, email ***@example.com, dropped date_of_birth, document_number
  read a ticket with an IBAN in it       get_ticket           -> "Withdrawal of 40 EUR pending 3 days. Please send it to ****1332, or call me on ****5678."
  player asks to change the payout IBAN  update_bank_account  -> NEEDS_HUMAN  [bank-account-changes-go-to-a-human]
  10 EUR goodwill bonus                  apply_bonus          -> {"bonus_id": "B-9001", ..., "new_balance_eur": 52.5}
  model retries after a timeout          apply_bonus          -> {"bonus_id": "B-9001", ..., "new_balance_eur": 52.5}
  120 EUR bonus                          apply_bonus          -> NEEDS_HUMAN  [bonus-above-50-needs-a-supervisor]
  player asks to self-exclude            set_self_exclusion   -> NEEDS_HUMAN  [self-exclusion-goes-to-a-human]
  close with no resolution               close_ticket         -> NOT_ALLOWED  [close-only-with-a-resolution]
  a tool in no profile                   export_player_data   -> NOT_ALLOWED  [profile]

balance after two identical 10 EUR calls: 52.50 EUR (started at 42.50)
```

## The config

```yaml
upstream: http://operator-mcp:8765/mcp    # any streamable-http MCP server, or a local .py file
api_key: ${MCP_API_KEY}
audit_log: audit.jsonl

profiles:
  support-read:  { tools: [get_player, list_transactions, get_ticket] }
  support-write: { tools: [get_player, list_transactions, get_ticket, add_ticket_comment,
                           close_ticket, apply_bonus, update_bank_account, set_self_exclusion] }

mask:
  fields: { iban: last4, phone: last4, email: domain, date_of_birth: drop, document_number: drop }
  patterns: [iban, card, email, phone]

rules:
  - id: bank-account-changes-go-to-a-human
    tools: [update_bank_account]
    action: handoff
    reason: Bank account changes are always handled by a person.
  - id: bonus-above-50-needs-a-supervisor
    tools: [apply_bonus]
    when: { amount_eur: { gt: 50 } }
    action: handoff

idempotency:
  tools: [apply_bonus, add_ticket_comment, update_bank_account]
  window_seconds: 600
```

Conditions: `gt`, `gte`, `lt`, `lte`, `equals`, `in`, `matches` (regex), `missing`. The full example is
[examples/igaming/gatehouse.yaml](examples/igaming/gatehouse.yaml).

## Running it in front of a real server

```
gatehouse examples/igaming/gatehouse.yaml --profile support-write --port 8766
```

It serves streamable-http at `/mcp`. In an InteractiveAI agent manifest it is an ordinary MCP entry,
one per profile:

```yaml
agent_config:
  mcps:
    - id: operator                       # tools appear as operator:get_player
      hostname: http://gatehouse-support-write
      port: 8766
      api_key: ${GATEHOUSE_KEY}
```

Or as a platform-hosted MCP, from the included Dockerfile:

```
iai mcps create gatehouse-support-write --image-name gatehouse --image-tag v1 --port 8766
```

## Tests

```
python -m unittest discover -s tests
```

29 tests: every rule; shadow mode; masking edge cases (only Luhn-valid card numbers, amounts and ticket ids
untouched); the idempotency window; the full proxy in memory; a real streamable-http run that refuses
a call without the bearer key and still applies the rules with it; and a set of bypass regressions.

## Fails closed

A guardrail that can be argued past is a suggestion. gatehouse reads arguments the way the
upstream's validator will execute them, and refuses whatever it cannot read:

* `"true"`, `"1"`, `"yes"` are true and `"120"` is 120, so a rule never decides on a string while the
  tool runs on the coerced value.
* `NaN`, infinities and booleans in an amount are refused, not compared (`NaN > 50` is false).
* A rule that cannot evaluate an argument denies the call; whitespace counts as missing.
* `IBAN`, `iban` and `dateOfBirth` / `date_of_birth` are the same field to the masker.
* Content it cannot inspect (an image of an ID document, an embedded file) is withheld.
* It proxies tools only. Upstream resources and prompts would bypass every rule and mask, so they are
  neither listed nor readable through gatehouse.
* Shadow mode softens rules, never the profile: a tool outside the profile is refused in every mode.
* The bearer key is compared in constant time, and if the config asks for a key that resolves empty,
  gatehouse refuses to start rather than serving unauthenticated.

## Limits, honestly

* Masking is pattern- and field-based. A secret paraphrased into prose with no recognisable shape
  gets through; the field rules are the first line, a human on irreversible actions the last.
* Idempotency is an in-process dict: correct for one replica, Redis for several.
* One process per profile. Per-tool permissions inside the platform's own manifest would make that
  unnecessary, and would be the better long-term home for this.

MIT. Built by [Sri Krishna Vamsi D](https://github.com/srikrishnavansi).
