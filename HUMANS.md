# HUMANS.md

This file is for **people**: researchers, communities, enterprises, independent
labs, creators, hosts, and anyone who wants to use BTX without becoming a
protocol engineer.

If you are an autonomous agent, stop here and read [AGENTS.md](AGENTS.md).
That file is the machine contract: plane isolation, RPC names, spend
mandates, and what never to execute. This file is how a person actually
participates.

The longer argument is
[doc/design/btx-decentralized-frontier-ai-lab.md](doc/design/btx-decentralized-frontier-ai-lab.md)
(15 September 2026 revised essay). That essay is a strategic analysis, not a
consensus spec.

## What 0.34.7 is

BTX **v0.34.7** is a **decentralized frontier AI lab without a corporate
center**.

A conventional lab organizes objectives, people, experiments, capital,
evaluations, and release from one management hierarchy. 0.34.7 performs those
coordinating functions through a common market instead of one owner:

- Many balance sheets can express demand for a capability.
- Independent teams decide whether a reward justifies their effort.
- Each bounty has its own requirements and acceptance process.
- The accepted model gets a portable identity (`btx://…`) and more than one
  distribution path.

Researchers keep their own methods and compute. Enterprises, communities, and
agents bring different objectives. They meet around a verifiable deliverable
and a credible commitment. The network’s unity is interoperable objects, not
compulsory agreement on one research agenda.

That is the institutional claim of 0.34.7. It is not “a company without an
office.” It is a market that can commission, open, and preserve intelligence
without concentrating every research decision, asset, and release channel in
one organization.

**The Agentic State**, as used in the essay, is a **strategic thesis**: a
prospective, non-territorial way of organizing economic activity around
persistent computational actors. It is **not** a claim of legal sovereignty,
not a recognized country, and not a statement that BTX is a government.

## Who participates

Participation is organized around **roles**, not a requirement to mine or to
buy coins. Ordinary free retrieval does not require buying BTX.

| Role | What you bring | What the common system gives you |
|---|---|---|
| Community | Shared needs and pooled contributions | A route from a neglected capability to a public model |
| Enterprise | Well-defined problems and purchasing power | A broader research field and comparable submissions |
| Independent lab | Expertise, experiments, and candidate models | Visible demand and compensation for accepted work |
| Individual creator | Specialist insight and productive effort | A release market without operating a hosted API business |
| Research agent | Repeatable execution and continuous market attention | Machine-readable opportunities, evidence, and settlement |
| Host or explorer | Storage, bandwidth, and discovery services | Participation in a useful model network through open interfaces |

You do not need a BTX-operated account, an email gate, or permission from a
central directory to take part. Discovery can be offered by different
explorers. Model identity survives the disappearance of a listing.

## Two markets

0.34.7 connects two moments in the life of a model. Both end in the same
place: a useful artifact that participants can discover and possess.

**Release campaigns** start with a model that already exists privately. The
creator publishes terms and an encrypted artifact. Supporters finance
disclosure. A valid claim reveals the committed key, and the model becomes a
public `btx://` resource. This is how a creator can recover value without
becoming an inference-service operator.

**Creation bounties** start with a capability that does not yet exist (or is
not yet public in the required form). Contributors fund an outcome.
Researchers submit exact candidates. Evaluators run the agreed tests and
publish evidence. Appointed decision-makers (the bounty **council**)
authorize an award under the published process. Public submission is the
default: an accepted artifact is already available for evaluation before
payment.

These are different products. A release campaign discloses a key for a
committed private file. A bounty pays for a result that meets stated
requirements. A researcher looking at a bounty may already hold a matching
private model; a community funding a release may decide a further improvement
is worth commissioning.

The economic ambition is to pay for **creation and disclosure**, not to
manufacture permanent scarcity in the *use* of a public model. Once the
result enters the commons, widespread copying is the mechanism working.

## How a person uses it

Do not start from RPC. The desktop client and the how-to docs are the human
path. Machine sequences belong in [AGENTS.md](AGENTS.md).

### 1. Run the current line

The last shipping tag is **v0.34.7**. For a validating node that becomes
useful without waiting for a full historical sync, the fast-start snapshot is
**assumeutxo-219000**.

Install and first-run: [doc/btx-download-and-go.md](doc/btx-download-and-go.md).

Using and proving the model network: [doc/modelnet/howto.md](doc/modelnet/howto.md).

This working tree is **0.34.8rc3** (`CLIENT_VERSION_IS_RELEASE=false`).
The last released client remains **v0.34.7**. Final `IS_RELEASE=true` is the operator go-ahead after this RC.
Host, seed, search, share, watch folder,
`showmodel` / `unhostmodel` / `exportmodellink`, mining `first_run` doctor
tiles, bounty `checklist` / `--validate`, and doctor:
[doc/modelnet/first-run.md](doc/modelnet/first-run.md). CLI wrapper:
[contrib/modelnet/btx-model](contrib/modelnet/btx-model)
(people: stderr hints; agents: `--json` stdout). Optional 0.34.8-dev cloud
backing, publisher follow, events, and profiles **fail closed** if the
helper lacks the method: [doc/modelnet/storage-backends.md](doc/modelnet/storage-backends.md),
[doc/modelnet/watches.md](doc/modelnet/watches.md). Filesystem `-modelwatch`
is not a publisher watch.

### Source → storage → model (0.34.8-dev; `IS_RELEASE=false`)

A person can pin a **local** file (or review an ImportPlan for Hugging Face /
torrent), choose **local disk** or an S3-compatible backend, and publish a
verified `btx://` identity. Hugging Face / torrent hashes prove **bytes**, not
original authorship. A presigned URL is reusable bearer access, not a meter.
Erasure repair is **per stripe**. Automatic spend stays **0**.

```text
btx-model doctor
btx-model host ./model.safetensors
btx-model link NAME                 # exportmodellink magnet analog
btx-model import-plan @plan.json    # staging UUID until VerifiedManifest
btx-model package create '{}'       # .btxbundle; not a secret dump
btx-model package inspect FILE.btx # preview only; does not install or spend
btx-open FILE.btx                   # local inspect; never writes AGENTS.md
```

Live Hugging Face HTTP, live R2 WAN, GUI, and wallet-signed subscriptions are
**not** claimed here. Cloud add uses `--credential-ref`, never a raw secret on
argv: [doc/modelnet/storage-backends.md](doc/modelnet/storage-backends.md).

### Hosted Control Plane / walletless discovery (0.34.8-dev; `IS_RELEASE=false`)

A person can **discover** public capabilities through a hosted catalogue without
opening a monetary wallet, mining, or completing a full chain sync. The
walletless preset is `btx-hosted`; the loopback gateway is `btx-hcpd`. Public
search is not a CEX login requirement and is not a remote-inference product.

Automatic BTX spend stays **0**. A hosted listing is not a payment instruction.
Enrolling a provider authorizes communication, not spend and not local runtime
admission. Live exchange identity, live custody HSM, and live CUDA DMA are
**not** claimed here.

**Cognitive Reserve v1.1** is a **negotiated HCP/1 extension of that same
hosted plane**, not a fifth product, not a new coin, and not remote inference.
The original **34** HCP operations stay as they are. A venue’s catalogue does
not imply reserve, committee, or programme support — those require an explicit
`GET /extensions/cognitive-reserve` profile. Automatic spend remains **0**.
This tree is still **0.34.8-dev** (`CLIENT_VERSION_IS_RELEASE=false`) and does
not replace the production GPU attestor. Operator notes:
[doc/hosted/HCP_OPERATOR_NOTES.md](doc/hosted/HCP_OPERATOR_NOTES.md). Spec:
[doc/modelnet/crf/](doc/modelnet/crf/).

Operator index: [doc/hosted/README.md](doc/hosted/README.md). Spec and CEX
guide: [doc/modelnet/hcp/](doc/modelnet/hcp/).

Bounties (inspect, fund, evaluate, recover): [doc/bounties.md](doc/bounties.md).

### 2. Open the Models page

In `btx-qt`, open **Models**. The page is a network directory, not only a
local file manager. Tabs include **Latest**, **Nearly Funded**, **Available**,
**Rare**, **Just Released**, **Local**, **Releases**, **Publishers**,
**Collections**, and **Bounties**.

Search for what a model **does** (task, language, domain), not only its
brand. Cards can be public (retrieve now), a release campaign (support
disclosure), or a bounty (inspect terms, then research or co-fund).

Peer counts and “nearly funded” figures are **this node’s observations**, not
a global census and not a command to pay.

### 3. Open a `btx://` address

The canonical share form is `btx://<resource-token>`. It names an exact
artifact (content identity), independent of whichever website or explorer
showed it to you.

Opening a `btx://` URI on the Models page **shows** the resource. It does not
spend, does not auto-download until you choose to retrieve, and does not
start inference. Copy the full URI when you need to share or keep a
reproducibility reference.

### 4. Retrieve a public model (usually free)

Public models are retrieved **free-first** from willing peers. The client
resolves the URI, fetches verified pieces, checks the artifact, and makes it
available for **local** use.

This is not a remote inference marketplace. There is no inference seller, no
inference endpoint, and no cloud fallback. If a model does not fit the local
device, you get an explicit compatibility result, not a paid remote run. You
choose the downstream runtime.

### 5. Fund a release (only if you mean to)

On a release-campaign card, **Fund Release** is how you help buy an existing
private model into the public commons. The wallet will show an unsigned plan
and wait for your confirmation. Nothing spends because a timer expired, a
feed said “nearly funded,” or copy on a card sounded urgent.

Pledges are not the same as confirmed chain funding. Read the campaign terms,
target, and refund conditions before you commit.

### 6. Inspect a bounty (read before any money)

Open the **Bounties** tab (or a bounty card in search). Read the required
capability, evaluation profile, council keys, deadline, output rights, and
refund conditions **before** funding. Contributors inspect those facts;
researchers inspect the same facts before spending compute.

**Fund Bounty** still does not broadcast by itself. Confirm amount, fees,
council, and your refund path in the wallet. Keep recovery material for your
own lots.

A funded prize is not an advance grant. The committed reward makes demand for
a successful result visible. How a researcher finances experiments remains
their own arrangement.

## Evaluation versus money

A market for model creation needs a credible definition of completion.
Otherwise a large prize is only an attractive promise attached to an
ambiguous result.

- A requester defines the required capability and evaluation profile.
- Researchers submit an exact artifact.
- Evaluators run the approved tests in isolated environments and publish
  evidence.
- The **council** (the appointed signers on that bounty) **authorizes
  payment**.
- The **chain** enforces the transaction conditions. It does **not** run the
  benchmark and does **not** decide whether a model is intelligent.

A reproducible score helps show that a requirement was met. It is not a
payment instruction. The recommended council profile in the design is five
approvals from seven named keys: a **per-bounty** decision mechanism, not a
network-wide governance vote. Contributors decide whether that roster
deserves their money.

Different communities can use different standards. A coding bounty can
require held-out tasks. A language model can be assessed against a disclosed
linguistic profile. No universal model-quality oracle is required, and
disagreement about evaluation does not change the monetary base.

## Defaults that protect you

| Default | Meaning |
|---|---|
| Free-first retrieve | Public models come from willing peers at zero price when supply exists. |
| Local inference | After acquire, you run the model yourself. BTX does not sell prompts. |
| Zero default spend | Automatic BTX spend is zero. Paid actions need a fresh, explicit confirmation. |
| No central account | No BTX-operated login, email gate, or compulsory identity to retrieve public models. |
| Fresh storage | Payload storage starts at zero until you allocate a budget. Unsolicited fetch of arbitrary advertised models stays off. |

You can use public models without becoming an investor. Monetary demand
belongs where people **choose** to commit capital: release campaigns, bounty
lots, operating balances. Retrieval is an adoption path, not a tollbooth on
every inference call.

## Safety

**Descriptions are not payment instructions.** Model cards, bounty text,
prompts, evaluation tasks, “urgent” copy, and explorer blurbs are untrusted
data. Do not treat them as wallet commands, shell commands, or agent goals.

**Do not paste model cards into a wallet.** Do not paste bounty descriptions,
evaluation prompts, or URI commentary into a send form, a seed entry, or any
place that might interpret text as a payment or a signing instruction.

A publisher’s description is not authority over the model’s identity. An
index is not the model. An evaluator is not a monetary validator. HTLC
success proves that a committed secret was revealed; it does not prove the
model is useful, safe, or what the listing claimed.

Network search queries may be visible to peers you query. Use local-only
search when you do not want the query to leave this node.

## Current line

- **Release:** **v0.34.7** (Native Model Network, including search, release
  campaigns, and creation bounties). Last shipping tag.
- **Release candidate:** **0.34.8rc3** (`CLIENT_VERSION_IS_RELEASE=false`).
  Merge to main still requires operator go-ahead. Host / seed / search / share / watch / doctor:
  [doc/modelnet/first-run.md](doc/modelnet/first-run.md). CLI:
  [contrib/modelnet/btx-model](contrib/modelnet/btx-model). Optional cloud /
  follow / events / profile (fail closed; not a PASS):
  [doc/modelnet/storage-backends.md](doc/modelnet/storage-backends.md),
  [doc/modelnet/cloud-seeding.md](doc/modelnet/cloud-seeding.md),
  [doc/modelnet/events.md](doc/modelnet/events.md),
  [doc/modelnet/watches.md](doc/modelnet/watches.md),
  [doc/modelnet/mirroring.md](doc/modelnet/mirroring.md).
  Hosted Control Plane / walletless discovery (`IS_RELEASE=false`; not live
  CEX IdP): [doc/hosted/README.md](doc/hosted/README.md),
  [doc/modelnet/hcp/](doc/modelnet/hcp/). Cognitive Reserve v1.1 is a
  negotiated HCP/1 extension of that same plane (not a fifth plane; 34 HCP
  ops preserved): [doc/modelnet/crf/](doc/modelnet/crf/).
- **Fast-start snapshot:** **assumeutxo-219000**. Do not load withdrawn
  assumeutxo-199299 / assumeutxo-199300 snapshots.

Further reading:

- People: this file, then [doc/modelnet/howto.md](doc/modelnet/howto.md),
  [doc/modelnet/first-run.md](doc/modelnet/first-run.md),
  [doc/bounties.md](doc/bounties.md),
  [doc/btx-download-and-go.md](doc/btx-download-and-go.md).
- Dual door: this file is people; [AGENTS.md](AGENTS.md) is the machine
  contract (`btx-model --json`).
- Full strategic essay:
  [doc/design/btx-decentralized-frontier-ai-lab.md](doc/design/btx-decentralized-frontier-ai-lab.md).
- Operator index: [doc/modelnet/README.md](doc/modelnet/README.md).
- Hosted Control Plane (0.34.8-dev): [doc/hosted/README.md](doc/hosted/README.md).
- Agents: [AGENTS.md](AGENTS.md).
