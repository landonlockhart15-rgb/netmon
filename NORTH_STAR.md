# NetMon — North Star

> Read this before proposing or reviewing any change. It defines what this
> project is *trying to be*. A change can be correct and still be wrong if it
> doesn't serve this. Private hobby project — goals are **capability, power, and
> craft**, plus learning while building. No revenue/user-growth target.

## What this really is
The **best home-network monitoring system on the market — passive AND offensive.**
Three pillars are the foundation, not the ceiling — they should always keep
getting better, but they don't define the boundary of what this app can become:

1. **Total visibility** — identify **every device on the network using every
   means possible**: ARP/mDNS/SSDP/DHCP, port & service scans, OS/vendor
   fingerprinting, passive traffic inference, MAC/OUI lookup, hostname/UPnP,
   captive probing. Nothing on the network is unknown.
2. **Security lab (offensive)** — capable of finding **any possible exploit on
   any possible machine**: vuln scanning, CVE mapping, exposed-service and
   weak-cred detection, exploit-surface analysis. A real red-team lab for the
   home network.
3. **Uptime Guardian** — keeps you online: detects outages, diagnoses cause,
   and **auto-heals** (e.g. reboots the Orbi), always safely and reversibly.

Beyond these three: look at the WHOLE app — every existing feature, every
screen, every workflow — and improve any of it. And don't stop at what's
already here. Propose genuinely new features that fit naturally alongside
what NetMon already does, even ones Landon hasn't thought of himself. There
is no size ceiling — a small polish and a brand-new subsystem are both
in scope, judged only on whether they make the app better.

It is **fused with AI** (plain-English diagnosis and insight) and is meant to be
**graphically amazing, professional, and smooth.**

## Who it's for
Both audiences, at once, not a tradeoff between them:
- **Point-and-click, works the first time** for someone with zero technical
  background — no setup friction, no jargon walls, sane defaults everywhere.
- **Real depth underneath** for a power user who wants to dig in — advanced
  options should exist and be genuinely capable, just not forced on anyone
  who doesn't go looking for them.
- **Transparency and traceability, always.** Every action NetMon takes
  (a scan, a heal, a block) must be visible, explained, and reversible. The
  user should never wonder what happened or why — plain-English by default,
  full detail one click away.

## What "great" looks like
- **Sees everything.** Device discovery is exhaustive and identification is
  confident — make/model/OS/role for every node, by any technique available.
- **Finds anything.** The security lab surfaces real, current exploits and exposure
  on any host, with evidence and a clear path to fix.
- **Keeps you online.** Detect → diagnose → heal, with guardrails and a plain record.
- **Looks the part.** A polished, smooth, professional UI — topology, devices, and
  findings rendered beautifully; never clunky.
- **Speaks human.** AI explains what a finding/outage means and what to do, and
  every action is traceable back to why it happened.
- **Works for anyone, rewards depth.** A total beginner succeeds with defaults;
  an expert finds real power tools when they look for them.
- **Token-frugal AI — a priority.** The plain-English diagnosis and insight lean
  on capable free/local models first; paid subscription models (Claude, Codex,
  GPT) are a deliberate last resort, used only when a finding genuinely needs
  them. Great AI explanation should cost as little paid token as possible.

## Build toward
More discovery & fingerprinting techniques; deeper offensive scanning and
exploit-finding; broader self-healing actions; sharper AI diagnosis; richer
topology and device intelligence; continual UI polish — AND genuinely new
capabilities beyond the three pillars that make this a more complete, more
impressive home-network app. Both the **backend** (scanning/identification/
healing engine) and the **frontend** (visualization) should be excellent.

## Do NOT
- Ship maintenance/test/refactor churn as if it were the product when there's real
  discovery, offensive-security, healing, UI, or genuinely new capability to build.
- Add a second parallel monitor/scan/insight path when one exists — extend it.
- Take a network/host action that isn't safe and reversible, or hide what it did.
- Bury the user in dev-speak or raw output — AI should translate it, always,
  regardless of how advanced the underlying feature is.
- Reach for a paid/subscription model for AI diagnosis when a free or local one
  would do. Paid is the exception, never the default explainer.

## The vibe
A relentless, professional home-network operator and red-team lab that anyone
can pick up and trust immediately, but that rewards a power user who wants to
go deeper. It sees every device, finds every weakness, keeps you online,
explains itself completely, and looks gorgeous doing it — and it keeps
surprising Landon with things he didn't ask for but is glad it built.
