# NetMon — North Star

> Read this before proposing or reviewing any change. It defines what this
> project is *trying to be*. A change can be correct and still be wrong if it
> doesn't serve this. Private hobby project — goals are **capability, autonomy,
> and clarity**, plus learning while building. No revenue or user-growth target.

## What this really is
A home-network guardian. It watches the network, understands what it sees, and
acts — it monitors devices and uptime, **explains problems in plain English** (a
non-technical person should understand what's wrong and why), and **heals
itself** (Uptime Guardian auto-reboots the Orbi on an outage). AI diagnoses;
rules decide; the human is informed, not required.

## What "great" looks like
- **Speaks human, not dev.** Every alert/insight says what it means for the home
  and what (if anything) to do — never a stack trace or raw metric dump.
- **Acts autonomously and safely.** Detect → diagnose → fix, with guardrails and
  a clear record of what it did and why. Always reversible.
- **Trustworthy.** Few false alarms; when it speaks, it matters.
- **Insightful.** Surfaces patterns a person wouldn't catch (a flaky device, a
  recurring 3am drop) before they become a problem.

## Build toward
Smarter diagnosis and root-causing, more self-healing actions (beyond reboot),
clearer plain-English explanations, proactive pattern detection, a calm and
legible dashboard. Capability that reduces how often a human must intervene.

## Do NOT
- Bury the user in dev-speak, raw logs, or metric noise.
- Take a network action that isn't safe and reversible, or act without recording
  why in plain English.
- Add a second parallel monitor/insight/explain path when one exists — extend it.
- Ship test-scaffolding or refactors *as if* they were the product when there's
  real guardian capability to build.

## The vibe
A calm, competent operator watching the house. Quiet until it matters, clear
when it speaks, and fixes things before you have to ask.
