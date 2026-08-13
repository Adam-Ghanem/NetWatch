# NetWatch distribution checklist

This checklist is intentionally manual. It is designed to earn attention through useful technical context rather than asking strangers for stars. Before publishing anywhere, read the destination’s current rules, disclose that you built the project when relevant, and avoid posting the same copy across communities.

## 1. r/Python or r/netsec

Choose one community based on the post’s value. Use **r/Python** for the Python/FastAPI implementation story and a concrete engineering lesson. Use **r/netsec** for the defensive network-visibility problem, authorization boundaries, and what the tool deliberately does not do. Do not lead with “please star my repo,” do not use engagement bait, and do not post identical promotional copy to both communities.

A value-first title could be:

> I built a local-first Python network-visibility dashboard: what I learned about bounded scans, cautious device identity, and evidence-backed change review

The body should spend most of its space on one useful lesson: why NetWatch says **Not observed** instead of **offline**, how it discards traffic payload bytes, how the 15-second/1,000-frame boundary works, or how local evidence is kept close to ownership and criticality context. Include one sanitized screenshot, a short architecture explanation, the repository link at the end, and a clear statement that it is for authorized environments. Ask for technical feedback on one specific design decision instead of asking for stars.

## 2. LinkedIn technical post

Keep the tone practical and personal. A DUT student angle is credible when it explains the learning process instead of presenting a student project as an enterprise replacement.

Suggested structure:

> I’m building NetWatch while studying cybersecurity and networking: a local-first Python/FastAPI tool for authorized network visibility.
>
> The most useful design decision was not “scan more.” It was keeping the workflow explainable: discover assets, compare what changed, review common service exposure, preserve business context, and avoid overstating what the evidence proves.
>
> A few boundaries I kept explicit: private targets only, authorization before network actions, payload-free traffic metadata, localhost-first deployment, and no claim that SQLite plus an in-process scheduler is multi-replica HA.
>
> The current suite passes 235/235 tests locally, with 77.4% coverage in the verified run. I’m looking for feedback on the onboarding, demo clarity, and contributor experience.
>
> Repository: https://github.com/Adam-Ghanem/NetWatch

Attach the 1280×640 social preview or one sanitized dashboard preview. Reply to technical questions with evidence, link to the relevant documentation, and invite interested readers to try the two-command Quickstart rather than requesting a follow or star.

## 3. Dev.to article

Use the working title **“Building NetWatch: async network monitoring in Python”** only if the article accurately explains the implementation. The article should not imply that NetWatch is a full NMS, SIEM, or offensive scanner.

Recommended outline:

1. **The problem:** why a small authorized team needs local visibility and change context, not just a list of scan results.
2. **The architecture:** FastAPI dashboard, SQLite stores, bounded scanners, identity evidence, and the local-first deployment boundary.
3. **The async design:** explain bounded concurrency, timeouts, semaphores, and why predictable limits matter more than maximum scan volume.
4. **Evidence and uncertainty:** show why “Not observed” is safer than claiming a host is offline, and how service findings remain review prompts rather than vulnerability proof.
5. **Safety by design:** private-target validation, authorization confirmations, no payload retention, localhost publishing, role boundaries, and de-identified optional intelligence.
6. **A one-minute run:** embed the two-command Quickstart and one sanitized dashboard image.
7. **What NetWatch does not solve:** multi-replica HA, continuous full-flow analytics, external incident management, and production disaster recovery.
8. **How to contribute:** link to the good-first-issue queue and identify the demo GIF, Windows Quickstart, and architecture walkthrough issues.

Use a canonical link to the GitHub repository, add descriptive tags such as `python`, `cybersecurity`, `networking`, and `opensource` only when they match the article, and include a clear author disclosure. Over time, update the article when the repository’s behavior or Quickstart changes so search traffic does not land on stale instructions.

## After publishing

Respond to substantive comments, record recurring onboarding questions, and convert repeated friction into documentation issues. Track repository visits, unique referrers, stars, forks, issue starts, and contributor pull requests over a simple weekly window. Optimize the next post around the strongest technical question, not around posting frequency.
