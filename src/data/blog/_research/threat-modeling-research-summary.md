---
title: Threat Modeling with LLMs
author: Abhishek Satpathy
pubDatetime: 2026-02-27T00:00:00Z
modDatetime: 2026-03-05T06:51:47Z
slug: threat-modeling-with-llms
featured: false
draft: false
tags:
  - research
  - ml
  - security
description: Preliminary findings regarding the effectiveness of threat modeling with LLMs and other interesting parts of the process.
---

# Humans in the Loop Can Improve Automated Threat Modeling for ML-Enabled Systems

I realized today that I had never publicly discussed any of the research I did at CMU last summer. I'm not going to pursue a publication regarding this research, but I think the things that I learned were useful. Hence, I'm making this blogpost.

## Problem Framing

Software systems are hilariously insecure. In 2024 alone, over 40,000 CVEs were published, a 38% increase over 2023, and the seventh consecutive year of record highs. As software systems scale in complexity, it becomes more difficult to verify their security. There have been many approaches in literature and in industry to address this: formal verification, static and dynamic analysis, penetration testing, fuzzing, secure-by-design frameworks, etc. The approach that I was interested in investigating was threat modeling.

Threat modeling is the practice of systematically decomposing a system to identify what can go wrong, who might exploit it, and what you should do about it. You enumerate attacker profiles, entrypoints, assets, and assumptions, usually using a data flow diagram of the system.

The problem is that it's extremely, EXTREMELY tedious. Even doing it once on a toy system as part of the research process felt endlessly boring. The actual process involves pulling together security engineers, developers, and business stakeholders for multiple multi-hour sessions, walking through data flow diagrams, brainstorming threats, and carefully documenting everything. Not only that, but updates to the system require a full repeat of the process, slowing down development and making it impractical for the average dev team.

In particular, any system that leverages ML now has to contend with an entirely new attack surface not present in more traditional software. ML components are vulnerable to causative attacks, exploratory attacks, integrity attacks, privacy violations, and more, none of which are currently captured by frameworks like STRIDE that were designed for conventional software. My primary investigation was whether frontier LLMs provided any measurable uplift in threat modeling productivity, whether through full automation or partial assistance. If they did, it could make threat modeling more accessible to software engineers who don't find the prospect of spending dozens of hours poring over diagrams and carefully enumerating threats very appealing.

## Main Finding

LLMs often invent context. If you just hand a model a system description and ask it to threat model, it will confidently hallucinate details about your architecture and produce a threat model that sounds plausible but is fundamentally naïve. We found empirically that this was the core problem with existing LLM-automation tooling like StrideGPT; they make undue assumptions about the system.

A human-in-the-loop mitigates these mistakes, but takes a lot of time. So, I spent the summer carefully building a system that elicits exactly the right context from a human.

Our approach worked as follows. An LLM "Question Generator" interviews the developer about their system. A separate "Context Judge" decides if enough detail has been gathered. Once the context is sufficient, the LLM uses it to generate attacker profiles, entrypoints, assets, and assumptions, all of which get verified by the human. Crucially, the system also searches for complex, nonlocal "chains" of threats that span multiple components.

We evaluated this on an example AWS application (the `generative-ai-newsletter-app` sample) with a ground truth threat model, using Gemini 2.5 Pro. The results:

| Model | Precision | Recall | ML Recall |
|---|---|---|---|
| MLTC (ours, full pipeline) | 0.46 | 0.86 | 1.00 |
| StrideGPT | 0.14 | 0.43 | 0.20 |
| Generated Context only | 0.67 | 0.29 | 0.40 |
| Q&A only | 0.33 | 0.14 | 0.20 |
| Generated Context & Q&A | 0.75 | 0.43 | 0.60 |

Our full pipeline achieved 0.86 recall for general threats and 1.00 recall for ML-specific threats, massively outperforming both zero-shot prompting and StrideGPT. The precision was worse (0.46 vs 0.67 for generated context alone), but not too much worse. Generally in security, missing a real threat is worse than flagging a false one.

Doing a few ablations led us to discover that: generated context alone gets you good precision but terrible recall, Q&A alone is even worse, and combining both and running the full pipeline with human verification gets you a high recall score.

This contributes to a growing body of evidence that traditional threat modeling can be at least partially automated. The key insight is that the automation has to be designed around the model's weaknesses, specifically, its tendency to hallucinate when given insufficient context.

## Disclaimers

Nevertheless, there are a few reasons I didn't publish this.

The first is methodological. This type of tool requires a developer study to be meaningful. I want to measure the uplift that software engineers see in threat modeling productivity. My sample size is too small for the data to mean anything, and the evaluation doesn't even measure the right thing. Precision and recall against a ground truth threat model tells you about coverage, not about whether a developer can produce a comparable threat model in less time. The real question is: how much faster can we get similar results? I didn't answer that.

The second reason is more fundamental: I think the problems this research tries to solve will be washed away by model scale.

Richard Sutton's "The Bitter Lesson" (2019) observes that, historically, AI researchers have built domain-specific knowledge into their systems, and this always helps in the short term, but in the long run, general methods that leverage computation win by a large margin. The pattern has repeated across chess, Go, speech recognition, and computer vision. My research is a textbook example of the thing Sutton warns against: I spent a summer carefully engineering a context elicitation pipeline (a Question Generator, a Context Judge, structured decomposition into threat categories) to compensate for the model's inability to gather context on its own. I realized, a while after, that this is the kind of human-knowledge scaffolding that Sutton points to in his writing.

As models' capabilities improve, we should expect two things:

1. They get better at asking elicitation questions in a typical chat conversation, reducing the need for a bespoke multi-agent elicitation system.
2. They get better at autonomously understanding and querying codebases, reducing the need for a human to answer those questions at all.

The second point has arguably already happened. Anthropic released Claude Code Security on February 20, 2026. It reads and reasons about codebases the way a human security researcher would: understanding component interactions, tracing data flows across files, and identifying complex multi-component vulnerability patterns. It even runs each finding through an adversarial verification pass to filter false positives. This is not threat modeling per se, but the core capability it demonstrates (an agent that autonomously builds deep context about a codebase and reasons about security properties over that context) is exactly the bottleneck my HITL system was designed to address.

More broadly, agentic coding tools like Claude Code can now navigate million-line codebases, execute commands, run tests, and manage entire implementation workflows autonomously. A coding agent pointed at a repository and told "threat model this system" can, in principle, answer its own context elicitation questions by reading the code, inspecting the architecture, and tracing data flows without any human interview process. I suspect a study today would find that this approach matches or exceeds what my carefully engineered pipeline produced last summer.

Basically, this research is not "bitter-lesson pilled" enough. The scaffolding I built was useful at a fixed point in time, but the problems it solves are the kind that scale tends to dissolve. Whether you're a researcher, a startup founder, or an engineer, Boris Cherny's advice is prescient: "Don’t build for the model of today, build for the model 6 months from now."


## Other Interesting Findings

Multimodal models are incredibly good at diagram-to-text problems, especially Gemini. I don't have formal empirical evidence for this specific claim, but the broader benchmarks back it up. The Gemini family has consistently posted state-of-the-art or near-SOTA numbers on visual document understanding tasks: DocVQA, ChartQA, InfographicVQA, and MathVista. Gemini 3 Pro scored 81% on MMMU-Pro and 87.6% on Video-MMMU. For our use case (feeding in an architecture diagram and getting back a structured textual representation) even last summer's Gemini 2.5 Pro was more than good enough for 99% of cases. I can only imagine that Gemini 3.1 Pro is even better.