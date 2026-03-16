---
title: Threat Modeling with LLMs
author: Abhishek Satpathy
pubDatetime: 2026-02-27T00:00:00Z
modDatetime: 2026-03-16T15:44:48Z
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

I realized today that I had never publicly talked about the research I did at CMU last summer. I’m not planning to turn it into a paper, but I learned a lot from it, and I think those lessons are worth sharing. So, I’m writing this blog post.

## Problem Framing

Software systems are hilariously insecure. In 2024 alone, over 40,000 CVEs were published: a 38% increase over 2023, and the seventh straight year of record highs. As software systems grow more complex, verifying their security gets harder. Both industry and academia have proposed many ways to deal with this: formal verification, static and dynamic analysis, penetration testing, fuzzing, secure-by-design frameworks, and so on. The approach I was interested in was threat modeling.

Threat modeling is the practice of systematically breaking down a system to identify what can go wrong, who might exploit it, and what should be done about it. In practice, this usually means enumerating attacker profiles, entry points, assets, and assumptions, often using a data flow diagram of the system.

The problem is that it is extremely, **extremely** tedious. Even doing it once on a toy system as part of the research process felt endlessly boring. In the real world, the process usually involves pulling together security engineers, developers, and business stakeholders for multiple multi-hour sessions, walking through data flow diagrams, brainstorming threats, and carefully documenting everything. Worse, whenever the system changes, you often have to repeat the process. That slows development and makes threat modeling impractical for the average team.

This gets even worse for systems that use ML. Traditional threat modeling frameworks like STRIDE were designed for conventional software and do not capture ML-specific attack surfaces well: data poisoning, model extraction, adversarial inputs, membership inference, training data leakage. These are not edge cases. They are core ways ML systems can fail, and most teams have no systematic way to identify them.

That gap motivated the project: could LLMs make threat modeling practical enough that teams would actually do it, especially for ML-enabled systems where the attack surface is least understood?

## Main Finding

LLMs often invent context. If you give a model a system description and ask it to produce a threat model, it will often confidently hallucinate details about the architecture and generate something that sounds plausible but is fundamentally naïve. Empirically, we found that this was the central problem with existing LLM-based automation tools like StrideGPT: they make too many assumptions about the system.

A human in the loop can reduce those mistakes, but that usually costs a lot of time. So I spent the summer building a system designed to extract exactly the right context from a human, and only as much as needed.

The approach worked like this. An LLM “Question Generator” interviewed the developer about their system. A separate “Context Judge” determined whether enough detail had been gathered. Once the context was sufficient, the LLM used it to generate attacker profiles, entry points, assets, and assumptions, all of which were then verified by the human. Crucially, the system also searched for complex, nonlocal threat “chains” spanning multiple components.

We evaluated this on an example AWS application (the `generative-ai-newsletter-app` sample) with a ground-truth threat model, using Gemini 2.5 Pro. The results were:

| Model                      | Precision | Recall | ML Recall |
| -------------------------- | --------: | -----: | --------: |
| MLTC (ours, full pipeline) |      0.46 |   0.86 |      1.00 |
| StrideGPT                  |      0.14 |   0.43 |      0.20 |
| Generated Context only     |      0.67 |   0.29 |      0.40 |
| Q&A only                   |      0.33 |   0.14 |      0.20 |
| Generated Context & Q&A    |      0.75 |   0.43 |      0.60 |

Our full pipeline achieved 0.86 recall on general threats and 1.00 recall on ML-specific threats, substantially outperforming both zero-shot prompting and StrideGPT. Precision was worse than the “generated context only” baseline (0.46 vs. 0.67), but not catastrophically so. In security, missing a real threat is usually worse than flagging a false positive.

The ablations were also informative. Generated context alone gave reasonably good precision but poor recall. Q&A alone performed even worse. But combining both, then running the full pipeline with human verification, produced much higher recall.

I think this adds to a growing body of evidence that threat modeling can be at least partially automated. The key is that the automation has to be designed around the model’s weaknesses, especially its tendency to hallucinate when it lacks context.

## Disclaimers

There are a few reasons I didn’t try to publish this.

The first is methodological. To evaluate a tool like this properly, you really want a developer study: recruit software engineers, have one group use the tool and another do threat modeling manually, then measure both coverage and time-to-completion. I didn’t do that, because the evaluation infrastructure alone would have taken months.

Even the simpler evaluation I *did* run—computing precision and recall against a ground-truth threat model—was labor-intensive. I had to build that ground truth by hand, which meant carefully reading through the entire application architecture, enumerating plausible threats, and verifying each one. For a single toy application, that took days. Scaling that to multiple systems, with enough data to publish, was not feasible in one summer.

And even then, precision and recall against a ground truth only tell you about coverage. They do not tell you whether a developer can produce a comparable threat model faster. The real question is: how much faster can we get similar results? Answering that requires the developer study I wasn’t able to run.

The second reason is more fundamental: I think the specific problems this research tries to solve may be washed away by model scale.

Richard Sutton’s “The Bitter Lesson” argues that AI researchers repeatedly build domain-specific structure into their systems, and while that often helps in the short term, the long-run winners are usually more general methods that scale with computation. We’ve seen that pattern in chess, Go, speech recognition, and computer vision. My project is, frankly, a textbook example of the kind of thing Sutton warns about. I spent a summer engineering a context-elicitation pipeline—a Question Generator, a Context Judge, structured decomposition into threat categories—to compensate for the model’s inability to gather context on its own. Later, I realized that this was exactly the kind of human-designed scaffolding Sutton is skeptical of.

As models improve, I think we should expect two things:

1. They will get better at asking the right elicitation questions in ordinary chat, reducing the need for a bespoke multi-agent system.
2. They will get better at autonomously understanding and querying codebases, reducing the need for a human to answer those questions at all.

The second point may already be here. Anthropic released Claude Code Security on February 20, 2026. It reads and reasons about codebases in a way that looks much closer to a human security researcher: understanding component interactions, tracing data flows across files, and identifying complex multi-component vulnerability patterns. It also runs each finding through an adversarial verification pass to filter false positives. This is not exactly threat modeling, but the core capability it demonstrates—autonomously building deep context about a codebase and reasoning about security properties over that context—is precisely the bottleneck my human-in-the-loop system was designed to address.

More broadly, agentic coding tools like Claude Code can now navigate million-line codebases, execute commands, run tests, and manage substantial implementation workflows autonomously. An agent pointed at a repository and told “threat model this system” can, in principle, answer its own context-elicitation questions by reading the code, inspecting the architecture, and tracing data flows without any human interview process. I suspect that a study run today would find that this approach matches or exceeds what my carefully engineered pipeline produced last summer.

Basically, this research is not bitter-lesson-pilled enough. The scaffolding I built was useful at a particular moment in time, but it solves problems that scale may simply erase. Whether you are a researcher, founder, or engineer, Boris Cherny’s advice feels prescient here: “Don’t build for the model of today. Build for the model 6 months from now.”

## Other Interesting Findings

One other thing I came away believing: multimodal models are very good at diagram-to-text tasks, especially Gemini.

I do not have formal empirical evidence for that claim in this project, but the broader benchmark picture supports it. The Gemini family has consistently posted state-of-the-art or near-state-of-the-art results on visual document understanding tasks like DocVQA, ChartQA, InfographicVQA, and MathVista. Gemini 3 Pro reportedly scored 81% on MMMU-Pro and 87.6% on Video-MMMU.

For our use case—feeding in an architecture diagram and getting back a structured textual representation—even last summer’s Gemini 2.5 Pro was more than good enough in almost every case. I can only imagine that Gemini 3.1 Pro is even better.