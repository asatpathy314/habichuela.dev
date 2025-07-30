---
title: A reflection on CMU REUSE
author: Abhishek Satpathy
pubDatetime: 2025-03-20T21:57:45Z
modDatetime:
slug: reflection-on-cmu-reuse
featured: false
draft: false
tags:
  - Research
  - Machine Learning
  - Software Engineering
description: A short reflection on my experience in the undergraduate summer research program at Carnegie Mellon.
---

### General Thoughts

Coming to Carnegie Mellon, its reputation scared me a little. CMU is famous for cracked students, hard classes, world-class research, and unicorn startups built out of dorm rooms. Although the University of Virginia is a terrific school, it doesn’t have that same "clout," especially in its CS department.

In particular, I was worried about disappointing my professor. Surprisingly though, my mentors were very accepting. They didn’t care how much I knew or what progress I made yesterday. They met me where I was and helped me move forward, and they cared more about curating my research taste and thought process.

In the process, I realized that, from an institution’s perspective, the primary goal of these programs is recruiting and talent development. As an undergraduate student, your output is rarely economically productive enough to justify the stipend you receive. Institutions absorb the cost because it allows them to develop a more skilled, available workforce.

Keep in mind then, summer programs exist for students to invest in themselves. If you're a student at a summer program, learn as much as you can, do as much as you can, and when it’s time to rest, actually get some rest instead of pulling all-nighters.

### What I Wish I Had Done Better

There are three things in particular I wish I had done better.

First, keeping an unreasonably detailed engineering/research notebook. Humans have limited memory, but in research, the most meaningful connections often come from disparate thoughts.  

For example, I was working on a retrieval-augmented generation (RAG) extension for threat modeling automation. During testing, I took detailed notes on what I observed. One thing I wrote was that the model tended to assume too much about the system (e.g., available tools, engineers’ permissions) in its reasoning and explanations.

It’s easy to forget a detail like that when you’re focused on collecting metrics like recall and precision. However, when I brought it up in a meeting, it led to a valuable contribution (implementing a novel elicitation loop for generating better context).

Critics of detailed logs argue it's pointless because most people never revisit their notes. That might have been true before the age of local agent command-line tools. Today, it’s easy to spin up something like the Gemini CLI and use it as a context-aware search engine for your notes, making it far easier to connect ideas across weeks and projects.

Second, recording all my meetings. Especially in research, your PI is often busy, and the few meetings you do have with them are incredibly valuable. It’s very easy to forget the minutiae of a 45‑minute conversation.

Recording meetings lets you stay focused on the discussion and later revisit specific points. An engineer at Microsoft first suggested this to me, and they personally attested it was the biggest contributor to earning a return offer and becoming a high performer on their team.

Even now, I use the few recordings I captured at the end of the summer almost every day as I draft my final poster and research paper.

Lastly, speaking to more professors and students outside my immediate group. I had a few conversations with professors outside of my mentor (one with Professor Kadane) that were deeply meaningful. I wish I had made a greater effort to meet more faculty and students across CMU.

### Closing Thoughts

My biggest takeaways from the summer were learning how to do independent research and realizing that I prefer machine learning research to software engineering research.

By nature, I’m a skeptical person. I constantly ask myself whether what I’m doing is valuable and whether others will find it useful. In machine learning, researchers sometimes overlook these questions. It was refreshing to work with my professor, who focused on software engineering research, because they often asked these questions more directly and eloquently than I ever could. I learned what developers value, what the research community values, and how to identify novel, important research directions.

At the same time, I didn’t spend my evenings studying software engineering best practices, security, or how practitioners monitor ML systems. I spent my evenings learning linear algebra, backpropagation, neural networks, and implementing classic ML papers. I worked through CS231n homework assignments, read *Situational Awareness: The Decade Ahead* by Leopold Aschenbrenner, *The Precipice* by Toby Ord, and *Superintelligence* by Nick Bostrom (or playing piano!).

As romantic a notion as it is, I grew up on sci‑fi novels, and machine intelligence is something I’m deeply passionate about. We are drifting toward a future where intelligence is commoditized in the same way physical labor was during the Industrial Revolution. But alignment and mechanistic interpretability research show that we still have major issues to solve to ensure these systems promote human flourishing rather than something stupid like making as many paperclips as possible.

I want the chance to contribute to that effort. Maybe my fears are unfounded. Maybe AI is a bubble and we’ll see the funding dry up in a few years. Either way, I still love the day‑to‑day work of machine learning research: digging into the math and "model biology," identifying gaps in existing work by reading widely and thinking deeply, and testing out new ideas.

As Jim Carrey said, “You can fail at something you don’t want, so you might as well take a chance doing what you love.”
