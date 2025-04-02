---
title: Diff Sentry and HooHacks 2025
author: Abhishek Satpathy
pubDatetime: 2025-04-02T03:10:11Z
modDatetime: 
slug: diff-sentry-hoohacks
featured: false
draft: false
ogImage: https://diff-sentry.tech/og.png
tags:
  - dev
  - product
description: A reflection on losing at HooHacks 2025
---

## Table of contents

## Context  
For context, this past weekend three of my wonderful friends and I decided to take 36 hours out of our lives to build something cool. We struggled to land on a decent idea, but eventually settled on a code vulnerability scanner. After researching potential markets and considering [the state of open source software security](https://4008838.fs1.hubspotusercontent-na1.net/hubfs/4008838/2024-tidelift-state-of-the-open-source-maintainer-report.pdf), we committed to building an open source tool for open source maintainers.

## Project  
![OpenGraph preview image for the project](@/assets/images/og.png):  
- Backend: FastAPI  
- Frontend: React.js + Tailwind CSS  
- CI/CD: GitHub Actions  
- Hosting: Frontend on Cloudflare Pages, API on Heroku (since Cloudflare doesn't support Python directly)  
- Domain: `get.tech` domain with Cloudflare DNS  

We tied everything together with the Google Gemini API for vulnerability scanning. There were also definitely a lot of roadblocks:  
- Wrestling with A, CNAME, and AAAA records
- API integration headaches  
- Figuring out monorepo deployments to different platforms  

But against the odds, we built a fully hosted, functional project with solid documentation in 24 hours flat. We even threw in a Chrome extension that rounds up Amazon purchases to donate spare change to OSS projects (currently using Plaid API, but planning to switch to GitHub Sponsors to avoid fees). While not part of our core product, we believed supporting developers financially is part of security - better funded maintainers write more secure code.

## Reflections  
So why did Diff Sentry join 185+ other submissions in the "no prize" graveyard? Unfortunately HooHacks doesn't provide direct feedback, but here's my best guess:

**1. Our Project lacked Technical depth**  
To be completely honest - our core vulnerability scanning was essentially a dressed-up LLM wrapper. Sure, we:  
1. Converted git diffs to much more human-readable formats for the prompts
2. Applied best practices in prompt engineering to deliver 90%+ accuracy on vulnerability detection
3. Built products that were deployed to production from the first commit
4. Used Gemini as a binary classifier  

But at the end of the day, our API was just a wrapper for Gemini API calls with some formatting. Meanwhile, winning teams were building robotic VR surgeons and training graph neural networks from scratch. We nailed execution but missed the "wow" factor.

**2. Scale**  
To me, I think in general winners at hackathons play a different game. They chase moon shots - ideas that *could* change the world if fully realized. We built something practical: a security tool with clear monetization paths/growth stragies. They built insanely cool, inspirational prototypes. That's a lesson, judges don't expect you to build a fully functional product in 24 hours, and will punish you when you sacrifice potential for realism. Go for the moon shot, for the idea that saves the world, and hackathons will reward you for trying something hard. If building it in 24 hours doesn't seem impossible, your idea is probably too easy.

## Moving forward
We're still proud of Diff Sentry and plan to develop it further. However, the lesson I learned at HooHacks is that hackathons aren't case competitions or startup accelerators, they're about building cool shit.