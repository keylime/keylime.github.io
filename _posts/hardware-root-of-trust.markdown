---
layout: blog
title:  "How to set up Keylime Runtime Integrity Management"
author: "Luke Hinds"
date:   2019-04-02
---
### Core root of trust measurement (CRTM)

When a platform is rebooted (or one could argue, first turned on) all of the PCRs are set to `0` (zero's)

The system first then undergo's the "Security (SEC) Phase"

The SEC Phase is resposible for the following:

* Handling all platform restart events
* Creating a temporary memory store
* Serving as the root of trust in the system
* Passing handoff information to the PEI Core
