---
layout: post
title:  "Human friendly logging date format"
author: "Luke Hinds"
date:   2019-04-01
---
Open `/etc/keylime.conf`

Use the following for `formatter_formatter`

    [formatter_formatter]
    format = %(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s
    datefmt = %Y-%m-%d %H:%M:%S

Example of new format

```
2019-03-08 12:05:10.267 - keylime.cloudverifier - INFO - Instance ids in db loaded from file: [u'D432FBB3-D2F1-4A97-9EF7-75BD81C00000']
2019-03-08 12:05:10.267 - keylime.cloudverifier - INFO - Starting Cloud Verifier (tornado) on port 8881, use <Ctrl-C> to stop
2019-03-08 12:05:10.268 - keylime.cloudverifier_common - INFO - Setting up TLS...
2019-03-08 12:05:10.268 - keylime.cloudverifier_common - INFO - Existing CA certificate found in /var/lib/keylime/cv_ca, not generating a new one
2019-03-08 12:05:10.271 - keylime.cloudverifier - INFO - Starting service for revocation notifications on port 8992
```
