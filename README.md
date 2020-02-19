# Yara Whitelist Rule Creator
#### _A TheHive/Cortex responder_ 

The YWRC responder sends a `thehve:case` to a listener.

### Set up on thehive and cortex host:

NB: The system needs to have cortexutils installed!
Install it using pip (both py2 and py3, to be sure):
```
pip install cortexutils
pip3 install cortexutils
```

### How to use
(Assuming `$cortexResponders = /opt/Cortex-Analyzers/responders/`)
1. Upload the `responder` directory as `$cortexResponders/` on the remote host.
2. Restart cortex and thehive
3. Enable the YaraWhitelistRuleCreator responder in cortex.
4. Start the listener.
5. Use the responder on a case.