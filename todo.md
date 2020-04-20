##Requests

##General
*  Implement logging (both socket and file) instead of printing to console.
*  Backend reports back to frontend if rule already exists in repo.
*  Rename post_rule_json and post_commit_json far more sensibly / unambiguously.

##Backend
* Implement handling incoming YARA rule to be pushed to TheoOracle.
* Rename retv dict to be attribute compatible (no fancy characters).

##Frontend
* Implement sending valid YARA rule to TheOracle/Backend.
* Make encapsulator work with click (surround elements currently in editor div)
* Add some sort of hashed "state" string to URL to reproduce the current editor elements from URL.
* Properly implement showing of column error occurred on (currently just appended to SyntaxError str).
* Split (what's possible) of script blocks into separate .js files.

### Bugs:
* Drag and drop won't work until you've added at least one item to the editor, 
  likely issue with no existing items to sort with.