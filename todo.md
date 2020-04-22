##Requests

##General
*  Rename post_rule_json and post_commit_json far more sensibly / unambiguously.

##Backend
* Rename retv dict to be attribute compatible (no fancy characters).

##Frontend
* Make encapsulator work with click (surround elements currently in editor div)
* Add some sort of hashed "state" string to URL to reproduce the current editor elements from URL.
* Properly implement showing of column error occurred on (currently just appended to SyntaxError str).
* Split (what's possible) of script blocks into separate .js files.
* Make cursor into a pointing-hand when hovering buttons.


### Bugs:
* Drag and drop won't work until you've added at least one item to the editor, 
  likely issue with no existing items to sort with.