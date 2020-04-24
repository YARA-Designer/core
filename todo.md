##Requests
*  Compare YARA rules' similarity (particularly conditions)
    * Change generator to use descriptive names.

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
* Style modals more sensibly and make them fit width of their content, not span page width (more or less).
* Strip deprecated yara_rule_raw for parts and delete it.

## Bugs
* Drag and drop won't work until you've added at least one item to the editor, 
  likely issue with no existing items to sort with.
