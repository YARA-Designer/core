##Requests
*  Compare YARA rules' similarity (particularly conditions)
    * Change generator to use descriptive names.

##General
*  Rename post_rule_json and post_commit_json far more sensibly / unambiguously.
*  Rename all instances of "artifacts" to "observables" for less confusion..

##Backend
* Rename retv dict to be attribute compatible (no fancy characters).

##Frontend
* Make encapsulator work with click (surround elements currently in editor div)
* Add some sort of hashed "state" string to URL to reproduce the current editor elements from URL.
* Properly implement showing of column error occurred on (currently just appended to SyntaxError str).
* Split (what's possible) of script blocks into separate .js files.
* Style modals more sensibly and make them fit width of their content, not span page width (more or less).
* Strip deprecated yara_rule_raw for parts and delete it.
* Replace all antiquated XHR requests with fetch.
* Figure out some sort of scroll overflow for modals when they vertically size beyond reason (or beyond viewport).

## Bugs
* Drag and drop won't work until you've added at least one item to the editor, 
  likely issue with no existing items to sort with.
* When switching from dark to light theme some CSS variables doesn't get explicitly set, e.g. `--modal_background_info`.