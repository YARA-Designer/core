### Priority 1
* Clone dragged elements, don't move actual.
* Create a submit div/area at the bottom where you drag a finished rule
    1. Take grouped SPAN elements
    2. Assemble elements into a condition string with artifact vars
    3. POST condition string back into Python backend.
    4. Send into Yara rule generator
* Create a Yara rule generator that takes a condition string with artifact vars.
* Delete (cloned) elements dragged back into artifact/operator div element.

#### Priority 2
* Fix colouring when combining elements in the editor div.
* Fix issue with droppable area being only the start of the display:grid.

##### Priority 3
* Split (what's possible) of script blocks into separate .js files.
* Fix drag and drop transparency issues: https://stackoverflow.com/a/26534667

##Bugs:
* Elements clone into the source div if the drop dest was invalid.
* Cloning still happens in editor div if you drag a child node out of a span group.
* Looks like elements with the same ID cannot co-exist within the same span group
    Possible solutions:
    - Modify every cloned (operator) ID to be unique.
    - 