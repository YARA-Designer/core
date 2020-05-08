/**
 * Add a MD5 sum property to String prototype which returns the MD5 sum of its value.
 * */
Object.defineProperty(String.prototype, 'md5sum', {
    value: function() {
        return md5(this);
  }
});

// Exceptions
function NoContentsException(message) {
    this.message = message;
    this.name = NO_CONTENTS_EXCEPTION;
}

// https://stackoverflow.com/a/26272668
function getStyleRuleValue(selector, style) {
 let selector_compare=selector.toLowerCase();
 let selector_compare2= selector_compare.substr(0,1)==='.' ?  selector_compare.substr(1) : '.'+selector_compare;

 for (let i = 0; i < document.styleSheets.length; i++)
 {
  let mySheet = document.styleSheets[i];
  let myRules = mySheet.cssRules ? mySheet.cssRules : mySheet.rules;

  for (let j = 0; j < myRules.length; j++)
  {
    if (myRules[j].selectorText)
    {
     let check = myRules[j].selectorText.toLowerCase();
     switch (check)
     {
      case selector_compare  :
      case selector_compare2 : return myRules[j].style[style];
     }
    }
   }
  }
 }



// IDs and ClassNames (Helps tremendously when renaming identifier strings at a later date):
// Common values:
const NONE = "none";
const BLOCK = "block";
const CLICK = "click";
const AUX_CLICK = "auxclick";
const ACTIVE = "active";
const ID = "id";

// MIME Types:
const MIMETYPE_JSON = 'application/json';
const MIMETYPE_URL_ENCODED = 'application/x-www-form-urlencoded';

// Exceptions:
NO_CONTENTS_EXCEPTION = "NoContentsException";

// CSS Vars:
const CSS_VAR_PREFIX = "--";

// Root:
const ROOT_CLASS = 'yara-rule-designer';

// Modifying classes
const SIZE_WIDE_CLASS = "size-wide";
const SIZE_FULLWIDTH_CLASS = "size-fullwidth";

// Modals:
const MODAL_CLASS = "custom-modal";
const MODAL_CONTENT_CLASS = `${MODAL_CLASS}-content`;
const MODAL_HEADER = "header";
const MODAL_HEADER_CONTENT = `${MODAL_HEADER}-content`;
const MODAL_BODY = "body";
const MODAL_BODY_TOP = `${MODAL_BODY}-top`;
const MODAL_BODY_MIDDLE = `${MODAL_BODY}-middle`;
const MODAL_BODY_BOTTOM = `${MODAL_BODY}-bottom`;
const MODAL_FOOTER = "footer";
const MODAL_CLOSE = "close";
const MODAL_BG = "modal-background";
const MODAL_TEXT_COLOR = "modal-color";
const MODAL_DEFAULT_HEADER = "";
const MODAL_DEFAULT_BODY = "";
const MODAL_DEFAULT_BODY_TOP = "";
const MODAL_DEFAULT_BODY_MIDDLE = "";
const MODAL_DEFAULT_BODY_BOTTOM = "";
const MODAL_DEFAULT_FOOTER = "<p>Tip: Click anywhere outside of this modal to close.</p>";
const MODAL_DEFAULT_CONFIRMATION_HEADER = "<h2>Are you sure?</h2>";
const MODAL_DEFAULT_CONFIRMATION_BODY = "";
const MODAL_DEFAULT_CONFIRMATION_BODY_TOP = "";
const MODAL_DEFAULT_CONFIRMATION_BODY_MIDDLE = "";
const MODAL_DEFAULT_CONFIRMATION_BODY_BOTTOM = "";
const MODAL_DEFAULT_CONFIRMATION_FOOTER = MODAL_DEFAULT_FOOTER;

const RESPONSE_MODAL = "response-modal";
const RESPONSE_MODAL_HEADER = `${RESPONSE_MODAL}-${MODAL_HEADER}`;
const RESPONSE_MODAL_BODY = `${RESPONSE_MODAL}-${MODAL_BODY}`;
const RESPONSE_MODAL_FOOTER = `${RESPONSE_MODAL}-${MODAL_FOOTER}`;
const RESPONSE_MODAL_BUTTON = `${RESPONSE_MODAL}-button`;
const RESPONSE_MODAL_BUTTON_COMMIT = `${RESPONSE_MODAL_BUTTON}-commit-onclick`;
const RESPONSE_MODAL_BUTTON_COMMIT_CLASS = `${RESPONSE_MODAL_BUTTON}-commit`;
const RESPONSE_MODAL_BUTTON_COMMIT_DISABLED_CLASS = `${RESPONSE_MODAL_BUTTON_COMMIT_CLASS}-disabled`;
const RESPONSE_MODAL_BUTTON_JSON_COLLAPSIBLE_CLASS = `${RESPONSE_MODAL_BUTTON}-json-collapsible`;
const RESPONSE_MODAL_JSON_COLLAPSIBLE_CONTENT_CLASS = `${RESPONSE_MODAL}-json-collapsible-content`;

const CONFIRMATION_MODAL = "confirmation-modal";
const CONFIRMATION_MODAL_HEADER = `${CONFIRMATION_MODAL}-${MODAL_HEADER}`;
const CONFIRMATION_MODAL_BODY = `${CONFIRMATION_MODAL}-${MODAL_BODY}`;
const CONFIRMATION_MODAL_FOOTER = `${CONFIRMATION_MODAL}-${MODAL_FOOTER}`;
const CONFIRMATION_MODAL_BUTTON = `${CONFIRMATION_MODAL}-button`;
const CONFIRMATION_MODAL_BUTTON_YES = `${CONFIRMATION_MODAL_BUTTON}-yes-onclick`;
const CONFIRMATION_MODAL_BUTTON_YES_CLASS = `${CONFIRMATION_MODAL_BUTTON}-yes`;
const CONFIRMATION_MODAL_BUTTON_NO = `${CONFIRMATION_MODAL_BUTTON}-no-onclick`;
const CONFIRMATION_MODAL_BUTTON_NO_CLASS = `${CONFIRMATION_MODAL_BUTTON}-no`;

// Tables:
const CUSTOM_TABLE_CLASS = "custom-table";
const CUSTOM_TABLE_CONTAINER = `${CUSTOM_TABLE_CLASS}-container`;
const TABLE_FILTER_INPUT_SUFFIX = "input-filter";
const TABLE_FILTER_RADIO_CLASS_SUFFIX = `${TABLE_FILTER_INPUT_SUFFIX}-radios`;
const TABLE_FILTER_COUNT = "filter-count";
const TABLE_FILTER_CHECKED_RADIO = "Title";
const TABLE_FILTER_HIDDEN_RADIOS = ["Pending"];

// Table: -- Fetched Rules
const RULES_TABLE = "fetched-rules";

// Designer:
const HTML_TITLE = `${ROOT_CLASS}-title`;
const DESIGNER_HEADER = `${ROOT_CLASS}-header`;
const DESIGNER_HEADER_CONTENT = `${DESIGNER_HEADER}-content`;
const DESIGNER_HEADER_CONTENT_TITLE = `${DESIGNER_HEADER_CONTENT}-title`;
const DESIGNER_HEADER_CONTENT_BYLINE = `${DESIGNER_HEADER_CONTENT}-byline`;
const DESIGNER_HEADER_CONTENT_DESCRIPTION = `${DESIGNER_HEADER_CONTENT}-description`;

const DESIGNER_TAGS = `${ROOT_CLASS}-tags`;
const DESIGNER_TAGS_CHECKBOX_CLASS = "yara-tag-checkbox";
const OPERATOR_CONTAINER = `${ROOT_CLASS}-operators`;
const ARTIFACT = `artifact`;
const ARTIFACT_CLASS = `condition-artifact`;
const ARTIFACT_CONTAINER = `${ROOT_CLASS}-artifacts`;
const ARTIFACT_TYPE = `artifact-type`;
const ARTIFACT_TYPE_CLASS = `condition-artifact-type`;
const ARTIFACT_TYPE_CONTAINER = `${ROOT_CLASS}-artifact-types`;
const LEFTPANE_DRAGGABLES = [OPERATOR_CONTAINER, ARTIFACT_TYPE_CONTAINER, ARTIFACT_CONTAINER];

const DESIGNER_EDITOR = `${ROOT_CLASS}-editor`;

// Text and styling:
const NUMBERED_TEXTBOX_CLASS = "numbered-lines";
const SUCCESS_ICON = "<span style='color: green'>&#10003;</color>";
const FAILED_ICON = "<span style='color: red'>&#10005;</span>";
const BGCOLOR_RED_CLASS = "red-bg";
const TEXT_COLOR_GREEN_CLASS = "green-text";
const TEXT_COLOR_RED_CLASS = "red-text";
const YARA_VARIABLE_DENOMINATOR = "$";

// Convenience/readability constants:
const MOUSECLICK_LEFT = 0;
const MOUSECLICK_MIDDLE = 1;
const MOUSECLICK_RIGHT = 2;
const ARTIFACT_CLASSES = ["condition-artifact", "condition-artifact-type"];
const KEYWORD_CLASSES = ["condition-keyword"];
const INFO_LEVEL = "info";
const ERROR_LEVEL = "error";
const WARNING_LEVEL = "warning";
const SUCCESS_LEVEL = "success";
const SYNTAX_ERROR = "syntax";

// NB: *NOT* Unused and needs to be var (instead of let/const) due to being a GLOBAL.
var currentlyLoadedRule = null;

/////////////////////////////////// Dragula - drag 'n Drop //////////////////////////////////////////

dragula([
    // Enable drag and drop for these DIVs:
    document.getElementById(OPERATOR_CONTAINER),
    document.getElementById(ARTIFACT_TYPE_CONTAINER),
    document.getElementById(ARTIFACT_CONTAINER),
    document.getElementById(DESIGNER_EDITOR)
], { // Apply logic.
    copy: function (el, source) {
        // If the source is one of the draggable elements, allow copy.
        return LEFTPANE_DRAGGABLES.includes(source.id);
    },

    accepts: function (el, target) {
        // If the target is NOT one of the draggable elements, accept drop.
        return !LEFTPANE_DRAGGABLES.includes(target.id);
    }
});

///////////////// Response modal globals (Re-implementations and listeners) ////////////////////////

// Get the modals
let modals = [];
let modalIds = [RESPONSE_MODAL, CONFIRMATION_MODAL];
for (let i = 0; i < modalIds.length; i++ ) {
    // Add modals by-id.
    modals.push(document.getElementById(modalIds[i]));

   // Add close logic.
   let closeCustomModal = document.getElementById(`${modalIds[i]}-${MODAL_CLOSE}`); //[i];

   // When the user clicks on <span> (x), close (hide) the modal
   document.getElementById(`${modalIds[i]}-${MODAL_CLOSE}`).onclick = function() {
     document.getElementById(modalIds[i]).style.display = NONE;
   };

   // When the user clicks anywhere outside of the modal, close it
    window.onclick = function (event) {
        for (let i = 0; i < modalIds.length; i++) {
            if (event.target === document.getElementById(modalIds[i])) {
                document.getElementById(modalIds[i]).style.display = NONE;
            }
        }
    };
}

/**
 * Convenience: Shortens the line width when getting a CSS variable.
 */
function getCSSVar(varName) {
    return getComputedStyle(document.documentElement).getPropertyValue(`${CSS_VAR_PREFIX}${varName}`);
}

/**
 * Shows a pop-up modal with customisable header, footer and body,
 * as well as background color based on level.
 *
 * level: String that is appended to CSS variables:
 *  - '-modal-background-*'
 *  - '-modal-color-*'
 */
function popupModal(modalId=null, header=null, bodyTop=null, bodyMiddle=null, bodyBottom=null, footer=null, level=null) {
    // Modal element itself.
    let modal = document.getElementById(modalId);

    // Reset any custom resizing or other modal-content classList modifications.
    modal.getElementsByClassName(MODAL_CONTENT_CLASS)[0].className = MODAL_CONTENT_CLASS;

    // Modal sub-elements.
    let modalHeader = document.getElementById(`${modalId}-${MODAL_HEADER}`);
    let modalHeaderContent = document.getElementById(`${modalId}-${MODAL_HEADER_CONTENT}`);
    // let modalBody = document.getElementById(`${modalId}-${MODAL_BODY}`);
    console.log("modalBodyTop", `${modalId}-${MODAL_BODY_TOP}`);
    let modalBodyTop = document.getElementById(`${modalId}-${MODAL_BODY_TOP}`);
    let modalBodyMiddle = document.getElementById(`${modalId}-${MODAL_BODY_MIDDLE}`);
    let modalBodyBottom = document.getElementById(`${modalId}-${MODAL_BODY_BOTTOM}`);
    let modalFooter = document.getElementById(`${modalId}-${MODAL_FOOTER}`);

    // Set level (if null, set to info/default).
    level = (level != null) ? level : INFO_LEVEL;

    // Set sub-element values, if given.
    modalHeaderContent.innerHTML = (header != null) ? header: MODAL_DEFAULT_HEADER;
    // modalBody.innerHTML  = (body != null) ? body : MODAL_DEFAULT_BODY;
    modalBodyTop.innerHTML  = (bodyTop != null) ? bodyTop : MODAL_DEFAULT_BODY_TOP;
    modalBodyMiddle.innerHTML  = (bodyMiddle != null) ? bodyMiddle : MODAL_DEFAULT_BODY_MIDDLE;
    modalBodyBottom.innerHTML  = (bodyBottom != null) ? bodyBottom : MODAL_DEFAULT_BODY_BOTTOM;
    modalFooter.innerHTML = (footer != null) ? footer :  MODAL_DEFAULT_FOOTER;

    // Set custom style.
    //      Header.
    modalHeader.style.background = getCSSVar(`${MODAL_BG}-${level}`);
    modalHeader.style.color = getCSSVar(`${MODAL_TEXT_COLOR}-${level}`);
    //      Footer.
    modalFooter.style.background = getCSSVar(`${MODAL_BG}-${level}`);
    modalFooter.style.color = getCSSVar(`${MODAL_TEXT_COLOR}-${level}`);

    // Show modal.
    modal.style.display = BLOCK;

    // Return the modal to be easily used by caller.
    return modal;
}

function popupWarningModal(header, body, footer=null) {
    let hdr = `<h2>Warning: ${header}</h2>`;
    let bdy = `<h3>${body}</h3>`;

    popupModal(RESPONSE_MODAL, hdr, null, bdy, null, footer, WARNING_LEVEL);
}

function popupErrorModal(header, body, footer=null) {
    let hdr = `<h2>Warning: ${header}</h2>`;
    let bdy = `<h3>${body}</h3>`;

    popupModal(RESPONSE_MODAL, hdr, null, bdy, null, footer, ERROR_LEVEL);
}

function performAction(actionObj) {
    if ( actionObj.hasOwnProperty("action") ) {
        // Apply arguments (if defined).
        if (actionObj.hasOwnProperty("args")) {
            if (actionObj.args.length > 0) {
                // Perform action with arguments.
                actionObj.action(...actionObj.args);
            } else {
                console.error("performAction was given actionObj with empty arguments list!", actionObj)
            }
        } else {
            // Perform action without arguments.
            actionObj.action();
        }
    } else {
        console.error("performAction was given actionObj with no action key!", actionObj)
    }
}


/**
*   Adds Yes/No confirmation buttons to a custom modal and binds actions to them.
*/
function popupConfirmationModal(yesAction, noAction=undefined,
                                body=MODAL_DEFAULT_CONFIRMATION_BODY,
                                header=MODAL_DEFAULT_CONFIRMATION_HEADER,
                                footer=MODAL_DEFAULT_CONFIRMATION_FOOTER,
                                level=WARNING_LEVEL) {

    // Append bindable buttons to custom body.
    let bodyMiddle = body;
    bodyMiddle += `<button id="${CONFIRMATION_MODAL_BUTTON_YES}" class="${CONFIRMATION_MODAL_BUTTON_YES_CLASS}">Yes</button>`;
    bodyMiddle += `<button id="${CONFIRMATION_MODAL_BUTTON_NO}" class="${CONFIRMATION_MODAL_BUTTON_NO_CLASS}">No</button>`;

    // Spawn modal.
    popupModal(CONFIRMATION_MODAL, header, null, bodyMiddle, null, footer, level);

    // Add bindings to buttons.
    document.getElementById(CONFIRMATION_MODAL_BUTTON_YES).onclick = function() {
        yesAction && performAction(yesAction);

        // Close modal.
        document.getElementById(CONFIRMATION_MODAL).style.display = NONE;
    };
    document.getElementById(CONFIRMATION_MODAL_BUTTON_NO).onclick = function() {
        // Perform bound action (if defined).
        noAction && noAction();

        // Close modal after handling button action.
        document.getElementById(CONFIRMATION_MODAL).style.display = NONE;
    };
}

function popupHelpModal() {
    let header = "<h2>How To Use</h2>";
    let bodyMiddle =
            "<h4>Adding items</h4>" +
            "<p>Either click on or drag items from the left-pane to add them to the editor." + "<br/>" +
            "<i>NB: Drag and drop won't work until you've added at least one item to the editor.</i></p>" +
            // "<p></p>" +

            "<h4>Removing items</h4>" +
            "<p>Middle mouse-click on an item in the editor to remove it.</p>"+

            "<h4>Tags</h4>" +
            "<p>Check the checkboxes for which tags you want to include (if any).</p>";

    popupModal(RESPONSE_MODAL, header, null, bodyMiddle, null, null, INFO_LEVEL);

}

///////////////////////////////////// Core (designer) code ///////////////////////////////////

/**
 * Override default behaviour for mouse clicks in the editor div,
 * in order to support middle and right clicks.
 */
document.getElementById(DESIGNER_EDITOR).addEventListener(AUX_CLICK, function(ev) {
  console.log(ev.button);
  // Prevent default action in order to implement our own.
  ev.preventDefault();

  // Handle aux click events.
  onAuxClick(ev);
});

function addToEditor(clickEvent) {
    let editorDiv = document.getElementById(DESIGNER_EDITOR);

    // If target is already in the editor, ignore the click event.
    if (clickEvent.target.parentNode.getAttribute(ID) === DESIGNER_EDITOR) {
        console.log("Ignored click event (target is child of editor div):");
        console.log(clickEvent);
        return
    }

    console.log('addToEditor: ' + $(clickEvent.target).text());
    editorDiv.appendChild(makeClone(clickEvent.target));
}

function removeFromEditor(clickEvent) {
    let editorDiv = document.getElementById(DESIGNER_EDITOR);

    // Only perform remove action if target is a child of editor div.
    if (clickEvent.target.parentNode.getAttribute(ID) === DESIGNER_EDITOR) {
        console.log("removeFromEditor: " + $(clickEvent.target).text());
        editorDiv.removeChild(clickEvent.target);
    }
}

function onAuxClick(auxClickEvent) {
    console.log("onAuxClick:");
    console.log(auxClickEvent);

    // Check which mouse button was pressed and act accordingly.
    switch (auxClickEvent.button) {
        case MOUSECLICK_MIDDLE:
            removeFromEditor(auxClickEvent);
            break;
        case MOUSECLICK_RIGHT:
            break;
    }
}

function getEditorContents() {
    return document.getElementById(DESIGNER_EDITOR).children;
}

function getEditorArtifactsAndTypes(unique=true) {
    let artifacts = [];
    let children = getEditorContents();
    if (children.length === 0) {
        throw new NoContentsException("Editor had no contents");
    }

    for (let i = 0; i < children.length; i++) {
        if ( ARTIFACT_CLASSES.includes(children[i].className) ) {
            if (unique === true) {
                // If unique is specified, omit duplicate entries.
                if ( !artifacts.some(child => child.id === children[i].id) ) {
                    artifacts.push(children[i]);
                }
            } else {
                artifacts.push(children[i]);
            }
        }
    }

    return artifacts;
}

function getEditorElementArtifactText(element) {
    // Get text string.
    return $(element).text();
}

function getEditorElementKeywordText(element) {
    // Get text string.
    return $(element).text();
}

function getEditorConditionString() {
    let conditionString = "";
    let children = getEditorContents();

    // Spacing to use in front of a word, to form a coherent sentence structure.
    let preSpacing = "";
    for (let i = 0; i < children.length; i++) {
        if (i === 1) {
            // If we're past the first entry we can start prepending spacing.
            preSpacing = " ";
        }

        // If child is of the artifact family.
        if ( ARTIFACT_CLASSES.includes(children[i].className) ) {
            // Prepend with a YARA variable denominator.
            conditionString += preSpacing + YARA_VARIABLE_DENOMINATOR + children[i].id;
        } else if (KEYWORD_CLASSES.includes(children[i].className)) {
            // Child is a logical operator
            conditionString += preSpacing + getEditorElementKeywordText(children[i]).toLowerCase();
        } else {
            console.error("getEditorConditionString is not supposed to reach an else condition!", children[i]);
        }
    }

    return conditionString;
}

function getEnabledTags() {
    let enabledTags= [];
    let tagCheckboxes = document.getElementsByClassName(DESIGNER_TAGS_CHECKBOX_CLASS);

    for (let i = 0; i < tagCheckboxes.length; i++) {
        if (tagCheckboxes[i].checked) enabledTags.push(tagCheckboxes[i].value);
    }

    return enabledTags;
}

/**
 * Generate a JSON of varname and vardata to send in POST request.
 */
function getRuleJsonFromEditorElements() {
    let json = {};
    let yaraRule = window.currentlyLoadedRule;
    let yaraRuleName = `Whitelist_${yaraRule.data.title}`; // FIXME: Hardcoded string variable should be made configurable.
    let yaraMetaDescription = `Whitelist regler for alarmen: Whitelist_${yaraRule.data.title}`; // FIXME: Hardcoded string variable should be made configurable.

    // Set meta FIXME: sub-dicts hardcoded!
    json["meta"] = {"description" : yaraMetaDescription};

    // Set rule name.
    json["rule"] = yaraRuleName;

    // Set tags.
    json["tags"] = getEnabledTags();

    // Get list of artifacts currently residing in editor DIV.
    json["artifacts"] = {};

    let artifactElements = getEditorArtifactsAndTypes();
    for (let i = 0; i < artifactElements.length; i++) {
        json["artifacts"][YARA_VARIABLE_DENOMINATOR + artifactElements[i].id] = {
            "artifact": getEditorElementArtifactText(artifactElements[i])
        }
    }

    // Get condition.
    json["condition"] = getEditorConditionString();

    return json;
}

function addCaseDetailsCollapsibleButtonLogic(className) {
    let coll = document.getElementsByClassName(className);
    let i;

    for (i = 0; i < coll.length; i++) {
      coll[i].addEventListener(CLICK, function() {
        this.classList.toggle(ACTIVE);
        let content = this.nextElementSibling;
        if (content.style.display === BLOCK) {
          content.style.display = NONE;
        } else {
          content.style.display = BLOCK;
        }
      });
    }
}


function fetchGetRequest(url, callback) {
    function status(response) {
        if (response.status >= 200 && response.status < 300) {
            return Promise.resolve(response)
        } else {
            return Promise.reject(new Error(response.statusText))
        }
    }

    function json(response) {
        return response.json()
    }

    fetch(url)
    .then(status)
    .then(json)
    .then(function(data) {
        // console.log(`fetchRequest succeeded with JSON response`, data);
        callback(data);
      }).catch(function(error) {
        console.log('fetchRequest failed!', error);
      });
}

async function fetchPostRequest(url = '', data = {}, callback) {
    function status(response) {
        if (response.status >= 200 && response.status < 300) {
            return Promise.resolve(response)
        } else {
            return Promise.reject(new Error(response.statusText))
        }
    }

    function json(response) {
        return response.json()
    }

    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        mode: 'cors', // no-cors, *cors, same-origin
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
          'Content-Type': MIMETYPE_JSON
          // 'Content-Type': MIMETYPE_URL_ENCODED',
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        body: JSON.stringify(data) // body data type must match "Content-Type" header
        })
        .then(status)
        .then(json)
        .then(function(data) {
            console.log(`fetchPostRequest succeeded with JSON response`, data);
            callback(data);
          }).catch(function(error) {
            console.log('Request failed', error);
          });

    // return response.json(); // parses JSON response into native JavaScript objects
}


function getRule(ruleId, callback=printRulesTable) {
    let url = $('#getRule').data().url;

    fetchPostRequest(url, { id:  ruleId}, callback);
}

function getRules(callback=printRulesTable) {
    fetchGetRequest($('#getRules').data().url, callback);
}

/**
 * Generates a (nicely formatted/indented) HTML <TABLE> based on a list of header:column maps.
 *
 * @param id                    (Unique) ID for <TABLE>.
 * @param headerContentMaps     List of header:column maps (e.g. [{"title": "a title}].
 * @param className             (Unique) class name for <TABLE>.
 *
 * @returns {string}            Generated HTML <TABLE>.
 */
function makeTable(id, headerContentMaps, className = CUSTOM_TABLE_CLASS) {
    // Header row:
    let headerColumns = "";
    // For key in arbitrary JSON (they all share the same keys).
    for (let key of Object.keys(headerContentMaps[0])) {
        let friendlyName = key;

        // Encountered header is a HTML comment, attempt to extract its hidden friendly name.
        if ( containsHtmlComment(friendlyName) ) {
            friendlyName = getHtmlCommentData(friendlyName);
        }

        headerColumns += `        <th id="${id}-header-${friendlyName}">${key}</th>\n`;
    }

    let headerRow =
        `    <tr id="${id}-headers" class='header ${className}-header'>\n` +
        `${headerColumns}` +
        `    </tr>`;

    // Content rows:
    let tableContents = "";
    // For JSON in list.
    for (let i = 0; i < headerContentMaps.length; i++) {
        let item = headerContentMaps[i];
        tableContents += `    <tr id="${id}-row-${i}">\n`;

        // For item in JSON.
        let keys = Object.keys(item);
        for (let key of keys) {
            let keyIndex = Object.keys(item).indexOf(key);
            tableContents += `        <td id="${id}-row-${i}-col-${keyIndex}">${item[key]}</td>\n`;
        }
        tableContents +=
            `    </tr>\n`;
    }

    return `<table id="${id}" class="${className}">\n` +
            `${headerRow}\n` +
            `${tableContents}` +
            `</table>`;
}

/**
 * Makes a ISO8601 datetime string more human readable.
 *
 * @param isoDateString     "YYYY-MM-DDTHH:MM:SS.f"
 * @returns {string}        "YYYY-MM-DD HH:MM:SS"
 */
function humanizeISODate(isoDateString) {
    let date = isoDateString.split('T')[0];
    let time = isoDateString.split('T')[1].split('.')[0];

    return `${date} ${time}`;
}

function isIterable(obj) {
    // checks for null and undefined
    if (obj == null) {
        return false;
    }
        return typeof obj[Symbol.iterator] === 'function';
}

function makeRuleTableRows(rules) {
    let headerContentMaps = [];

    if (isIterable(rules) !== true) {
        rules = Array(rules);
    }

    for (let rule of rules) {
        headerContentMaps.push({
            "<!--Pending-->": "",  // Value intentionally left blank (to be filled with pending bar later).
            "Title": rule.data.title,
            "Sev": rule.data.severity,
            "<!--Observables--><img src='/static/images/searchicon.png' title='Observables'>": rule.data.observables.length,
            "Added": rule.added_on !== null ? humanizeISODate(rule.added_on) : "N/A",
            "YARA File": rule.yara_filename !== undefined ? rule.yara_filename : "N/A",
            "Modified": rule.last_modified !== null ? humanizeISODate(rule.last_modified): "N/A",
            "ID": rule.data.id
        });
    }

    return headerContentMaps;
}

function filterFetchedRules(inputId, tableId, filterRadioId, filterCountCallback=null) {
    let input = document.getElementById(inputId);
    let filter = input.value.toUpperCase();
    let table = document.getElementById(tableId);
    let filterRadios = document.getElementById(filterRadioId).getElementsByTagName('input');

    // Get all table row elements.
    let tr = table.getElementsByTagName("tr");

    // Get the currently checked radio button.
    let enabledTd = 0;
    for (let idx = 0; idx < filterRadios.length; idx++) {
        console.log(`filterCheckboxes[${idx}]`, filterRadios[idx]);
        if (filterRadios[idx].checked) {
            enabledTd = idx;
        }
    }

    // Loop through all table rows, and hide those who don't match the search query
    let filterCount = 0;
    for (let i = 0; i < tr.length; i++) {
        let td = tr[i].getElementsByTagName("td")[enabledTd];

        if (td) {
            let txtValue = td.textContent || td.innerText;

            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = NONE;
                filterCount++;
            }
        }
    }

    // Report statistics to a callback (if defined).
    filterCountCallback && filterCountCallback(filterCount);
}

/**
 * Takes a string and returns a boolean of whether it's a HTML comment.
 *
 * @param s
 */
function isHtmlComment(s) {
    return ( s.startsWith("<!--") && s.endsWith("-->") );
}

/**
 * Takes a string and returns a boolean of whether contains a HTML comment.
 *
 * @param s
 */
function containsHtmlComment(s) {
    const regex = /<!--.*-->/g;
    return s.search(regex) !== -1;
}

/**
 * Takes a string and returns the substring in-between the HTML comment delimiters.
 *
 * @param s
 */
function getHtmlCommentData(s) {
    const regex = /<!--(.*)-->/;

    // Return the second item which is the 1st capturing group,
    // (the first group entry is the complete match).
    return s.match(regex)[1].toString();
}

function filterCountCallback(filterCount, modalId = RESPONSE_MODAL) {
    let filtercountElement = document.getElementById(
        `${modalId}-${MODAL_HEADER}-${TABLE_FILTER_COUNT}`);

    filtercountElement.innerText = filterCount > 0 ? `(filtered: ${filterCount})` : "";
}

function getCellValue(tr, idx) {
    return tr.children[idx].innerText || tr.children[idx].textContent;
}


function comparer(idx, asc) {
    return function(a, b) { return function(v1, v2) {
        return v1 !== '' && v2 !== '' && !isNaN(v1) && !isNaN(v2) ? v1 - v2 : v1.toString().localeCompare(v2);
    }(getCellValue(asc ? a : b, idx), getCellValue(asc ? b : a, idx));
}}

function mockRules(num) { // FIXME: Remove this debug/testing function.
    let mockRules = [];
    for (let i = 0; i < num; i++) {
        mockRules.push({
            "added_on": "2020-03-05T13:50:07.793123",
            "case_id": String(i),
            "data": {
                "title": `Mock Rule #${i}`,
                "severity": i,
                "observables": [],
                "id": String(i)
            },
            "last_modified": "2020-04-29T10:28:28.504976",
            "pending": true,
            "yara_file": null
        })
    }
    return mockRules;
}

/**
 * Print fetched rules table.
 *
 * Customised printTable code for fetched rules.
 *
 * @param rules
 * @param defaultCheckedRadio
 * @param hideRadios
 * @param modalId
 */
function printRulesTable(rules, defaultCheckedRadio = TABLE_FILTER_CHECKED_RADIO,
                         hideRadios = TABLE_FILTER_HIDDEN_RADIOS, modalId = RESPONSE_MODAL) {
    console.log("rules", rules);
    console.log("mock rules", mockRules(5));
    for ( let mockRule of mockRules(50) ) {
        rules.push(mockRule);
    }

    let header = `<h3>Fetched rules <span id='${modalId}-header-${TABLE_FILTER_COUNT}'</span></h3>`;
    let bodyTop = "";
    let bodyMiddle = "";
    let footer = "Tip: Click any row to load its corresponding rule.";
    let tableId = RULES_TABLE;
    let headerContentMaps = makeRuleTableRows(rules);

    // Filter/Search input text box:
    let filterRadioClassName = `${tableId}-${TABLE_FILTER_RADIO_CLASS_SUFFIX}`;
    let filterRadioId = filterRadioClassName;
    let filterInputId = `${tableId}-${TABLE_FILTER_INPUT_SUFFIX}`;
    bodyTop +=
        `<input type="text" id="${filterInputId}" onkeyup="filterFetchedRules('${filterInputId}', ` +
        `'${tableId}', '${filterRadioId}', filterCountCallback)" placeholder="Filter table..">`;

    // Checkboxes:
    let radioHTML = "";
    let columns = Object.keys(headerContentMaps[0]);
    for (let i = 0; i < columns.length; i++) {
        let style = "";
        let column = columns[i];

        // Encountered header is a HTML comment, attempt to extract its hidden friendly name.
        if ( containsHtmlComment(column) ) {
            column = getHtmlCommentData(column);
        }

        // Skip radios if told to.
        if (hideRadios) {
            if (hideRadios.includes(column)) {
                console.log(`Hide added radio button: ${column}`);
                style += "display: none;"
            }
        }

        // Ignore empty keys (If they have no name, they were probably not meant to be automatically added like this).
        if (column !== "" && column !== null) {
            let checked = "";

            // Set checked property if column matched the defaultCheckedRadio (and defaultCheckedRadio is defined).
            if (defaultCheckedRadio) {
                checked = column === defaultCheckedRadio ? " checked": "";
            }

            // Make styles applicable if any are defined.
            if (style !== "") {
                style = `style="${style}"`;
            }

            radioHTML +=
                `<input type="radio" name="${filterRadioClassName}" class="form-check-input" ` +
                `id="${filterRadioId}-${i}" title="${column}"${checked}${style}>\n` +
                `<label class="form-check-label" for="${filterRadioId}-${i}"${style}>${column}</label>\n`;
        }
    }

    // Assemble checkboxes HTML.
    bodyTop += `<div class="${filterRadioClassName} form-check form-check-inline" id="${filterRadioId}">\n` +
        `${radioHTML}\n</div>`;
    bodyTop += "<br>";

    // Table:
    let table = makeTable(tableId, headerContentMaps);
    let tableContainer =
        `<div id=${CUSTOM_TABLE_CONTAINER}>\n` +
        `    ${table}\n` +
        `</div>\n`;
    bodyMiddle += tableContainer;
    // console.log(body);

    let modal = popupModal(RESPONSE_MODAL, header, bodyTop, bodyMiddle, null, footer, INFO_LEVEL);

    // Apply actions to modal and table that couldn't be applied before it was spawned:

    // Set size to fullwidth due to the amount of columns of this particular table.
    modal.getElementsByClassName(MODAL_CONTENT_CLASS)[0].classList.add(SIZE_FULLWIDTH_CLASS);

    // Add onclick action for sorting headers.
    for ( let headerElem of document.getElementById(`${tableId}-headers`).children ) {
        headerElem.onclick = function () {
            let table = document.getElementById(tableId);
            while(table.tagName.toUpperCase() !== 'TABLE') table = table.parentNode;
            Array.prototype.slice.call(table.querySelectorAll('tr:nth-child(n+2)'))
                .sort(comparer(Array.prototype.slice.call(headerElem.parentNode.children).indexOf(headerElem), this.asc = !this.asc))
                .forEach(function(tr) { table.appendChild(tr) });
        }
    }

    for (let i = 0; i < rules.length; i++) {
        // Add pending bar to rules that have never been designed.
        if (rules[i]["pending"] === true) {
            document.getElementById(`${tableId}-row-${i}-col-0`).style.backgroundColor = "#f4d03f";
        }

        // Add onclick action for each row to load the corresponding rule.
        document.getElementById(`${tableId}-row-${i}`).onclick = function() {
            // If editor isn't empty, prompt for confirmation to avoid possible work loss.
            if (getEditorContents().length > 0) {
                popupConfirmationModal({"action": loadRule, "args": [rules[i].data.id]}, null,
                    "<h3>You currently have contents in the editor, loading a rule clears the editor.</h3>")
            } else {
                loadRule(rules[i].data.id);
                document.getElementById(RESPONSE_MODAL_FOOTER).innerText =
                    `Loaded rule: ${rules[i].data.title} [ID: ${rules[i].data.id}]`;
            }
        };

        // Set pointer cursor in each row to indicate onclick presence.
        document.getElementById(`${tableId}-row-${i}`).style.cursor = "pointer";
    }
}

function loadRuleDialog() {
    getRules();
}

function setTitle(title, id, description=null) {
    document.getElementById(HTML_TITLE).innerText = title;
    document.getElementById(DESIGNER_HEADER_CONTENT_TITLE).innerHTML =
        `<p> Case: ${title}</p>`;
    document.getElementById(DESIGNER_HEADER_CONTENT_BYLINE).innerHTML =
        `<p>ID: ${id}</p>`;
    document.getElementById(DESIGNER_HEADER_CONTENT_DESCRIPTION).innerHTML =
        `<p>${description}</p>`;
}

function setTags(tags) {
    let html ="";
    for (let i = 0; i < tags.length; i++) {
        html += `<input type="checkbox" id="tagCheckbox${i}" class="${DESIGNER_TAGS_CHECKBOX_CLASS}" ` +
            `value="${tags[i]}">\n` +
            `<label for="tagCheckbox${i}" title="${tags[i]}">${tags[i]}</label>\n`;
            `<div class="w-100"></div>\n`;
    }
    document.getElementById(DESIGNER_TAGS).innerHTML = html;
}

function setObservableTypes(types) {
    let html = "";

    for (let i = 0; i < types.length; i++) {
        html +=
            `<span id='${ARTIFACT_TYPE}-${types[i].md5sum()}' class='${ARTIFACT_TYPE_CLASS}' onclick='addToEditor(event)'>${types[i]}</span>`;
    }

    document.getElementById(ARTIFACT_TYPE_CONTAINER).innerHTML = html;
}

function setObservableData(data) {
    let html = "";

    for (let i = 0; i < data.length; i++) {
        html +=
            `<span id='${ARTIFACT}-${data[i].md5sum()}' class='${ARTIFACT_CLASS}' onclick='addToEditor(event)'>${data[i]}</span>`;
    }

    document.getElementById(ARTIFACT_CONTAINER).innerHTML = html;
}

function setAllObservables(observables) {
    let uniqueTypes = [];
    let uniqueData = [];

    for (let observable of observables) {
        if (observable.hasOwnProperty("dataType")) {
            if (observable.dataType !== null && !uniqueTypes.includes(observable.dataType)) {
                uniqueTypes.push(observable.dataType);
            }
        }
        if (observable.hasOwnProperty("data")) {
            if (observable.data !== null && !uniqueData.includes(observable.data)) {
                uniqueData.push(observable.data);
            }
        }
    }

    setObservableTypes(uniqueTypes);
    setObservableData(uniqueData);
}

function loadRuleCallback(rule) {
    // Clear editor.
    clearEditorDivContents();

    // Set the currently loaded rule global variable (used in other functions).
    window.currentlyLoadedRule = rule;

    // Set title tag and title div.
    setTitle(rule.data.title, rule.data.id, rule.data.description);

    // Set tags div.
    setTags(rule.data.tags);

    // Set observables divs.
    setAllObservables(rule.data.observables);
}

function loadRule(ruleId) {
    getRule(ruleId, loadRuleCallback);
}

function handlePostRuleResponse(json) {
    let errorType = "";
    let errorMessage = "";
    let errorLineNumber = 0;
    let errorColumnNumber = 0;
    let errorColumnRange = 0;
    let errorWord = "";
    let level = "success";

    // Parse JSON:
    let outJson = json["out"];

    let compilable = outJson["compilable"];
    let success = outJson["success"];

    let sourcePreprocessed = outJson["source (preprocessed)"]; // FIXME: Fix JSON key naming convention.

    let yaraRuleSourceFile = outJson["generated_yara_source_file"]; // FIXME: Fix JSON key naming convention.

    if (!compilable) {
        level = "warning";
    }

    if (!success) {
        errorMessage = outJson["error"]["message"];
        errorType = outJson["error"]["type"];
        errorLineNumber = parseInt(outJson["error"]["line_number"]);
        errorColumnNumber = parseInt(outJson["error"]["column_number"]);
        errorColumnRange = parseInt(outJson["error"]["column_range"]);
        errorWord = outJson["error"]["word"];
        level = "error";

        console.log("errorMessage: " + errorMessage);
        console.log("errorType: " + errorType);
        console.log("errorLineNumber: " + errorLineNumber);
        console.log("errorColumnNumber: " + errorColumnNumber);
        console.log("errorColumnRange: " + errorColumnRange);
        console.log("errorWord: " + errorWord);
        console.log("level: " + level);
    }

    // Define header
    let header = `<h2>YARA rule generation results: ${String(level).toUpperCase()}</h2>`;

    // Define body
    let body = "";

    // Passed/Failed items.
    body += "<p>" + (compilable === true ? SUCCESS_ICON : FAILED_ICON) + " Compiles </p>";

    // Error message (if any).
    if (!success) {
        body += `<p>${errorType.replace(/^\w/, c => c.toUpperCase())} error message: ${errorMessage}</p>`;
    }

    // Formatted string of the generated YARA rule ("source").
    body += "<br/>Generated YARA rule:<br/>";

    // Loop through lines to add line numbering support via CSS counter.
    let lines = String(sourcePreprocessed).split('\n');
    body += `<pre class='${NUMBERED_TEXTBOX_CLASS}'>`;
    for (let i = 0; i < lines.length; i++) {
        if (!success) {
            if (errorType === SYNTAX_ERROR && i === errorLineNumber-1) {
                // Color bad column or line.
                let stringUpToMark = lines[i].substring(0, errorColumnNumber -1);
                let stringToMark = lines[i].substring(errorColumnNumber -1, errorColumnRange - 1);
                let stringPastMark = lines[i].substring(errorColumnRange -1, lines[i].length);

                // FIXME: Debug syntax error marking (not sure it is quite over yet).
                // console.log("stringUpToMark: " + stringUpToMark);
                // console.log(`stringToMark: '${stringToMark}'`);
                // console.log("stringPastMark: " + stringPastMark);

                lines[i] = `${stringUpToMark}<mark class='${BGCOLOR_RED_CLASS}'>${stringToMark}</mark>${stringPastMark}`;
            }
        }

        // Append line
        body += `<span>${lines[i]}</span>`;
    }
    body += "</pre>";

    // Add commit button if valid result.
    if (success) {
        body += `<button id="${RESPONSE_MODAL_BUTTON_COMMIT}" class="${RESPONSE_MODAL_BUTTON_COMMIT_CLASS}">Commit & Push</button>`;
    } else {
        body += `<button id="${RESPONSE_MODAL_BUTTON_COMMIT}" class="${RESPONSE_MODAL_BUTTON_COMMIT_DISABLED_CLASS}" disabled>Commit & Push</button>`;
    }

    // Collapsible raw JSON details.
    body +=
        `<button type='button' class='${RESPONSE_MODAL_BUTTON_JSON_COLLAPSIBLE_CLASS}'>Show JSON</button>\n` +
        `<div class='${RESPONSE_MODAL_JSON_COLLAPSIBLE_CONTENT_CLASS}'>\n` +
        `    <pre>\n` +
        `        ${JSON.stringify(json, undefined, 4)}\n` +
        `    </pre>\n` +
        `</div>`;

    // Spawn modal.
    popupModal(RESPONSE_MODAL, header, null, body, null, MODAL_DEFAULT_FOOTER, level);

    // Perform changes that requires a spawned modal:

    // Add bindings to buttons.
    document.getElementById(RESPONSE_MODAL_BUTTON_COMMIT).onclick = function() {
        // Perform bound action.
        let jsonToCommit = {};
        let yaraRule = window.currentlyLoadedRule;
        jsonToCommit["filepath"] = yaraRuleSourceFile;
        jsonToCommit["rulename"] = json["in"]["rule"]; // FIXME: Make backend send the proper sanitized rulename in "out" dict.
        jsonToCommit["case_id"] = yaraRule.data.id;

        postCommit(jsonToCommit);

        // Close modal after handling button action.
        document.getElementById(CONFIRMATION_MODAL).style.display = NONE;
    };

    // Make the JSON detailsCollapsible element actually collapsible.
    addCaseDetailsCollapsibleButtonLogic(RESPONSE_MODAL_BUTTON_JSON_COLLAPSIBLE_CLASS);
}

/**
 * Make a custom POST request for non-form elements like DIV and SPAN.
 */
function postRule() {
    try {
        let json = getRuleJsonFromEditorElements();

        let xhr = new XMLHttpRequest();  // FIXME: Replace antiquated XHR with fetch.
        let postDesignedRuleUrl = $('#postDesignedRuleUrl').data().url;

        console.log("POST URL: " + postDesignedRuleUrl);

        xhr.open("POST", postDesignedRuleUrl, true);
        xhr.setRequestHeader('Content-Type', MIMETYPE_JSON);

        // Add custom handling of the response returned by XHR POST URL.
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                handlePostRuleResponse(JSON.parse(xhr.responseText));
            }
        };

        // Convert a JavaScript value to a JavaScript Object Notation (JSON) string (Required for POST).
        xhr.send(JSON.stringify(json));
    } catch (e) {
        if (e.name === NO_CONTENTS_EXCEPTION) {
            console.warn(e.message, e.name);
            popupWarningModal(e.message, "Please add contents to the editor before submitting.");
        } else {
            console.error(e.message, e.name);
            popupErrorModal(e.name, e.message);
        }
    }
}

function printGitLogEntry(hexSha, authorUsername, authorEmail, dateString, msg) {
    return `<span>
                commit ${hexSha}<br/>
                Author: ${authorUsername} &lt;<a href="mailto:${authorEmail}">${authorEmail}</a>&gt;<br/>
                Date: &nbsp;&nbsp; ${dateString}<br/>
                <br/>
                &nbsp;&nbsp;&nbsp;&nbsp;${msg}
            </span>`;
}

function printGitDiff(diffString, color=true) {
    if (diffString === "") {
        return "<p>There were no differences between this and the previous commit.</p>"
    }

    let retv = `<pre class='${NUMBERED_TEXTBOX_CLASS}'>`;

    if (color) {
        for (let line of diffString.split('\n')) {
            if (line.startsWith("+")) {
                retv += `<span><mark class='${TEXT_COLOR_GREEN_CLASS}'>${line}</mark>\n</span>`
            } else if (line.startsWith("-")) {
                retv += `<span><mark class='${TEXT_COLOR_RED_CLASS}'>${line}</mark>\n</span>`
            }
            else {
                retv += `<span>${line}\n</span>`;
            }
        }
    } else {
        for (let line of diffString.split('\n')) {
            retv += `<span>${line}</span>`
        }
    }
        retv += "</pre>";

    return retv;
}

function handlePostCommitResponse(json) {
    let errorType = "";
    let errorMessage = "";
    let level = SUCCESS_LEVEL;

    // Parse JSON:
    let outJson = json["out"];

    // let compilable = outJson["compilable"];
    let success = outJson["success"];

    if (!success) {
        errorMessage = outJson["error"]["message"];
        errorType = outJson["error"]["type"];
        level = outJson["error"].hasOwnProperty("level") ? outJson["error"]["level"] : ERROR_LEVEL;

        console.log("errorMessage: " + errorMessage);
        console.log("errorType: " + errorType);
        console.log("level: " + level);
    }

    // Define header
    let header = `<h2>YARA rule commit & push results: ${String(level).toUpperCase()}</h2>`;

    // Define body
    let body = "";

    // Error message (if any).
    if (!success) {
        body += `<p>${errorType.replace(/^\w/, c => c.toUpperCase())} ${level} message: ${errorMessage}</p>`;
    }

    // Main (body) contents.
    if (success) {
        let commit = outJson["commit"];
        body += printGitLogEntry(commit["hexsha"], commit["author_username"], commit["author_email"],
                                 commit["committed_date_custom"], commit["message"]);
        body += "<br/><br/>";
        body += printGitDiff(commit["diff"], true);
    }

    // Collapsible raw JSON details.
    body +=
        `<button type='button' class='${RESPONSE_MODAL_BUTTON_JSON_COLLAPSIBLE_CLASS}'>Show JSON</button>` +
        `<div class='${RESPONSE_MODAL_JSON_COLLAPSIBLE_CONTENT_CLASS}'>` +
        `    <pre>` +
        `        ${JSON.stringify(json, undefined, 4)}` +
        `    </pre>` +
        `</div>`;

    // Spawn modal.
    popupModal(RESPONSE_MODAL, header, null, body, null, MODAL_DEFAULT_FOOTER, level);

    // Perform changes that requires a spawned modal:
    // Make the JSON detailsCollapsible element actually collapsible.
    addCaseDetailsCollapsibleButtonLogic(RESPONSE_MODAL_BUTTON_JSON_COLLAPSIBLE_CLASS);
}

/**
 * Make a custom POST request for non-form elements like DIV and SPAN.
 */
function postCommit(json) {
    let xhr = new XMLHttpRequest();  // FIXME: Replace antiquated XHR with fetch.
    let postCommitUrl = $('#postCommitUrl').data().url;

    console.log("POST URL: " + postCommitUrl);

    xhr.open("POST", postCommitUrl, true);
    xhr.setRequestHeader('Content-Type', MIMETYPE_JSON);

    // Add custom handling of the response returned by XHR POST URL.
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            // Make sure to close any open modals.
            for ( let modalElement of document.getElementsByClassName(MODAL_CLASS) ) {
                if (modalElement.style.display !== NONE) {
                    console.log("[postCommit] xhr.onreadystatechange: Closed open modal: " + modalElement.id);
                    modalElement.style.display = NONE;
                }
            }

            // Handle response.
            handlePostCommitResponse(JSON.parse(xhr.responseText));
        }
    };

    // Convert a JavaScript value to a JavaScript Object Notation (JSON) string (Required for POST).
    xhr.send(JSON.stringify(json));
}

function clearEditorDivContents() {
    let editorDiv = document.getElementById(DESIGNER_EDITOR);
    editorDiv.textContent = '';
}

function clearRule() {
    // Define body
    let body = "<h3>Are you sure you want to clear the current rule? This is action is <em>irreversible</em>.</h3>";

    // yesAction, noAction, body, args...
    popupConfirmationModal({"action": clearEditorDivContents}, null, body);
}

function makeClone(node) {
    console.log(node);
    let clone;

    // Returns a copy of node. If deep is true, the copy also includes the node's descendants.
    clone = node.cloneNode(true);

    node.parentNode.insertBefore(clone, node);

    return clone;
}

function getParameterByName(name, url) {
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';

    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

// Global code
let idParm = getParameterByName(ID);

if (idParm !== null && idParm !== "") {
    console.log("Load rule: " + idParm);
    loadRule(idParm);
}

// Indicate that script ran through to the end during the initial load.
console.log("Ready.");
