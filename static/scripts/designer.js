// Exceptions
function NoContentsException(message) {
    this.message = message;
    this.name = "NoContentsException"
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

const ROOT_CLASS = 'yara_rule_designer';
const DIVS_WITH_CLONING = ['yara_rule_designer_artifacts', 'yara_rule_designer_operators'];
const ELEMENT_OPERATORS = 'yara_rule_designer_operators';
const ELEMENT_ARTIFACT_TYPES = 'yara_rule_designer_artifact_types';
const ELEMENT_ARTIFACTS = 'yara_rule_designer_artifacts';
const LEFTPANE_DRAGGABLES = [ELEMENT_OPERATORS, ELEMENT_ARTIFACT_TYPES, ELEMENT_ARTIFACTS];
const ELEMENT_EDITOR = 'yara_rule_designer_editor';
const SUCCESS_ICON = "<span style='color: green'>&#10003;</color>";
const FAILED_ICON = "<span style='color: red'>&#10005;</span>";
const YARA_VARIABLE_DENOMINATOR = "$";

let originalParentIdLookupByClass = {
    "draggable_artifact": "yara_rule_designer_artifacts",
    "condition_keyword": "yara_rule_designer_operators",
    "condition_encapsulator": "yara_rule_designer_operators"
};

// Convenience/readability constants.
const LEFT_CLICK = 0;
const MIDDLE_CLICK = 1;
const RIGHT_CLICK = 2;
const ARTIFACT_CLASSES = ["draggable_artifact", "draggable_artifact_type"];
const KEYWORD_CLASSES = ["condition_keyword"];
const MODAL_DEFAULT_HEADER = "";
const MODAL_DEFAULT_BODY = "";
const MODAL_DEFAULT_FOOTER = "<p>Tip: Click anywhere outside of this modal to close.</p>";
const MODAL_DEFAULT_CONFIRMATION_HEADER = "<h2>Are you sure?</h2>";
const MODAL_DEFAULT_CONFIRMATION_BODY = "";
const MODAL_DEFAULT_CONFIRMATION_FOOTER = MODAL_DEFAULT_FOOTER;
const LEVEL_ERROR = "error";
const LEVEL_WARNING = "warning";
const LEVEL_SUCCESS = "success";

var currentlyLoadedRule = null;

/////////////////////////////////// Dragula - drag 'n Drop //////////////////////////////////////////

dragula([
    // Enable drag and drop for these DIVs:
    document.getElementById(ELEMENT_OPERATORS),
    document.getElementById(ELEMENT_ARTIFACT_TYPES),
    document.getElementById(ELEMENT_ARTIFACTS),
    document.getElementById(ELEMENT_EDITOR)
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
let modal_ids = ["response-modal", "confirmation-modal"];
for (let i = 0; i < modal_ids.length; i++ ) {
    // Add modals by-id.
    modals.push(document.getElementById(modal_ids[i]));
    console.log("pushed: " + modal_ids[i]);

   // Add close logic.
   let closeCustomModal = document.getElementById(modal_ids[i] + "-close");//[i];

   // When the user clicks on <span> (x), close (hide) the modal
   document.getElementById(modal_ids[i] + "-close").onclick = function() {
     document.getElementById(modal_ids[i]).style.display = "none";
   };

   // When the user clicks anywhere outside of the modal, close it
    window.onclick = function (event) {
        for (let i = 0; i < modal_ids.length; i++) {
            if (event.target === document.getElementById(modal_ids[i])) {
                document.getElementById(modal_ids[i]).style.display = "none";
            }
        }
    };
}

/**
 * Convenience: Shortens the line width when getting a CSS variable.
 */
function getCSSVar(varName) {
    return getComputedStyle(document.documentElement).getPropertyValue('--' + varName);
}

/**
 * Shows a pop-up modal with customisable header, footer and body,
 * as well as background color based on level.
 *
 * level: String that is appended to CSS variables:
 *  - '-modal_background_*'
 *  - '-modal_color_*'
 */
function popupModal(modal_id=null, header=null, body=null, footer=null, level=null) {
    // Modal element itself.
    let modal = document.getElementById(modal_id);

    // Modal sub-elements.
    let modalHeader = document.getElementById(modal_id + "-header");
    let modalBody = document.getElementById(modal_id + "-body");
    let modalFooter = document.getElementById(modal_id + "-footer");

    // Set level (if null, set to info/default).
    level = (level != null) ? level : "info";
    console.log("level:" + level);

    // Set sub-element values, if given.
    modalHeader.innerHTML = (header != null) ? header: MODAL_DEFAULT_HEADER;
    modalBody.innerHTML  = (body != null) ? body : MODAL_DEFAULT_BODY;
    modalFooter.innerHTML = (footer != null) ? footer :  MODAL_DEFAULT_FOOTER;

    // Set custom style.
    //      Header.
    modalHeader.style.background = getCSSVar("modal_background_" + level);
    modalHeader.style.color = getCSSVar("modal_color_" + level);
    //      Footer.
    modalFooter.style.background = getCSSVar("modal_background_" + level);
    modalFooter.style.color = getCSSVar("modal_color_" + level);

    // Show modal.
    modal.style.display = "block";

    // Return the modal to be easily used by caller.
    return modal;
}

function popupWarningModal(header, body, footer=null) {
    let hdr = `<h2>Warning: ${header}</h2>`;
    let bdy = `<h3>${body}</h3>`;
    popupModal("response-modal", hdr, bdy, footer, "warning");
}

function popupErrorModal(header, body, footer=null) {
    let hdr = `<h2>Warning: ${header}</h2>`;
    let bdy = `<h3>${body}</h3>`;
    popupModal("response-modal", hdr, bdy, footer, "error");
}

/**
*   Adds Yes/No confirmation buttons to a custom modal and binds actions to them.
*/
function popupConfirmationModal(yesAction, noAction=undefined,
                                body=MODAL_DEFAULT_CONFIRMATION_BODY,
                                header=MODAL_DEFAULT_CONFIRMATION_HEADER,
                                footer=MODAL_DEFAULT_CONFIRMATION_FOOTER,
                                level=LEVEL_WARNING) {

    // Append bindable buttons to custom body.
    body += `<button id="confirmation-modal-button-yes-onclick" class="confirmation-modal-button-yes">Yes</button>`;
    body += `<button id="confirmation-modal-button-no-onclick" class="confirmation-modal-button-no">No</button>`;

    // Spawn modal.
    popupModal("confirmation-modal", header, body, footer, level);

    // Add bindings to buttons.
    document.getElementById("confirmation-modal-button-yes-onclick").onclick = function() {
        // Perform bound action (if defined).
        yesAction && yesAction();

        // Close modal.
        document.getElementById("confirmation-modal").style.display = "none";
    };
    document.getElementById("confirmation-modal-button-no-onclick").onclick = function() {
        // Perform bound action (if defined).
        noAction && noAction();

        // Close modal after handling button action.
        document.getElementById("confirmation-modal").style.display = "none";
    };
}

function popupHelpModal() {
    let header = "<h2>How To Use</h2>";
    let body =
            "<h4>Adding items</h4>" +
            "<p>Either click on or drag items from the left-pane to add them to the editor." + "<br/>" +
            "<i>NB: Drag and drop won't work until you've added at least one item to the editor.</i></p>" +
            // "<p></p>" +

            "<h4>Removing items</h4>" +
            "<p>Middle mouse-click on an item in the editor to remove it.</p>"+

            "<h4>Tags</h4>" +
            "<p>Check the checkboxes for which tags you want to include (if any).</p>";

    popupModal("response-modal", header, body, null, "info");

}

///////////////////////////////////// Core (designer) code ///////////////////////////////////

/**
 * Override default behaviour for mouse clicks in the editor div,
 * in order to support middle and right clicks.
 */
document.getElementById('yara_rule_designer_editor').addEventListener('auxclick', function(ev) {
  console.log(ev.button);
  // Prevent default action in order to implement our own.
  ev.preventDefault();

  // Handle aux click events.
  onAuxClick(ev);
});

function addToEditor(clickEvent) {
    let editorDiv = document.getElementById("yara_rule_designer_editor");

    // If target is already in the editor, ignore the click event.
    if (clickEvent.target.parentNode.getAttribute("id") === "yara_rule_designer_editor") {
        console.log("Ignored click event (target is child of editor div):");
        console.log(clickEvent);
        return
    }

    console.log('addToEditor: ' + $(clickEvent.target).text());
    editorDiv.appendChild(makeClone(clickEvent.target));
}

function removeFromEditor(clickEvent) {
    let editorDiv = document.getElementById("yara_rule_designer_editor");

    // Only perform remove action if target is a child of editor div.
    if (clickEvent.target.parentNode.getAttribute("id") === "yara_rule_designer_editor") {
        console.log("removeFromEditor: " + $(clickEvent.target).text());
        editorDiv.removeChild(clickEvent.target);
    }
}

function onAuxClick(auxClickEvent) {
    console.log("onAuxClick:");
    console.log(auxClickEvent);

    // Check which mouse button was pressed and act accordingly.
    switch (auxClickEvent.button) {
        case MIDDLE_CLICK:
            removeFromEditor(auxClickEvent);
            break;
        case RIGHT_CLICK:
            break;
    }
}

function getEditorContents() {
    return document.getElementById("yara_rule_designer_editor").children;
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
            console.error("getEditorConditionString is not supposed to reach an else condition!");
            console.error(children[i]);
        }
    }

    return conditionString;
}

function getEnabledTags() {
    let enabledTags= [];
    let tagCheckboxes = document.getElementsByClassName("yara-tag-checkbox");

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
    let yaraRuleName = `Whitelist_${yaraRule.data.title}`;
    let yaraMetaDescription = `Whitelist regler for alarmen: Whitelist_${yaraRule.data.title}`;

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
      coll[i].addEventListener("click", function() {
        this.classList.toggle("active");
        let content = this.nextElementSibling;
        if (content.style.display === "block") {
          content.style.display = "none";
        } else {
          content.style.display = "block";
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
        console.log(`fetchRequest succeeded with JSON response`, data);
        callback(data);
      }).catch(function(error) {
        console.log('Request failed', error);
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
          'Content-Type': 'application/json'
          // 'Content-Type': 'application/x-www-form-urlencoded',
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
function makeTable(id, headerContentMaps, className="custom-table") {
    // Header row:
    let headerColumns = "";
    // For key in arbitrary JSON (they all share the same keys).
    for (let key of Object.keys(headerContentMaps[0])) {
        headerColumns += `        <th id="${id}-header-${key}">${key}</th>\n`;
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

    let htmlTable =
        `<table id="${id}" class="${className}">\n` +
        `${headerRow}\n` +
        `${tableContents}` +
        `</table>`;

    return htmlTable;
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
            "": "",  // Intentionally left blank (to be filled with pending bar later).
            "Title": rule.data.title,
            "Sev": rule.data.severity,
            "<img src='/static/images/searchicon.png' title='Observables'>": rule.data.observables.length,
            "Added": rule.added_on !== null ? humanizeISODate(rule.added_on) : "N/A",
            "YARA File": rule.yara_filename !== undefined ? rule.yara_filename : "N/A",
            "Modified": rule.last_modified !== null ? humanizeISODate(rule.last_modified): "N/A",
            "ID": rule.data.id
        });
    }

    return headerContentMaps;
}

function filterFetchedRules() {

}

function printRulesTable(rules) {
    let body = "";
    let footer = "Tip: Click any row to load its corresponding rule.";
    let tableId = "fetched-rules";

    // Filter/Search
    body += `<input type="text" id="fetched-rules-input-filter" onkeyup="filterFetchedRules()" placeholder="Filter table..">`;
    body += "<br>";

    // Table
    let headerContentMaps = makeRuleTableRows(rules);
    body += makeTable(tableId, headerContentMaps);
    // console.log(body);

    popupModal("response-modal", "<h3>Fetched rules</h3>", body, footer, "info");

    // Apply actions to modal and table that couldn't be applied before it was spawned:
    // document.getElementById("response-modal").style.width = "100%";

    for (let i = 0; i < rules.length; i++) {
        // Add pending bar to rules that have never been designed.
        if (rules[i]["pending"] === true) {
            document.getElementById(`${tableId}-row-${i}-col-0`).style.backgroundColor = "#f4d03f";
        }

        // Add onclick action for each row to load the corresponding rule.
        document.getElementById(`${tableId}-row-${i}`).onclick = function() {
            loadRule(rules[i].data.id);
            document.getElementById("response-modal-footer").innerText =
                `Loaded rule: ${rules[i].data.title} [ID: ${rules[i].data.id}]`;
        };

        // Set pointer cursor in each row to indicate onclick presence.
        document.getElementById(`${tableId}-row-${i}`).style.cursor = "pointer";
    }
}

function loadRuleDialog() {
    getRules();
}

function setTitle(title, id, description=null) {
    document.getElementById('yara-designer-title').innerText = title;
    document.getElementById('yara_rule_designer_header').innerHTML =
        `<p> Case: ${title} [ID: ${id}] </p>`;
    document.getElementById('yara_rule_designer_header').innerHTML +=
        `<h6>${description}</h6>`;
}

function setTags(tags) {
    let html ="";
    for (let i = 0; i < tags.length; i++) {
        html += `<input type="checkbox" id="tagCheckbox${i}" class="yara-tag-checkbox" value="${tags[i]}">\n` +
                `<label for="tagCheckbox${i}" title="${tags[i]}">${tags[i]}</label>\n`;
                `<div class="w-100"></div>\n`;
    }
    document.getElementById('yara-rule-designer-tags').innerHTML = html;
}

function setObservableTypes(types) {
    let html = "";

    for (let i = 0; i < types.length; i++) {
        html +=
            `<span id='artifact_type${i}' class='draggable_artifact_type' onclick='addToEditor(event)'>${types[i]}</span>'`;
    }

    document.getElementById('yara_rule_designer_artifact_types').innerHTML = html;
}

function setObservableData(data) {
    let html = "";

    for (let i = 0; i < data.length; i++) {
        html +=
            `<span id='artifact${i}' class='draggable_artifact' onclick='addToEditor(event)'>${data[i]}</span>'`;
    }

    document.getElementById('yara_rule_designer_artifacts').innerHTML = html;
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
    console.log("Got rule", rule);

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

    let sourcePreprocessed = outJson["source (preprocessed)"];

    let yaraRuleSourceFile = outJson["generated_yara_source_file"];

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
    body += "<pre class='numbered_lines'>";
    for (let i = 0; i < lines.length; i++) {
        if (!success) {
            if (errorType === "syntax" && i === errorLineNumber-1) {
                // Color bad column or line.
                let stringUpToMark = lines[i].substring(0, errorColumnNumber -1);
                let stringToMark = lines[i].substring(errorColumnNumber -1, errorColumnRange - 1);
                let stringPastMark = lines[i].substring(errorColumnRange -1, lines[i].length);

                // FIXME: Debug (not sure it is quite over yet).
                // console.log("stringUpToMark: " + stringUpToMark);
                // console.log(`stringToMark: '${stringToMark}'`);
                // console.log("stringPastMark: " + stringPastMark);

                lines[i] = `${stringUpToMark}<mark class='red-bg'>${stringToMark}</mark>${stringPastMark}`;
            }
        }

        // Append line
        body += `<span>${lines[i]}</span>`;
    }
    body += "</pre>";

    // Add commit button if valid result.
    if (success) {
        body += `<button id="response-modal-button-commit-onclick" class="response-modal-button-commit">Commit & Push</button>`;
    } else {
        body += `<button id="response-modal-button-commit-onclick" class="response-modal-button-commit-disabled" disabled>Commit & Push</button>`;
    }

    // Collapsible raw JSON details.
    body +=
        "<button type='button' class='response-modal-json-collapsible-button'>Show JSON</button>" +
        "<div class='response-modal-json-collapsible-content'>" +
            "<pre>" +
                JSON.stringify(json, undefined, 4) +
            "</pre>" +
        "</div>";

    // Spawn modal.
    popupModal("response-modal", header, body, MODAL_DEFAULT_FOOTER, level);

    // Perform changes that requires a spawned modal:

    // Add bindings to buttons.
    document.getElementById("response-modal-button-commit-onclick").onclick = function() {
        // Perform bound action.
        let jsonToCommit = {};
        let yaraRule = window.currentlyLoadedRule;
        jsonToCommit["filepath"] = yaraRuleSourceFile;
        jsonToCommit["rulename"] = json["in"]["rule"]; // FIXME: Make backend send the proper sanitized rulename in "out" dict.
        jsonToCommit["case_id"] = yaraRule.data.id;

        postCommit(jsonToCommit);

        // Close modal after handling button action.
        document.getElementById("confirmation-modal").style.display = "none";
    };

    // Make the JSON detailsCollapsible element actually collapsible.
    addCaseDetailsCollapsibleButtonLogic("response-modal-json-collapsible-button");
}

/**
 * Make a custom POST request for non-form elements like DIV and SPAN.
 */
function postRule() {
    try {
        let json = getRuleJsonFromEditorElements();

        let xhr = new XMLHttpRequest();
        let postDesignedRuleUrl = $('#postDesignedRuleUrl').data().url;

        console.log("POST URL: " + postDesignedRuleUrl);

        xhr.open("POST", postDesignedRuleUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');

        // Add custom handling of the response returned by XHR POST URL.
        xhr.onreadystatechange = function () {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                handlePostRuleResponse(JSON.parse(xhr.responseText));
            }
        };

        // Convert a JavaScript value to a JavaScript Object Notation (JSON) string (Required for POST).
        xhr.send(JSON.stringify(json));
    } catch (e) {
        if (e.name === "NoContentsException") {
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

    let retv = "<pre class='numbered_lines'>";

    if (color) {
        for (let line of diffString.split('\n')) {
            if (line.startsWith("+")) {
                retv += `<span><mark class='green-text'>${line}</mark>\n</span>`
            } else if (line.startsWith("-")) {
                retv += `<span><mark class='red-text'>${line}</mark>\n</span>`
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
    let level = "success";

    // Parse JSON:
    let outJson = json["out"];

    // let compilable = outJson["compilable"];
    let success = outJson["success"];

    if (!success) {
        errorMessage = outJson["error"]["message"];
        errorType = outJson["error"]["type"];
        level = outJson["error"].hasOwnProperty("level") ? outJson["error"]["level"] : "error";

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
        "<button type='button' class='response-modal-json-collapsible-button'>Show JSON</button>" +
        "<div class='response-modal-json-collapsible-content'>" +
            "<pre>" +
                JSON.stringify(json, undefined, 4) +
            "</pre>" +
        "</div>";

    // Spawn modal.
    popupModal("response-modal", header, body, MODAL_DEFAULT_FOOTER, level);

    // Perform changes that requires a spawned modal:
    // Make the JSON detailsCollapsible element actually collapsible.
    addCaseDetailsCollapsibleButtonLogic("response-modal-json-collapsible-button");
}

/**
 * Make a custom POST request for non-form elements like DIV and SPAN.
 */
function postCommit(json) {
    let xhr = new XMLHttpRequest();
    let postCommitUrl = $('#postCommitUrl').data().url;

    console.log("POST URL: " + postCommitUrl);

    xhr.open("POST", postCommitUrl, true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    // Add custom handling of the response returned by XHR POST URL.
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            // Make sure to close any open modals.
            for ( let modalElement of document.getElementsByClassName("custom-modal") ) {
                if (modalElement.style.display !== "none") {
                    console.log("[postCommit] xhr.onreadystatechange: Closed open modal: " + modalElement.id);
                    modalElement.style.display = "none";
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
    let editorDiv = document.getElementById("yara_rule_designer_editor");
    editorDiv.textContent = '';
}

function clearRule() {
    // Define body
    let body = "<h3>Are you sure you want to clear the current rule? This is action is <em>irreversible</em>.</h3>";

    // yesAction, noAction, body, args...
    popupConfirmationModal(clearEditorDivContents, undefined, body);
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
let idParm = getParameterByName('id');

if (idParm !== null && idParm !== "") {
    console.log("Load rule: " + idParm);
    loadRule(idParm);
}