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