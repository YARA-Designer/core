// Global code
let themeParm = getParameterByName('theme');
let defaultThemePath = $('#theme').data().path;

function loadTheme(themeName, themePath=defaultThemePath) {
    const rootEl = document.querySelector(':root');

    let themeFile = themeName + ".json";
    let themeFilePath = themePath + themeFile;

    // Load corresponding theme JSON from file.
    console.log("Load theme: " + themeFilePath);
    $.getJSON(themeFilePath, function(json) {
        console.log(json); // this will show the info it in firebug console
        for (let key in json) {
            if (json.hasOwnProperty(key)) {
                console.log("setProperty(" + key + ", " + json[key] + ")");
                rootEl.style.setProperty(key, json[key]);
            }
        }

    });
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
if (themeParm !== null && themeParm !== "") {
    loadTheme(themeParm, $('#theme').data().path)
}