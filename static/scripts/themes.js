// extend jQuery with this tiny convenience to allow for simple existence tests.
$.fn.exists = function () {
    return this.length !== 0;
};

function loadTheme(themeName, themePath) {
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

let themeArg = $('#themeArg');

if (themeArg.exists()) {
    loadTheme(themeArg.data().name, themeArg.data().path)
}