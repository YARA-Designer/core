## Requests
*  Compare YARA rules' similarity (particularly conditions) - backend component.
*  Customisable metadata fields (user input @ frontend).

## Other
*  Rename post_rule_json and post_commit_json far more sensibly / unambiguously.
*  Rename all instances of "artifacts" to "observables" for less confusion..
* Rename retv dict to be attribute compatible (no fancy characters).
* Look into merging (responder's) listener webserver code into handlers.webserver.
* Get a WSGI production server when deploying to production:
    * https://stackoverflow.com/questions/51025893/flask-at-first-run-do-not-use-the-development-server-in-a-production-environmen
    * https://flask.palletsprojects.com/en/1.1.x/tutorial/deploy/
* Fix handling of offline git server.

## Bugs