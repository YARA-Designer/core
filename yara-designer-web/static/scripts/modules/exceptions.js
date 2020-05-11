const NO_CONTENTS_EXCEPTION = "NoContentsException";

// Exceptions
function NoContentsException(message) {
    this.message = message;
    this.name = NO_CONTENTS_EXCEPTION;
}