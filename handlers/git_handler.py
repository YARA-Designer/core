import os
from pathlib import Path

import git as gitpy
from git import Repo, Remote
from git.objects import Blob, Commit, TagObject, Tree, Submodule
from git.util import Actor

from handlers.config_handler import load_config
from handlers.log_handler import create_logger

log = create_logger(__name__)


def is_repo(path):
    """
    Checks if a given path is a Git repository.

    :param path:    Path to possible git repository.
    :return:        Boolean.
    """
    try:
        _ = gitpy.Repo(path).git_dir
        return True
    except gitpy.exc.InvalidGitRepositoryError:
        return False


def get_repo_dir(repo: Repo, strict=True) -> str:
    return str(Path(repo.git_dir).parent.resolve(strict=strict))


def get_or_init_repo(path: str) -> gitpy.Repo:
    """
    Gets a Git repo, if one doesn't already exist inits one and returns that.

    :param path:    Path to git repository.
    :return:        git.Repo object.
    """
    # Git init, if not already a repository.
    if is_repo(path):
        # An existing repo as a base.
        log.info("'{}' is already a Git repository, skipping init.".format(path))
        return gitpy.Repo(path)
    else:
        # An empty repo as a base.
        log.info("Initializing Git repository: '{}'.".format(path))
        return gitpy.Repo.init(path)


def add_remote(remote_name: str, repo: gitpy.Repo, url: str) -> gitpy.Remote:
    """
    Adds a remote to a Git repository.

    :param remote_name: Name of remote.
    :param repo:        git.Repo object.
    :param url:         URL to remote Git repository.
    :return:            git.Remote object.
    """
    log.info("Create remote '{}' with URL: {}".format(remote_name, url))
    remote = repo.create_remote(remote_name, url)
    log.info("Added remote '{}' URL: {}".format(remote_name, repo.remotes.origin.url))
    log.debug("repo.remotes.{}: {}".format(repo.remotes[remote_name], remote_name))

    # Make sure we actually have data.
    assert remote.exists()
    assert remote == repo.remotes[remote_name]

    # Required for Repo.create_head, else 'IterableList' object has no attribute 'origin/master'.
    log.info("Fetching data from remote '{}'...".format(remote_name))
    remote.fetch()

    # Setup a local tracking branch of a remote branch:
    log.info("Setup local tracking branch of remote '{}' branch.".format(remote_name))

    log.info("Create local branch 'master' from remote '{}/master'.".format(remote_name))
    repo.create_head('master', remote.refs.master)

    log.info("Set local 'master' to track remote '{}/master'.".format(remote_name))
    repo.heads.master.set_tracking_branch(remote.refs.master)

    log.info("Checkout local 'master' to working tree.")
    repo.heads.master.checkout()

    return remote


def pull(remote: gitpy.Remote):
    """
    Performs a Git pull from a given remote repository.

    :param remote:  git.Remote object.
    :return:
    """
    log.info("Pulling data from remote '{}'...".format(remote))
    remote.pull()


def clone_if_not_exist(url: str, path: str) -> gitpy.Repo:
    """
    Sets up and clones a Git repository of Repo and/or remote "origin" does not exist,
    else it performs a Git pull on an existing one.

    :param url:         URL to remote Git repository.
    :param path:        Path to Git repository.
    :return:            Cloned git.Repo object.
    """
    # Make sure destination exists.
    if not os.path.isdir(path):
        os.mkdir(path)

    # Git init, if not already a repository. Else get existing repo.
    repo = get_or_init_repo(path)

    # Add remote origin, only if it does not already exist.
    if "origin" not in repo.remotes:
        origin = add_remote("origin", repo, url)
    else:
        origin = repo.remotes.origin

    # Pull data from remote origin.
    pull(origin)

    return repo
