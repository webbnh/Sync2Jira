#!/usr/bin/env python3
# This file is part of sync2jira.
# Copyright (C) 2016 Red Hat, Inc.
#
# sync2jira is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# sync2jira is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with sync2jira; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110.15.0 USA
#
# Authors:  Ralph Bean <rbean@redhat.com>
""" Sync GitHub issues to a jira instance, via fedmsg.

Run with systemd, please.
"""
# Python Standard Library Modules
from copy import deepcopy
from datetime import datetime, timezone
import logging
import os
import requests
from time import sleep
import traceback
import warnings

# 3rd Party Modules
import fedmsg
import fedmsg.config
import jinja2
from requests_kerberos import HTTPKerberosAuth, OPTIONAL

# Local Modules
import sync2jira.upstream_issue as u_issue
import sync2jira.upstream_pr as u_pr
import sync2jira.downstream_issue as d_issue
import sync2jira.downstream_pr as d_pr
from sync2jira.mailer import send_mail
from sync2jira.intermediary import matcher

# Set up our logging
FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logging.basicConfig(format=FORMAT, level=logging.WARNING)
log = logging.getLogger('sync2jira')

# Only allow fedmsg logs that are critical
fedmsg_log = logging.getLogger('fedmsg.crypto.utils')
fedmsg_log.setLevel(50)

remote_link_title = "Upstream issue"
failure_email_subject = "Sync2Jira Has Failed!"

# Issue related handlers
issue_handlers = {
    # GitHub
    'github.issue.opened': u_issue.handle_github_message,
    'github.issue.reopened': u_issue.handle_github_message,
    'github.issue.labeled': u_issue.handle_github_message,
    'github.issue.assigned': u_issue.handle_github_message,
    'github.issue.unassigned': u_issue.handle_github_message,
    'github.issue.closed': u_issue.handle_github_message,
    'github.issue.comment': u_issue.handle_github_message,
    'github.issue.unlabeled': u_issue.handle_github_message,
    'github.issue.milestoned': u_issue.handle_github_message,
    'github.issue.demilestoned': u_issue.handle_github_message,
    'github.issue.edited': u_issue.handle_github_message,
}

# PR related handlers
pr_handlers = {
    # GitHub
    'github.pull_request.opened': u_pr.handle_github_message,
    'github.pull_request.edited': u_pr.handle_github_message,
    'github.issue.comment': u_pr.handle_github_message,
    'github.pull_request.reopened': u_pr.handle_github_message,
    'github.pull_request.closed': u_pr.handle_github_message,
}
DATAGREPPER_URL = "http://apps.fedoraproject.org/datagrepper/raw"
INITIALIZE = os.getenv('INITIALIZE', '0')
GITHUB_API = 'https://api.github.com/graphql'
GHP_LAST_UPDATE = os.getenv('SYNC2JIRA_LAST_UPDATE', '')


def load_config(loader=fedmsg.config.load_config):
    """
    Generates and validates the config file \
    that will be used by fedmsg and JIRA client.

    :param Function loader: Function to set up runtime config
    :returns: The config dict to be used later in the program
    :rtype: Dict
    """
    config = loader()

    # Force some vars that we like
    config['mute'] = True

    # debug mode
    if config.get('sync2jira', {}).get('debug', False):
        handler = logging.FileHandler('sync2jira_main.log')
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)

    # Validate it
    if 'sync2jira' not in config:
        raise ValueError("No sync2jira section found in fedmsg.d/ config")

    if 'map' not in config['sync2jira']:
        raise ValueError("No sync2jira.map section found in fedmsg.d/ config")

    possible = {'github', 'github_projects'}
    specified = set(config['sync2jira']['map'].keys())
    if not specified.issubset(possible):
        raise ValueError(f"Specified handlers: {specified}, must be a subset of {possible}.")

    if 'jira' not in config['sync2jira']:
        raise ValueError("No sync2jira.jira section found in fedmsg.d/ config")

    # Provide some default values
    defaults = {
        'listen': True,
    }
    for key, value in defaults.items():
        if key not in config['sync2jira']:
            config['sync2jira'][key] = value

    return config


def listen(config):
    """
    Listens to activity on upstream repos on GitHub
    via fedmsg, and syncs new issues there to the JIRA instance
    defined in 'fedmsg.d/sync2jira.py'

    :param Dict config: Config dict
    :returns: Nothing
    """
    if not config['sync2jira'].get('listen'):
        log.info("`listen` is disabled.  Exiting.")
        return

    log.info("Waiting for a relevant fedmsg message to arrive...")
    for _, _, topic, msg in fedmsg.tail_messages(**config):
        idx = msg['msg_id']
        suffix = ".".join(topic.split('.')[3:])
        log.debug("Encountered %r %r %r", suffix, topic, idx)

        if suffix not in issue_handlers and suffix not in pr_handlers:
            continue

        log.debug("Handling %r %r %r", suffix, topic, idx)

        handle_msg(msg, suffix, config)


def initialize_issues(config, testing=False, repo_name=None):
    """
    Initial initialization needed to sync any upstream
    repo with JIRA. Goes through all issues and
    checks if they're already on JIRA / Need to be
    created.

    :param Dict config: Config dict for JIRA
    :param Bool testing: Flag to indicate if we are testing. Default false
    :param String repo_name: Optional individual repo name. If defined we will only sync the provided repo
    :returns: Nothing
    """
    log.info("Running initialization to sync all issues from upstream to jira")
    log.info("Testing flag is %r", config['sync2jira']['testing'])
    mapping = config['sync2jira']['map']
    for upstream in mapping.get('github', {}).keys():
        if 'issue' not in mapping.get('github', {}).get(upstream, {}).get('sync', []):
            continue
        if repo_name is not None and upstream != repo_name:
            continue
        # Try and except for GitHub API limit
        try:
            for issue in u_issue.github_issues(upstream, config):
                try:
                    d_issue.sync_with_jira(issue, config)
                except Exception:
                    log.error("   Failed on %r", issue)
                    raise
        except Exception as e:
            if "API rate limit exceeded" in e.__str__():
                # If we've hit our API limit, sleep for 1 hour, and call our
                # function again.
                log.info("Hit Github API limit. Sleeping for 1 hour...")
                sleep(3600)
                if not testing:
                    initialize_issues(config)
                return
            else:
                if not config['sync2jira']['develop']:
                    # Only send the failure email if we are not developing
                    report_failure(config)
                    raise
    log.info("Done with GitHub issue initialization.")


def initialize_pr(config, testing=False, repo_name=None):
    """
    Initial initialization needed to sync any upstream
    repo with JIRA. Goes through all PRs and
    checks if they're already on JIRA / Need to be
    created.

    :param Dict config: Config dict for JIRA
    :param Bool testing: Flag to indicate if we are testing. Default false
    :param String repo_name: Optional individual repo name. If defined we will only sync the provided repo
    :returns: Nothing
    """
    log.info("Running initialization to sync all PRs from upstream to jira")
    log.info("Testing flag is %r", config['sync2jira']['testing'])
    mapping = config['sync2jira']['map']
    for upstream in mapping.get('github', {}).keys():
        if 'pullrequest' not in mapping.get('github', {}).get(upstream, {}).get('sync', []):
            continue
        if repo_name is not None and upstream != repo_name:
            continue
        # Try and except for GitHub API limit
        try:
            for pr in u_pr.github_prs(upstream, config):
                try:
                    if pr:
                        d_pr.sync_with_jira(pr, config)
                except Exception:
                    log.error("   Failed on %r", pr)
                    raise
        except Exception as e:
            if "API rate limit exceeded" in e.__str__():
                # If we've hit our API limit, sleep for 1 hour, and call our
                # function again.
                log.info("Hit Github API limit. Sleeping for 1 hour...")
                sleep(3600)
                if not testing:
                    initialize_pr(config)
                return
            else:
                if not config['sync2jira']['develop']:
                    # Only send the failure email if we are not developing
                    report_failure(config)
                    raise
    log.info("Done with GitHub PR initialization.")


def initialize_github_project(timestamp, config):
    """
    Pull changes since the last update directly from a GitHub Project

    :param str timestamp: last update time in YYYY-MM-DDTHH:MM:SSZ format
    :param Dict config: Config dict
    :return: Nothing
    """

    gh_token = config['sync2jira'].get('github_token')
    if not gh_token:
        gh_token = os.getenv('SYNC2JIRA_GITHUB_TOKEN', '')

    # For each project in the configuration map
    for org_name, org in config['sync2jira']['map'].get('github_projects', {}).items():
        # Query GitHub, loop over the resulting issues, and sync them with Jira.
        for entry in query_ghp(org_name, org['github_project_number'], timestamp, gh_token):
            log.debug("Handling %s Issue #%s", entry['repository']['nameWithOwner'], entry['number'])
            issue = u_issue.handle_gh_project_message(entry, org_name, config)
            d_issue.sync_with_jira(issue, config)


gql_query = '''
    query ($ORGANIZATION: String!, $PROJECT_NUMBER: Int!, $CURSOR: String!) {
        organization(login: $ORGANIZATION) {
            projectV2(number: $PROJECT_NUMBER) {
                updatedAt
                title
                items(first: 100, after: $CURSOR) {
                    totalCount
                    nodes {
                        content {
                            ... on Issue {
                                __typename
                                updatedAt
                                state
                                title
                                id
                                url
                                body
                                repository {
                                    ...RepoInfo
                                }
                                number
                                assignees(first: 4) {
                                    totalCount
                                    nodes {
                                        ...UserInfo
                                    }
                                }
                                author {
                                    ...UserInfo
                                }
                                comments(first: 50) {
                                    totalCount
                                    nodes {
                                        updatedAt
                                        author {
                                            ...UserInfo
                                        }
                                        body
                                        id
                                        createdAt
                                    }
                                }
                                closed
                                milestone {
                                    updatedAt
                                    title
                                    description
                                    state
                                    dueOn
                                    number
                                }
                                projectItems(first: 8) {
                                    totalCount
                                    nodes {
                                        updatedAt
                                        fieldValues(first: 18) {
                                            totalCount
                                            nodes {
                                                __typename
                                                ... on ProjectV2ItemFieldValueCommon {
                                                    updatedAt
                                                    field {
                                                        ... on ProjectV2FieldCommon {
                                                            name
                                                        }
                                                    }
                                                }
                                                ... on ProjectV2ItemFieldDateValue {
                                                    date
                                                }
                                                ... on ProjectV2ItemFieldIterationValue {
                                                    duration
                                                    startDate
                                                    title
                                                }
                                                ... on ProjectV2ItemFieldSingleSelectValue {
                                                    name
                                                }
                                                ... on ProjectV2ItemFieldTextValue {
                                                    text
                                                }
                                                ... on ProjectV2ItemFieldNumberValue {
                                                    number
                                                }
                                                ... on ProjectV2ItemFieldUserValue {
                                                    field {
                                                        ... on ProjectV2FieldCommon {
                                                            name
                                                        }
                                                    }
                                                    users(first: 1) {
                                                        totalCount
                                                        nodes {
                                                            ...UserInfo
                                                        }
                                                    }
                                                }
                                                ... on ProjectV2ItemFieldRepositoryValue {
                                                    field {
                                                        ... on ProjectV2FieldCommon {
                                                            name
                                                        }
                                                    }
                                                    repository {
                                                        ...RepoInfo
                                                    }
                                                }
                                                ... on ProjectV2ItemFieldLabelValue {
                                                    field {
                                                        ... on ProjectV2FieldCommon {
                                                            name
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        project {
                                            number
                                            owner {
                                                ... on Organization {
                                                    login
                                                }
                                            }
                                        }
                                    }
                                }
                                labels(first: 16) {
                                    totalCount
                                    nodes {
                                        updatedAt
                                        name
                                    }
                                }
                                closedByPullRequestsReferences(includeClosedPrs: true, first: 6) {
                                    totalCount
                                    nodes {
                                        ...PullRequestInfo
                                    }
                                }
                            }
                        }
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }
        }
        rateLimit(dryRun: false) {
            cost
            limit
            nodeCount
            remaining
            resetAt
            used
        }
    }

    fragment UserInfo on User {
        updatedAt
        name
        login
        email
    }

    fragment RepoInfo on Repository {
        updatedAt
        nameWithOwner
        shortDescriptionHTML
    }

    fragment PullRequestInfo on PullRequest {
        updatedAt
        title
        PRState: state
        baseRef {
            repository {
                ...RepoInfo
            }
        }
        repository {
            ...RepoInfo
        }
        number
        body
        assignees(first: 4) {
            totalCount
            nodes {
                ...UserInfo
            }
        }
        author {
            ...UserInfo
        }
        projectCards(first: 8) {
            totalCount
            nodes {
                state
                note
            }
        }
    }'''


def query_ghp(organization, project_number, timestamp, gh_token):
    """A generator which yields the `content` of each node in a GitHub project V2 item list"""
    has_next_page = True
    cursor = ""
    # TODO:
    #  - Add high-water-marking for `totalCount` values;
    #  - Add average items per query (seeking a lower projectV2.items max to lower overall cost points)
    queries = 0
    server_side_skipped = 0
    no_new_updates = 0
    updates = 0
    while has_next_page:
        log.debug("Querying GitHub API for %s/%s (cursor '%s')", organization, project_number, cursor)
        response = requests.post(
            url=GITHUB_API,
            json={
                'query': gql_query,
                'variables': {
                    'ORGANIZATION': organization,
                    'PROJECT_NUMBER': project_number,
                    'CURSOR': cursor,
                    # TODO: Add variable for projectV2.items.first value
                },
            },
            headers={'Authorization': 'Bearer ' + gh_token},
            allow_redirects=True,
        )
        if response.status_code != 200:
            log.warning("GitHub API error accessing %s/%s: %s",
                        organization, project_number, response.text)
            break

        data = response.json()
        errors = data.get('errors', [])
        if errors:
            if any(e.get('type') == 'RATE_LIMITED' for e in errors):
                reset_timestamp = int(response.headers['X-RateLimit-Reset'])
                reset_time = datetime.fromtimestamp(reset_timestamp, timezone.utc)
                log.warning(
                    "GitHub API rate limit exceeded, blocked until %s; waiting.",
                    reset_time)
                delay = reset_time - datetime.now(timezone.utc)
                sleep(delay.total_seconds() + 60)  # An extra minute to cover clock-skew
                log.info('Retrying GitHub')
                continue  # Retry with the same cursor
            log.warning(
                "GitHub API error accessing %s/%s: %s",
                organization, project_number, '; '.join(e['message'] for e in errors))
            break

        items = data['data']['organization']['projectV2']['items']
        log.debug(
            "Received %s items (%s rate limit points remaining until %s)",
            len(items['nodes']),
            response.headers['X-Ratelimit-Remaining'],
            datetime.fromtimestamp(int(response.headers['X-RateLimit-Reset']),
                                   timezone.utc))
        for item in items['nodes']:
            content = item['content']
            if not content:
                # Items which are filtered out on the server side show up as
                # empty entries in the response.
                server_side_skipped += 1
                continue

            verify_content_lists(content)

            # Remove backlinks from other projects; there should be no more
            # than one.  Note that, somehow, we sometimes have issues with _no_
            # project backlink...I'm not sure how that can happen, given that
            # we start from a project to get here, but....
            # (Note:  we must be very careful iterating over an enumerated list
            # as we delete items from it!)
            proj_items = content['projectItems']['nodes']
            if len(proj_items) == 0:
                log.debug("Issue %s found without backlink from %s/%s",
                          content['url'], organization, project_number)
            idx = 0
            while idx < len(proj_items):
                if (proj_items[idx]['project']['number'] != project_number
                        or proj_items[idx]['project']['owner']['login'] != organization):
                    # If this item is for a project which is not the one that
                    # we requested, remove the entry.  (Note that this shortens
                    # the list and moves a new entry into the _current_ index.)
                    del proj_items[idx]
                else:
                    idx += 1
            assert len(proj_items) <= 1

            # Skip items which we've already done in a previous run; we have to
            # check both the issue itself and the information maintained about
            # it in the project, if there is an associated project.
            if ((not proj_items or proj_items[0]['updatedAt'] < timestamp)
                    and content['updatedAt'] < timestamp):
                sanity_check_dates(content)
                no_new_updates += 1
                continue

            updates += 1
            yield content

        page_info = items['pageInfo']
        has_next_page = page_info['hasNextPage']
        cursor = page_info['endCursor']
        queries += 1

    log.info("%s/%s:  %d queries, %d issues with new updates, %d with no updates, %d server-side filtered",
             organization, project_number, queries, updates, no_new_updates, server_side_skipped)


def verify_content_lists(content):
    """Helper function which verifies that we received all of the list entries
    that we were supposed to get.

    If the 'totalCount' value is not equal to the length received, then we need
    to increase the request limit (which makes the query expensive) or add
    pagination (which also subjects us to the rate limit cap).

    :param Dict content: the Issue content
    :return: Nothing
    """
    assert content['assignees']['totalCount'] == len(content['assignees']['nodes'])
    assert content['comments']['totalCount'] == len(content['comments']['nodes'])
    assert content['projectItems']['totalCount'] == len(content['projectItems']['nodes'])
    for fields in (pi['fieldValues'] for pi in content['projectItems']['nodes']):
        assert fields['totalCount'] == len(fields['nodes'])
        if 'users' in fields:
            usr = fields['users']
            assert usr['totalCount'] == len(usr['nodes'])
    assert content['labels']['totalCount'] == len(content['labels']['nodes'])
    cpr = content['closedByPullRequestsReferences']
    assert cpr['totalCount'] == len(cpr['nodes'])
    for prs in cpr['nodes']:
        assert prs['assignees']['totalCount'] == len(prs['assignees']['nodes'])
        assert prs['projectCards']['totalCount'] == len(prs['projectCards']['nodes'])


def sanity_check_dates(content):
    """Helper function which performs some sanity checks on the content, to
    make sure that we're not skipping something unexpectedly.

    TODO:  This code should probably be removed once we are comfortable with
           GitHub's GraphQL API.

    :param Dict content: the Issue content
    :return: Nothing
    """
    for comment in content['comments']['nodes']:
        assert comment['updatedAt'] <= content['updatedAt']
    proj_nodes = content['projectItems']['nodes']
    assert len(proj_nodes) <= 1
    field_nodes = proj_nodes[0]['fieldValues']['nodes'] if proj_nodes else []
    for node in field_nodes:
        updated_at = node.get('updatedAt')
        assert updated_at is None or updated_at <= proj_nodes[0]['updatedAt']


def initialize_recent(config):
    """
    Initializes based on the recent history of datagrepper

    :param Dict config: Config dict
    :return: Nothing
    """
    # Query datagrepper
    ret = query(category=['github'], delta=int(600), rows_per_page=100)

    # Loop and sync
    for entry in ret:
        # Extract our topic
        suffix = ".".join(entry['topic'].split('.')[3:])
        log.debug("Encountered %r %r", suffix, entry['topic'])

        # Disregard if it's invalid
        if suffix not in issue_handlers and suffix not in pr_handlers:
            continue

        # Deal with the message
        log.debug("Handling %r %r", suffix, entry['topic'])
        msg = entry['msg']
        handle_msg({'msg': msg}, suffix, config)


def handle_msg(msg, suffix, config):
    """
    Function to handle incoming message from datagrepper
    :param Dict msg: Incoming message
    :param String suffix: Incoming suffix
    :param Dict config: Config dict
    """
    issue = None
    pr = None
    # GitHub '.issue.' is used for both PR and Issue
    # Check for that edge case
    if suffix == 'github.issue.comment':
        if 'pull_request' in msg['msg']['issue'] and msg['msg']['action'] != 'deleted':
            # pr_filter turns on/off the filtering of PRs
            pr = issue_handlers[suffix](msg, config, pr_filter=False)
            if not pr:
                return
            # Issues do not have suffix and reporter needs to be reformatted
            pr.suffix = suffix
            pr.reporter = pr.reporter.get('fullname')
            setattr(pr, 'match', matcher(pr.content, pr.comments))
        else:
            issue = issue_handlers[suffix](msg, config)
    elif suffix in issue_handlers:
        issue = issue_handlers[suffix](msg, config)
    elif suffix in pr_handlers:
        pr = pr_handlers[suffix](msg, config, suffix)

    if not issue and not pr:
        return
    if issue:
        d_issue.sync_with_jira(issue, config)
    elif pr:
        d_pr.sync_with_jira(pr, config)


def query(limit=None, **kwargs):
    """
    Run query on Datagrepper

    Args:
        limit: the max number of messages to fetch at a time
        kwargs: keyword arguments to build request parameters
    """
    # Pack up the kwargs into a parameter list for request
    params = deepcopy(kwargs)

    # Important to set ASC order when paging to avoid duplicates
    params['order'] = 'asc'

    # Fetch results:
    #  - once, if limit is 0 or None (the default)
    #  - until we hit the limit
    #  - until there are no more left to fetch
    fetched = 0
    total = limit or 1
    while fetched < total:
        results = get(params=params)
        count = results['count']

        # Exit the loop if there was nothing to fetch
        if count <= 0:
            break

        fetched += count
        for result in results['raw_messages']:
            yield result

        params['page'] = params.get('page', 1) + 1


def get(params):
    url = DATAGREPPER_URL
    headers = {'Accept': 'application/json', }

    response = requests.get(url=url, params=params, headers=headers,
                            auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL))
    return response.json()


def main(runtime_test=False, runtime_config=None):
    """
    Main function to check for initial sync
    and listen for fedmsgs.

    :param Bool runtime_test: Flag to indicate if we are performing a runtime test. Default false
    :param Dict runtime_config: Config file to be used if it is a runtime test. runtime_test must be true
    :return: Nothing
    """
    # Load config and disable warnings
    config = runtime_config if runtime_test and runtime_config else load_config()

    logging.basicConfig(level=logging.INFO)
    warnings.simplefilter("ignore")
    config['validate_signatures'] = False

    try:
        if str(INITIALIZE) == '1':
            log.info("Initialization True")
            # Initialize issues
            log.info("Initializing Issues...")
            initialize_issues(config)
            log.info("Initializing PRs...")
            initialize_pr(config)
            if runtime_test:
                return
        elif GHP_LAST_UPDATE:
            # Pull directly from a GitHub Project
            log.info("Initialization False. Pulling data since %s from GitHub Projects...", GHP_LAST_UPDATE)
            initialize_github_project(GHP_LAST_UPDATE, config)
        else:
            # Pull from datagrepper for the last 10 minutes
            log.info("Initialization False. Pulling data from datagrepper...")
            initialize_recent(config)
        try:
            listen(config)
        except KeyboardInterrupt:
            pass
    except:  # noqa: E722
        if not config['sync2jira']['develop']:
            # Only send the failure email if we are not developing
            report_failure(config)
        raise


def report_failure(config):
    """
    Helper function to alert admins in case of failure.

    :param Dict config: Config dict for JIRA
    """
    # Email our admins with the traceback
    template_loader = jinja2.FileSystemLoader(
        searchpath='usr/local/src/sync2jira/sync2jira/')
    template_env = jinja2.Environment(loader=template_loader, autoescape=True)
    template = template_env.get_template('failure_template.jinja')
    html_text = template.render(traceback=traceback.format_exc())

    # Send mail
    send_mail(recipients=[config['sync2jira']['mailing-list']],
              cc=None,
              subject=failure_email_subject,
              text=html_text)


def list_managed():
    """
    Function to list URL for issues under map in config.

    :return: Nothing
    """
    config = load_config()
    mapping = config['sync2jira']['map']
    warnings.simplefilter("ignore")

    for upstream in mapping.get('github', {}).keys():
        for issue in u_issue.github_issues(upstream, config):
            print(issue.url)


def close_duplicates():
    """
    Function to close duplicate functions. Uses downstream:close_duplicates.

    :return: Nothing
    """
    config = load_config()
    logging.basicConfig(level=logging.INFO)
    log.info("Testing flag is %r", config['sync2jira']['testing'])
    mapping = config['sync2jira']['map']
    warnings.simplefilter("ignore")

    for upstream in mapping.get('github', {}).keys():
        for issue in u_issue.github_issues(upstream, config):
            try:
                d_issue.close_duplicates(issue, config)
            except Exception:
                log.error("Failed on %r", issue)
                raise
    log.info("Done with GitHub duplicates.")


if __name__ == '__main__':
    main()
