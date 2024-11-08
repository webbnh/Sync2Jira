import unittest
import unittest.mock as mock
from unittest.mock import MagicMock
from copy import deepcopy
from typing import Union, Optional

import sync2jira.main as m

PATH = 'sync2jira.main.'
CONFIG_ENTRY = dict[str, dict[
    str, Union[str, bool, list, dict[str, dict[str, Union[str, dict[str, Union[str, int, list[dict[str, str]]]]]]]]]]
ISSUE_ENTRY = dict[str, Union[str, int, dict[str, list[dict[str, Union[str, dict[str, list[dict[str, str]]]]]]],
    list[dict[str, Union[Optional[str], list[dict[str, str]]]]]]]
PR_ENTRY = ISSUE_ENTRY


class TestMain(unittest.TestCase):
    """
    This class tests the main.py file under sync2jira
    """

    def setUp(self):
        """
        Set up the testing environment
        """
        # Mock Config dict
        self.mock_config: CONFIG_ENTRY = {
            'sync2jira': {
                'jira': {
                    'mock_jira_instance': {'mock_jira': 'mock_jira'}
                },
                'testing': {},
                'legacy_matching': False,
                'map': {
                    'github': {'key_github': {'sync': ['issue', 'pullrequest']}}
                },
                'initialize': True,
                'listen': True,
                'develop': False,
            },
        }

        # Mock Fedmsg Message
        self.mock_message = {
            'msg_id': 'mock_id',
            'msg': {'issue': 'mock_issue'}
        }

    def _check_for_exception(self, loader, target, exc=ValueError):
        try:
            m.load_config(loader)
            self.fail('No exception raised where expected.')
        except exc as e:
            self.assertIsInstance(e, exc)
            self.assertIn(target, repr(e))

    def test_config_validate_empty(self):
        loader = lambda: {}
        self._check_for_exception(loader, 'No sync2jira section')

    def test_config_validate_missing_map(self):
        loader = lambda: {'sync2jira': {}}
        self._check_for_exception(loader, 'No sync2jira.map section')

    def test_config_validate_misspelled_mappings(self):
        loader = lambda: {'sync2jira': {'map': {'githob': {}}}, 'jira': {}}
        self._check_for_exception(loader, "Specified handlers: {'githob'}, must")

    def test_config_validate_missing_jira(self):
        loader = lambda: {'sync2jira': {'map': {'github': {}}}}
        self._check_for_exception(loader, 'No sync2jira.jira section')

    def test_config_validate_all_good(self):
        loader = lambda: {'sync2jira': {'map': {'github': {}}, 'jira': {}}}
        m.load_config(loader)  # Should succeed without an exception.

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    @mock.patch(PATH + 'load_config')
    def test_close_duplicates(self,
                              mock_load_config,
                              mock_d,
                              mock_u):
        """
        This tests the 'close_duplicates' function where everything goes smoothly
        """
        # Set up return values
        mock_load_config.return_value = self.mock_config
        mock_u.github_issues.return_value = ['mock_issue_github']

        # Call the function
        m.close_duplicates()

        # Assert everything was called correctly
        mock_load_config.assert_called_once()
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.close_duplicates.assert_any_call('mock_issue_github', self.mock_config)

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    @mock.patch(PATH + 'load_config')
    def test_close_duplicates_errors(self, mock_load_config, mock_d, mock_u):
        """
        This tests the 'close_duplicates' function where closing duplicates raises an exception
        """
        # Set up return values
        mock_load_config.return_value = self.mock_config
        mock_u.github_issues.return_value = ['mock_issue']
        mock_d.close_duplicates.side_effect = Exception()

        # Call the function
        with self.assertRaises(Exception):
            m.close_duplicates()

        # Assert everything was called correctly
        mock_load_config.assert_called_once()
        mock_u.github_issues.assert_called_once()
        mock_d.close_duplicates.assert_called_with('mock_issue', self.mock_config)

    @mock.patch(PATH + 'load_config')
    @mock.patch(PATH + 'u_issue')
    def test_list_managed(self,
                          mock_u,
                          mock_load_config):
        """
        This tests the 'list_managed' function
        """
        # Set up return values
        mock_load_config.return_value = self.mock_config

        # Call the function
        m.list_managed()

        # Assert everything was called correctly
        mock_load_config.assert_called_once()
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)

    @mock.patch(PATH + 'initialize_recent')
    @mock.patch(PATH + 'report_failure')
    @mock.patch(PATH + 'INITIALIZE', 1)
    @mock.patch(PATH + 'initialize_issues')
    @mock.patch(PATH + 'initialize_pr')
    @mock.patch(PATH + 'load_config')
    @mock.patch(PATH + 'listen')
    def test_main_initialize(self,
                             mock_listen,
                             mock_load_config,
                             mock_initialize_pr,
                             mock_initialize_issues,
                             mock_report_failure,
                             mock_initialize_recent):
        """
        This tests the 'main' function
        """
        # Set up return values
        mock_load_config.return_value = self.mock_config

        # Call the function
        m.main()

        # Assert everything was called correctly
        mock_load_config.assert_called_once()
        mock_listen.assert_called_with(self.mock_config)
        mock_listen.assert_called_with(self.mock_config)
        mock_initialize_issues.assert_called_with(self.mock_config)
        mock_initialize_pr.assert_called_with(self.mock_config)
        mock_report_failure.assert_not_called()
        mock_initialize_recent.assert_not_called()

    @mock.patch(PATH + 'initialize_recent')
    @mock.patch(PATH + 'report_failure')
    @mock.patch(PATH + 'INITIALIZE', 0)
    @mock.patch(PATH + 'initialize_issues')
    @mock.patch(PATH + 'initialize_pr')
    @mock.patch(PATH + 'load_config')
    @mock.patch(PATH + 'listen')
    def test_main_no_initialize(self,
                                mock_listen,
                                mock_load_config,
                                mock_initialize_pr,
                                mock_initialize_issues,
                                mock_report_failure,
                                mock_initialize_recent):
        """
        This tests the 'main' function
        """
        # Set up return values
        mock_load_config.return_value = self.mock_config

        # Call the function
        m.main()

        # Assert everything was called correctly
        mock_load_config.assert_called_once()
        mock_listen.assert_called_with(self.mock_config)
        mock_listen.assert_called_with(self.mock_config)
        mock_initialize_issues.assert_not_called()
        mock_initialize_pr.assert_not_called()
        mock_report_failure.assert_not_called()
        mock_initialize_recent.assert_called_with(self.mock_config)

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_initialize(self,
                        mock_d,
                        mock_u):
        """
        This tests 'initialize' function where everything goes smoothly!
        """
        # Set up return values
        mock_u.github_issues.return_value = ['mock_issue_github']

        # Call the function
        m.initialize_issues(self.mock_config)

        # Assert everything was called correctly
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.sync_with_jira.assert_any_call('mock_issue_github', self.mock_config)

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_initialize_repo_name_github(self,
                                         mock_d,
                                         mock_u):
        """
        This tests 'initialize' function where we want to sync an individual repo for GitHub
        """
        # Set up return values
        mock_u.github_issues.return_value = ['mock_issue_github']

        # Call the function
        m.initialize_issues(self.mock_config, repo_name='key_github')

        # Assert everything was called correctly
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.sync_with_jira.assert_called_with('mock_issue_github', self.mock_config)

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_initialize_errors(self,
                               mock_d,
                               mock_u):
        """
        This tests 'initialize' function where syncing with JIRA throws an exception
        """
        # Set up return values
        mock_u.github_issues.return_value = ['mock_issue_github']
        mock_d.sync_with_jira.side_effect = Exception()

        # Call the function
        with self.assertRaises(Exception):
            m.initialize_issues(self.mock_config)

        # Assert everything was called correctly
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.sync_with_jira.assert_any_call('mock_issue_github', self.mock_config)

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    @mock.patch(PATH + 'sleep')
    @mock.patch(PATH + 'report_failure')
    def test_initialize_api_limit(self,
                                  mock_report_failure,
                                  mock_sleep,
                                  mock_d,
                                  mock_u):
        """
        This tests 'initialize' where we get an GitHub API limit error.
        """
        # Set up return values
        mock_error = MagicMock(side_effect=Exception('API rate limit exceeded'))
        mock_u.github_issues.side_effect = mock_error

        # Call the function
        m.initialize_issues(self.mock_config, testing=True)

        # Assert everything was called correctly
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.sync_with_jira.assert_not_called()
        mock_sleep.assert_called_with(3600)
        mock_report_failure.assert_not_called()

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    @mock.patch(PATH + 'sleep')
    @mock.patch(PATH + 'report_failure')
    def test_initialize_github_error(self,
                                     mock_report_failure,
                                     mock_sleep,
                                     mock_d,
                                     mock_u):
        """
        This tests 'initialize' where we get a GitHub API (not limit) error.
        """
        # Set up return values
        mock_error = MagicMock(side_effect=Exception('Random Error'))
        mock_u.github_issues.side_effect = mock_error

        # Call the function
        with self.assertRaises(Exception):
            m.initialize_issues(self.mock_config, testing=True)

        # Assert everything was called correctly
        mock_u.github_issues.assert_called_with('key_github', self.mock_config)
        mock_d.sync_with_jira.assert_not_called()
        mock_sleep.assert_not_called()
        mock_report_failure.assert_called_with(self.mock_config)

    @mock.patch(PATH + 'query_ghp')
    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_initialize_github_project(self, mock_d, mock_u, mock_query_ghp):
        config = deepcopy(self.mock_config)
        config['sync2jira']['github_token'] = 'mock_token'
        timestamp = "2024-10-07T15:40:00Z"
        issues = [
            {
                'repository': {'nameWithOwner': "mock_repo1"},
                'number': 17
            },
            {
                'repository': {'nameWithOwner': "mock_repo1"},
                'number': 18
            },
            {
                'repository': {'nameWithOwner': "mock_repo2"},
                'number': 20
            }
        ]
        mock_u.handle_gh_project_message.return_value = "mock_issue"

        # No project configuration
        mapping = config['sync2jira']['map']
        if 'github_projects' in mapping:
            del mapping['github_projects']
        mock_query_ghp.reset_mock()
        m.initialize_github_project(timestamp, config)
        mock_query_ghp.assert_not_called()
        mock_u.handle_gh_project_message.assert_not_called()
        mock_d.sync_with_jira.assert_not_called()

        # No configured projects
        mapping['github_projects'] = {}
        mock_query_ghp.reset_mock()
        m.initialize_github_project(timestamp, config)
        mock_query_ghp.assert_not_called()
        mock_u.handle_gh_project_message.assert_not_called()
        mock_d.sync_with_jira.assert_not_called()

        # One configured project containing one issue
        mapping['github_projects'] = {'mock_project1': {'github_project_number': 1}}
        mock_query_ghp.reset_mock()
        mock_query_ghp.side_effect = ((i for i in (issues[1],)),)
        m.initialize_github_project(timestamp, config)
        mock_query_ghp.assert_called_once_with('mock_project1', 1, timestamp, 'mock_token')
        mock_u.handle_gh_project_message.assert_called_with(issues[1], 'mock_project1', config)
        mock_d.sync_with_jira.assert_called_with(
            mock_u.handle_gh_project_message.return_value, config)

        # Three configured projects, the first with two issues, the second with
        # one, the third with none.
        mapping['github_projects'] = {
            'mock_project1': {'github_project_number': 1},
            'mock_project2': {'github_project_number': 2},
            'mock_project3': {'github_project_number': 3},
        }
        mock_query_ghp.reset_mock()
        mock_u.reset_mock()
        mock_d.reset_mock()
        mock_query_ghp.side_effect = (
            (i for i in (issues[2], issues[1])),
            (i for i in (issues[0],)),
            (i for i in ()))
        m.initialize_github_project(timestamp, config)
        mock_query_ghp.assert_has_calls([
            mock.call('mock_project1', 1, timestamp, 'mock_token'),
            mock.call('mock_project2', 2, timestamp, 'mock_token')])
        mock_u.handle_gh_project_message.assert_has_calls((
            mock.call(issues[2], 'mock_project1', config),
            mock.call(issues[1], 'mock_project1', config),
            mock.call(issues[0], 'mock_project2', config)))
        mock_d.sync_with_jira.assert_has_calls((
            mock.call(mock_u.handle_gh_project_message.return_value, config),
            mock.call(mock_u.handle_gh_project_message.return_value, config),
            mock.call(mock_u.handle_gh_project_message.return_value, config)))

    @mock.patch(PATH + 'handle_msg')
    @mock.patch(PATH + 'fedmsg')
    def test_listen_no_handlers(self,
                                mock_fedmsg,
                                mock_handle_msg):
        """
        Test 'listen' function where suffix is not in handlers
        """
        # Set up return values
        mock_fedmsg.tail_messages.return_value = [("dummy", "dummy", "mock_topic", self.mock_message)]

        # Call the function
        m.listen(self.mock_config)

        # Assert everything was called correctly
        mock_handle_msg.assert_not_called()

    @mock.patch(PATH + 'handle_msg')
    @mock.patch(PATH + 'issue_handlers')
    @mock.patch(PATH + 'fedmsg')
    def test_listen_no_issue(self,
                             mock_fedmsg,
                             mock_handlers_issue,
                             mock_handle_msg):
        """
        Test 'listen' function where the handler returns none
        """
        # Set up return values
        mock_handlers_issue['github.issue.comment'].return_value = None
        mock_fedmsg.tail_messages.return_value = [("dummy", "dummy", "d.d.d.github.issue.drop", self.mock_message)]

        # Call the function
        m.listen(self.mock_config)

        # Assert everything was called correctly
        mock_handle_msg.assert_not_called()

    @mock.patch(PATH + 'handle_msg')
    @mock.patch(PATH + 'issue_handlers')
    @mock.patch(PATH + 'fedmsg')
    def test_listen(self,
                    mock_fedmsg,
                    mock_handlers_issue,
                    mock_handle_msg):
        """
        Test 'listen' function where everything goes smoothly
        """
        # Set up return values
        mock_handlers_issue['github.issue.comment'].return_value = 'dummy_issue'
        mock_fedmsg.tail_messages.return_value = [("dummy", "dummy", "d.d.d.github.issue.comment", self.mock_message)]

        # Call the function
        m.listen(self.mock_config)

        # Assert everything was called correctly
        mock_handle_msg.assert_called_with(
            self.mock_message,
            'github.issue.comment', self.mock_config)

    @mock.patch(PATH + 'send_mail')
    @mock.patch(PATH + 'jinja2')
    def test_report_failure(self,
                            mock_jinja2,
                            mock_send_mail):
        """
        Tests 'report_failure' function
        """
        # Set up return values
        mock_template_loader = MagicMock()
        mock_template_env = MagicMock()
        mock_template = MagicMock()
        mock_template.render.return_value = 'mock_html'
        mock_template_env.get_template.return_value = mock_template
        mock_jinja2.FileSystemLoader.return_value = mock_template_loader
        mock_jinja2.Environment.return_value = mock_template_env

        # Call the function
        m.report_failure({'sync2jira': {'mailing-list': 'mock_email'}})

        # Assert everything was called correctly
        mock_send_mail.assert_called_with(cc=None,
                                          recipients=['mock_email'],
                                          subject='Sync2Jira Has Failed!',
                                          text='mock_html')

    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_handle_msg_no_handlers(self,
                                    mock_d,
                                    mock_u):
        """
        Tests 'handle_msg' function where there are no handlers
        """
        # Call the function
        m.handle_msg(self.mock_message, 'no_handler', self.mock_config)

        # Assert everything was called correctly
        mock_d.sync_with_jira.assert_not_called()
        mock_u.handle_github_message.assert_not_called()

    @mock.patch(PATH + 'issue_handlers')
    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_handle_msg_no_issue(self,
                                 mock_d,
                                 mock_u,
                                 mock_handlers_issue):
        """
        Tests 'handle_msg' function where there is no issue
        """
        # Set up return values
        mock_handlers_issue['github.issue.comment'].return_value = None

        # Call the function
        m.handle_msg(self.mock_message, 'github.issue.comment', self.mock_config)

        # Assert everything was called correctly
        mock_d.sync_with_jira.assert_not_called()
        mock_u.handle_github_message.assert_not_called()

    @mock.patch(PATH + 'issue_handlers')
    @mock.patch(PATH + 'u_issue')
    @mock.patch(PATH + 'd_issue')
    def test_handle_msg(self,
                        mock_d,
                        mock_u,
                        mock_handlers_issue):
        """
        Tests 'handle_msg' function
        """
        # Set up return values
        mock_handlers_issue['github.issue.comment'].return_value = 'dummy_issue'
        mock_u.handle_github_message.return_value = 'dummy_issue'

        # Call the function
        m.handle_msg(self.mock_message, 'github.issue.comment', self.mock_config)

        # Assert everything was called correctly
        mock_d.sync_with_jira.assert_called_with('dummy_issue', self.mock_config)

    @mock.patch(PATH + 'handle_msg')
    @mock.patch(PATH + 'query')
    def test_initialize_recent(self,
                               mock_query,
                               mock_handle_msg):
        """
        Tests 'initialize_recent' function
        """
        # Set up return values
        mock_query.return_value = [{
            'topic': 'm.m.m.github.issue.comment',
            'msg': 'mock_msg'

        }]

        # Call the function
        m.initialize_recent(self.mock_config)

        # Assert everything was called correctly
        mock_handle_msg.assert_called_with({'msg': 'mock_msg'}, 'github.issue.comment', self.mock_config)

    @mock.patch(PATH + 'handle_msg')
    @mock.patch(PATH + 'query')
    def test_initialize_recent_no_handler(self,
                                          mock_query,
                                          mock_handle_msg):
        """
        Tests 'initialize_recent' function where the topic is not for a valid handler
        """
        # Set up return values
        mock_query.return_value = [{
            'topic': 'm.m.m.bad.topic',
            'msg': 'mock_msg'

        }]

        # Call the function
        m.initialize_recent(self.mock_config)

        # Assert everything was called correctly
        mock_handle_msg.assert_not_called()

    @mock.patch(PATH + 'verify_content_lists')
    @mock.patch(PATH + 'sanity_check_dates')
    @mock.patch(PATH + 'requests')
    def test_query_ghp(self, mock_requests, _mock_scd, _mock_vcl):
        organization = "mock_organization"
        project_number = 17
        token = 'mock_token'
        timestamp = "2024-10-07T15:40:00Z"
        cursors = ("", "MTAw", "MqAw", "MzAw", "Mzcw")
        pages = (
            {
                "data": {
                    "organization": {
                        "projectV2": {
                            "updatedAt": "2024-11-13T18:15:53Z",
                            "title": "Eclipse Che Team B Backlog",
                            "items": {
                                "totalCount": 4,
                                "nodes": [
                                    {
                                        "content": {}
                                    },
                                    {
                                        "content": {
                                            "updatedAt": "2024-10-09T14:24:29Z",
                                            "url": "https:/github.com/mock_org/mock_repo/issues/17",
                                            "comments": {
                                                "totalCount": 1,
                                                "nodes": [{}]
                                            },
                                            "projectItems": {
                                                "totalCount": 2,
                                                "nodes": [
                                                    {
                                                        "updatedAt": "2024-10-09T14:24:33Z",
                                                        "fieldValues": {
                                                            "totalCount": 7,
                                                            "nodes": [{}, {}, {}, {}, {}, {}, {}]
                                                        },
                                                        "project": {
                                                            "number": project_number,
                                                            "owner": {
                                                                "login": organization
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "updatedAt": "2024-10-09T14:24:33Z",
                                                        "fieldValues": {
                                                            "totalCount": 5,
                                                            "nodes": [{}, {}, {}, {}, {}]
                                                        },
                                                        "project": {
                                                            "number": project_number + 4,  # Wrong project
                                                            "owner": {
                                                                "login": organization
                                                            }
                                                        }
                                                    }
                                                ]
                                            },
                                            "labels": {
                                                "totalCount": 1,
                                                "nodes": [
                                                    {}
                                                ]
                                            },
                                            "closedByPullRequestsReferences": {
                                                "totalCount": 0,
                                                "nodes": []
                                            }
                                        }
                                    },
                                    {
                                        "content": {
                                            "updatedAt": "2024-05-27T02:21:26Z",
                                            "url": "https:/github.com/mock_org/mock_repo/issues/17",
                                            "comments": {
                                                "totalCount": 2,
                                                "nodes": [{}, {}]
                                            },
                                            "projectItems": {
                                                "totalCount": 0,
                                                "nodes": []
                                            },
                                            "labels": {
                                                "totalCount": 1,
                                                "nodes": [{}]
                                            },
                                            "closedByPullRequestsReferences": {
                                                "totalCount": 0,
                                                "nodes": []
                                            }
                                        }
                                    },
                                    {
                                        "content": {}
                                    },
                                ],
                                "pageInfo": {
                                    "endCursor": cursors[1],
                                    "hasNextPage": True
                                }
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "organization": {
                        "projectV2": {
                            "updatedAt": "2024-11-13T18:15:53Z",
                            "title": "Eclipse Che Team B Backlog",
                            "items": {
                                "totalCount": 0,
                                "nodes": [],
                                "pageInfo": {
                                    "endCursor": cursors[2],
                                    "hasNextPage": True
                                }
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "organization": {
                        "projectV2": {
                            "updatedAt": "2024-11-13T18:15:53Z",
                            "title": "Eclipse Che Team B Backlog",
                            "items": {
                                "totalCount": 2,
                                "nodes": [
                                    {
                                        "content": {}
                                    },
                                    {
                                        "content": {}
                                    },
                                ],
                                "pageInfo": {
                                    "endCursor": cursors[3],
                                    "hasNextPage": True
                                }
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "organization": {
                        "projectV2": {
                            "updatedAt": "2024-11-13T18:15:53Z",
                            "title": "Eclipse Che Team B Backlog",
                            "items": {
                                "totalCount": 1,
                                "nodes": [
                                    {
                                        "content": {
                                            "updatedAt": "2024-10-09T14:24:29Z",
                                            "url": "https:/github.com/mock_org/mock_repo/issues/17",
                                            "comments": {
                                                "totalCount": 1,
                                                "nodes": [{}]
                                            },
                                            "projectItems": {
                                                "totalCount": 2,
                                                "nodes": [
                                                    {
                                                        "updatedAt": "2024-10-09T14:24:33Z",
                                                        "fieldValues": {
                                                            "totalCount": 7,
                                                            "nodes": [{}, {}, {}, {}, {}, {}, {}]
                                                        },
                                                        "project": {
                                                            "number": project_number,
                                                            "owner": {
                                                                "login": organization
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "updatedAt": "2024-10-09T14:24:33Z",
                                                        "fieldValues": {
                                                            "totalCount": 5,
                                                            "nodes": [{}, {}, {}, {}, {}]
                                                        },
                                                        "project": {
                                                            "number": project_number,
                                                            "owner": {
                                                                "login": organization + '-wrong'  # Wrong organization
                                                            }
                                                        }
                                                    }
                                                ]
                                            },
                                            "labels": {
                                                "totalCount": 1,
                                                "nodes": [
                                                    {}
                                                ]
                                            },
                                            "closedByPullRequestsReferences": {
                                                "totalCount": 0,
                                                "nodes": []
                                            }
                                        }
                                    },
                                ],
                                "pageInfo": {
                                    "endCursor": cursors[4],
                                    "hasNextPage": False
                                }
                            }
                        }
                    }
                }
            }
        )
        mock_response = MagicMock()
        mock_requests.post.return_value = mock_response

        # Test the request setup and error path
        mock_response.status_code = 418
        results = list(
            m.query_ghp(organization, project_number, timestamp, token))
        mock_requests.post.assert_called_once()
        self.assertEqual(
            organization,
            mock_requests.post.call_args.kwargs['json']['variables']['ORGANIZATION'])
        self.assertEqual(
            project_number,
            mock_requests.post.call_args.kwargs['json']['variables']['PROJECT_NUMBER'])
        self.assertEqual(
            '',
            mock_requests.post.call_args.kwargs['json']['variables']['CURSOR'])
        self.assertEqual(
            mock_requests.post.call_args.kwargs['headers']['Authorization'],
            'Bearer ' + token)
        mock_response.json.assert_not_called()
        self.assertEqual(results, [])

        # Test when the response is a single page
        mock_requests.reset_mock()
        mock_response.reset_mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = (pages[-1],)
        results = list(m.query_ghp(organization, project_number, timestamp, token))
        mock_requests.post.assert_called_once()
        mock_response.json.assert_called_once()
        expected = [node['content']
                    for node in pages[-1]['data']['organization']['projectV2']['items']['nodes']
                    if node['content']]
        self.assertEqual(results, expected)

        # Test when the response is multiple pages; also check that "old" items
        # are filtered out and backlinks from other projects are removed.
        mock_requests.reset_mock()
        mock_response.reset_mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = pages
        results = list(m.query_ghp(organization, project_number, timestamp, token))
        self.assertEqual(mock_requests.post.call_count, len(pages))
        self.assertEqual(mock_response.json.call_count, len(pages))
        for idx, call in enumerate(mock_requests.post.call_args_list):
            self.assertEqual(cursors[idx], call.kwargs['json']['variables']['CURSOR'])
        expected = [
            n['content']
            for p in pages for n in p['data']['organization']['projectV2']['items']['nodes']
            if n['content'] and n['content']['updatedAt'] >= timestamp]
        self.assertEqual(results, expected)
        for result in results:
            project_items = result['projectItems']['nodes']
            self.assertEqual(len(project_items), 1)
            self.assertEqual(project_items[0]['project']['number'], project_number)
            self.assertEqual(project_items[0]['project']['owner']['login'], organization)

    @mock.patch(PATH + 'get')
    def test_query(self, mock_get):
        """Tests 'query' function"""
        # Set up return values
        mock_get.return_value = {
            'raw_messages': ['test_msg'],
            'count': 1,
            'total': 1
        }
        # Call the function
        response = list(m.query())

        # Assert everything was called correctly
        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args.kwargs['params']['order'], 'asc')
        self.assertEqual(response, ['test_msg'])

    @mock.patch(PATH + 'HTTPKerberosAuth')
    @mock.patch(PATH + 'requests')
    def test_get(self,
                 mock_requests,
                 mock_kerberos_auth):
        """
        Tests 'get' function
        """
        # Set up return values
        mock_response = MagicMock()
        mock_response.json.return_value = 'mock_return_value'
        mock_requests.get.return_value = mock_response

        # Call the function
        response = m.get('mock_params')

        # Assert everything was called correctly
        self.assertEqual(response, 'mock_return_value')
        mock_requests.get.assert_called_with(
            auth=mock_kerberos_auth(),
            headers={'Accept': 'application/json'},
            params='mock_params',
            url=m.DATAGREPPER_URL)
