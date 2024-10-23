import unittest
import unittest.mock as mock
from copy import deepcopy
from distutils.command.config import config

import sync2jira.intermediary as i

PATH = 'sync2jira.intermediary.'


class TestIntermediary(unittest.TestCase):
    """
    This class tests the downstream_issue.py file under sync2jira
    """

    def setUp(self):
        self.mock_config = {
            'sync2jira': {
                'map': {
                    'github': {
                        'github': {'mock_downstream': 'mock_key'}
                    }
                }
            }
        }

        self.mock_github_issue = {
            'comments': [{
                'author': 'mock_author',
                'name': 'mock_name',
                'body': 'mock_body',
                'id': 'mock_id',
                'date_created': 'mock_date'
            }],
            'title': 'mock_title',
            'html_url': 'mock_url',
            'id': 1234,
            'labels': 'mock_tags',
            'milestone': 'mock_milestone',
            'priority': 'mock_priority',
            'body': 'mock_content',
            'user': 'mock_reporter',
            'assignees': 'mock_assignee',
            'state': 'open',
            'date_created': 'mock_date',
            'number': '1',
            'storypoints': 'mock_storypoints',
        }

        self.mock_github_pr = {
            'comments': [{
                'author': 'mock_author',
                'name': 'mock_name',
                'body': 'mock_body',
                'id': 'mock_id',
                'date_created': 'mock_date'
            }],
            'title': 'mock_title',
            'html_url': 'mock_url',
            'id': 1234,
            'labels': 'mock_tags',
            'milestone': 'mock_milestone',
            'priority': 'mock_priority',
            'body': 'mock_content',
            'user': {'fullname': 'mock_reporter'},
            'assignee': 'mock_assignee',
            'state': 'open',
            'date_created': 'mock_date',
            'number': 1234,
        }

    def checkResponseFields(self, response):
        self.assertEqual(response.source, 'github')
        self.assertEqual(response.title, '[github] mock_title')
        self.assertEqual(response.url, 'mock_url')
        self.assertEqual(response.upstream, 'github')
        self.assertEqual(response.comments, [{'body': 'mock_body', 'name': 'mock_name', 'author': 'mock_author',
                                              'changed': None, 'date_created': 'mock_date', 'id': 'mock_id'}])
        self.assertEqual(response.content, 'mock_content')
        self.assertEqual(response.reporter, 'mock_reporter')
        self.assertEqual(response.assignee, 'mock_assignee')
        self.assertEqual(response.id, '1234')

    def test_from_github_open(self):
        """
        This tests the 'from_github' function under the Issue class where the state is open
        """
        # Call the function
        response = i.Issue.from_github(
            upstream='github',
            issue=self.mock_github_issue,
            config=self.mock_config
        )

        # Assert that we made the calls correctly
        self.checkResponseFields(response)

        self.assertEqual(response.fixVersion, ['mock_milestone'])
        self.assertEqual(response.priority, 'mock_priority')
        self.assertEqual(response.status, 'Open')
        self.assertEqual(response.downstream, {'mock_downstream': 'mock_key'})
        self.assertEqual(response.storypoints, 'mock_storypoints')

    def test_from_github_open_without_priority(self):
        """
        This tests the 'from_github' function under the Issue class
        where the state is open but the priority is not initialized.
        """
        mock_github_issue = {
            'comments': [{
                'author': 'mock_author',
                'name': 'mock_name',
                'body': 'mock_body',
                'id': 'mock_id',
                'date_created': 'mock_date'
            }],
            'title': 'mock_title',
            'html_url': 'mock_url',
            'id': 1234,
            'labels': 'mock_tags',
            'milestone': 'mock_milestone',
            'body': 'mock_content',
            'user': 'mock_reporter',
            'assignees': 'mock_assignee',
            'state': 'open',
            'date_created': 'mock_date',
            'number': '1',
            'storypoints': 'mock_storypoints',
        }

        # Call the function
        response = i.Issue.from_github(
            upstream='github',
            issue=mock_github_issue,
            config=self.mock_config
        )

        # Assert that we made the calls correctly
        self.checkResponseFields(response)

        self.assertEqual(response.priority, None)
        self.assertEqual(response.status, 'Open')


    def test_from_github_closed(self):
        """
        This tests the 'from_github' function under the Issue class where the state is closed
        """
        # Set up return values
        self.mock_github_issue['state'] = 'closed'

        # Call the function
        response = i.Issue.from_github(
            upstream='github',
            issue=self.mock_github_issue,
            config=self.mock_config
        )

        # Assert that we made the calls correctly
        self.checkResponseFields(response)

        self.assertEqual(response.tags, 'mock_tags')
        self.assertEqual(response.fixVersion, ['mock_milestone'])
        self.assertEqual(response.priority, 'mock_priority')
        self.assertEqual(response.status, 'Closed')
        self.assertEqual(response.downstream, {'mock_downstream': 'mock_key'})
        self.assertEqual(response.storypoints, 'mock_storypoints')

    def test_mapping_github(self):
        """
        This tests the mapping feature from GitHub
        """
        # Set up return values
        self.mock_config['sync2jira']['map']['github']['github'] = {
            'mock_downstream': 'mock_key',
            'mapping': [{'fixVersion': 'Test XXX'}]
        }
        self.mock_github_issue['state'] = 'closed'

        # Call the function
        response = i.Issue.from_github(
            upstream='github',
            issue=self.mock_github_issue,
            config=self.mock_config
        )

        # Assert that we made the calls correctly
        self.checkResponseFields(response)

        self.assertEqual(response.tags, 'mock_tags')
        self.assertEqual(response.fixVersion, ['Test mock_milestone'])
        self.assertEqual(response.priority, 'mock_priority')
        self.assertEqual(response.status, 'Closed')
        self.assertEqual(response.downstream, {
            'mock_downstream': 'mock_key',
            'mapping': [{'fixVersion': 'Test XXX'}]})
        self.assertEqual(response.storypoints, 'mock_storypoints')

    @mock.patch(PATH + 'matcher')
    def test_from_github_pr_reopen(self,
                                   mock_matcher):
        """
        This tests the message from GitHub for a PR
        """
        # Set up return values
        mock_matcher.return_value = "JIRA-1234"

        # Call the function
        response = i.PR.from_github(
            upstream='github',
            pr=self.mock_github_pr,
            suffix='reopened',
            config=self.mock_config
        )

        # Assert that we made the calls correctly
        self.checkResponseFields(response)

        self.assertEqual(response.suffix, 'reopened')
        self.assertEqual(response.status, None)
        self.assertEqual(response.downstream, {'mock_downstream': 'mock_key'})
        self.assertEqual(response.jira_key, "JIRA-1234")
        self.mock_github_pr['comments'][0]['changed'] = None
        mock_matcher.assert_called_with(self.mock_github_pr['body'], self.mock_github_pr['comments'])

    def test_matcher(self):
        """ This tests the matcher function """
        # Positive case
        content = "Relates to JIRA: XYZ-5678"
        comments = [{"body": "Relates to JIRA: ABC-1234"}]
        expected = True
        actual = bool(i.matcher(content, comments))
        assert expected == actual

        # Negative case
        content = "No JIRAs here..."
        comments = [{"body": "... nor here"}]
        expected = False
        actual = bool(i.matcher(content, comments))
        assert expected == actual

    # TODO: Add new tests from PR

    def test_from_gh_project(self):
        # Items tested:
        # - zero, one, and two assignees
        # - zero, one, and two labels
        # - zero, one, and two comments
        # - comment body present and missing
        # - IssueState capitalization and trimming
        # - story points missing, in first position, in second position
        # - fixVersion mapping present and missing
        # - milestone present and missing

        mock_config = deepcopy(self.mock_config)
        upstream = 'mock_org/mock_repo'
        mock_config['sync2jira']['map']['github'][upstream] = {
            'mapping': [{'fixVersion': "mock_XXX"}]}
        gh_issue = {
            'title': 'mock_title',
            'url': 'mock_url',
            'body': 'mock_body',
            'author': {'name': 'mock_author'},
            'IssueState': ' CLOSED ',
            'id': 'mock_id',
            'number': 'mock_number',
            'comments': {'nodes': []},
            'labels': {'nodes': []},
            'assignees': {'nodes': []},
            'projectItems': {'nodes': []},
            'milestone': 'mock_milestone',  # Optional?
        }
        field_value_nodes = [
            {
                'field': {'name': 'Sprint'},
                'duration': 21,
                'startDate': '2024-09-18',
                'title': 'Sprint 3263'
            },
            {
                'field': {'name': 'Story Points'},
                'number': '34'
            }
        ]
        assignees = [
            {'name': 'mock_assignee_name_1', 'login': 'mock_assignee_login_1'},
            {'name': 'mock_assignee_name_2', 'login': 'mock_assignee_login_2'}
        ]
        labels = [{'name': 'mock_label_1'}, {'name': 'mock_label_2'}]
        comments = [
            {
                'author': {
                    'name': 'mock_comment_author_name_1',
                    'login': 'mock_comment_author_login_1',
                },
                'body': None,
                'id': 'mock_comment_id_1',
                'createdAt': 'mock_comment_created_at_1',
                'updatedAt': 'mock_comment_updated_at_1',
            },
            {
                'author': {
                    'name': 'mock_comment_author_name_2',
                    'login': 'mock_comment_author_login_2',
                },
                'body': 'mock_comment_body_2',
                'id': 'mock_comment_id_2',
                'createdAt': 'mock_comment_created_at_2',
                'updatedAt': 'mock_comment_updated_at_2',
            }
        ]

        c = 2
        self.assertEqual(c, len(assignees))
        self.assertEqual(c, len(labels))
        self.assertEqual(c, len(comments))
        self.assertEqual(c, len(field_value_nodes))
        # The first iteration will use the full lists; each subsequent
        # iteration will use a list with one fewer items; the last iteration
        # will use empty lists.  Each time we use the last part of the list,
        # so that the first element of the slice is different each time.
        for idx in range(c + 1):
            gh_issue['assignees']['nodes'] = assignees[idx:]
            gh_issue['labels']['nodes'] = labels[idx:]
            gh_issue['comments']['nodes'] = comments[idx:]
            gh_issue['projectItems']['nodes'] = [
                {'fieldValues': {'nodes': field_value_nodes[idx:]}}]
            gh_issue['milestone'] = 'mock_milestone' if c - idx > 0 else None
            i_issue = i.Issue.from_gh_project(gh_issue, upstream, mock_config)
            self.assertEqual('[mock_org/mock_repo] mock_title', i_issue.title)
            self.assertEqual(upstream, i_issue.upstream)
            self.assertEqual(mock_config['sync2jira']['map']['github'][upstream], i_issue.downstream)
            self.assertEqual('mock_body', i_issue.content)
            self.assertEqual({'fullname': 'mock_author'}, i_issue.reporter)
            self.assertEqual('Closed', i_issue.status)

            self.assertEqual(c - idx, len(i_issue.comments))
            self.assertEqual(c - idx, len(i_issue.tags))
            self.assertEqual(c - idx, len(i_issue.assignee))

            if c - idx > 0:
                self.assertEqual('mock_comment_author_name_2', i_issue.comments[-1]['author'])
                self.assertEqual('mock_comment_author_login_2', i_issue.comments[-1]['name'])
                self.assertEqual('mock_comment_body_2', i_issue.comments[-1]['body'])
                self.assertEqual('mock_assignee_name_2', i_issue.assignee[-1])
                self.assertEqual('mock_label_2', i_issue.tags[-1])
                self.assertEqual('34', i_issue.storypoints)
                self.assertEqual(['mock_mock_milestone'], i_issue.fixVersion)
            else:
                self.assertEqual(None, i_issue.storypoints)
                self.assertEqual(None, i_issue.fixVersion)

            if idx == 0:
                self.assertEqual('', i_issue.comments[0]['body'])
