from github import Github

import base64
from collections import namedtuple
import config
import frontmatter
import json
import logging
import os
import re
import webapp2

FILE_RE = re.compile("^SIPS/sip-(\d+).md$")
AUTHOR_RE = re.compile("[(<]([^>)]+)[>)]")
MERGE_MESSAGE = """
Hi, I'm a bot! This change was automatically merged because:

 - It only modifies existing WIP SIP(s)
 - The PR was approved or written by at least one author of each modified SIP
 - The build is passing
"""

github = Github(config.GITHUB_ACCESS_TOKEN)

SIPInfo = namedtuple('SIPInfo', ('number', 'authors'))

users_by_email = {}


def find_user_by_email(email):
    if email not in users_by_email:
        results = list(github.search_users(email))
        if len(results) > 0:
            logging.info("Recording mapping from %s to %s", email, results[0].login)
            users_by_email[email] = '@' + results[0].login
        else:
            logging.info("No github user found for %s", email)
    return users_by_email.get(email)


class MergeHandler(webapp2.RequestHandler):
    def resolve_author(self, author):
        if author.startswith('@'):
            return author.lower()
        else:
            # Email address
            return (find_user_by_email(author) or author).lower()

    def get_authors(self, authorlist):
        return set(self.resolve_author(author.groups(1)[0]) for author in AUTHOR_RE.finditer(authorlist))

    def check_file(self, pr, file):
        try:
            match = FILE_RE.search(file.filename)
            if not match:
                return (None, "File %s is not an SIP" % (file.filename,))
            sipnum = int(match.group(1))

            if file.status == "added":
                return (None, "Contains new file %s" % (file.filename,))

            logging.info("Getting file %s from %s@%s/%s", file.filename, pr.base.user.login, pr.base.repo.name, pr.base.sha)
            base = pr.base.repo.get_contents(file.filename, ref=pr.base.sha)
            basedata = frontmatter.loads(base64.b64decode(base.content))
            if basedata.get("status").lower() not in ("wip"):
                return (None, "SIP %d is in state %s, not WIP" % (sipnum, basedata.get("status")))

            sip = SIPInfo(sipnum, self.get_authors(basedata.get("author")))

            if basedata.get("sip") != sipnum:
                return (sip, "SIP header in %s does not match: %s" % (file.filename, basedata.get("sip")))

            logging.info("Getting file %s from %s@%s/%s", file.filename, pr.head.user.login, pr.head.repo.name, pr.head.sha)
            head = pr.head.repo.get_contents(file.filename, ref=pr.head.sha)
            headdata = frontmatter.loads(base64.b64decode(head.content))
            if headdata.get("sip") != sipnum:
                return (sip, "SIP header in modified file %s does not match: %s" % (file.filename, headdata.get("sip")))
            if headdata.get("status").lower() != basedata.get("status").lower():
                return (sip, "Trying to change SIP %d state from %s to %s" % (sipnum, basedata.get("status"), headdata.get("status")))

            return (sip, None)
        except Exception, e:
            logging.exception("Exception checking file %s", file.filename)
            return (None, "Error checking file %s" % (file.filename,))

    def post(self):
        payload = json.loads(self.request.get("payload"))
        if 'X-Github-Event' in self.request.headers:
            event = self.request.headers['X-Github-Event']
            logging.info("Got Github webhook event %s", event)
            if event == "pull_request_review":
                pr = payload["pull_request"]
                prnum = int(pr["number"])
                repo = pr["base"]["repo"]["full_name"]
                logging.info("Processing review on PR %s/%d...", repo, prnum)
                self.check_pr(repo, prnum)
        else:
            logging.info("Processing build %s...", payload["number"])
            if payload.get("pull_request_number") is None:
                logging.info("Build %s is not a PR build; quitting", payload["number"])
                return
            prnum = int(payload["pull_request_number"])
            self.check_pr(payload["repository"]["owner_name"] + "/" + payload["repository"]["name"], prnum)

    def get(self):
        self.check_pr(self.request.get("repo"), int(self.request.get("pr")))

    def get_approvals(self, pr):
        approvals = ['@' + pr.user.login.lower()]
        for review in pr.get_reviews():
            if review.state == "APPROVED":
                approvals.append('@' + review.user.login.lower())
        return approvals

    def check_pr(self, reponame, prnum):
        logging.info("Checking PR %d on %s", prnum, reponame)
        repo = github.get_repo(reponame)
        pr = repo.get_pull(prnum)
        if pr.merged:
            logging.info("PR %d is already merged; quitting", prnum)
            return
        if pr.mergeable_state != 'clean':
            logging.info("PR %d mergeable state is %s; quitting", prnum, pr.mergeable_state)
            return

        sips = []
        errors = []
        for file in pr.get_files():
            sip, error = self.check_file(pr, file)
            if sip is not None:
                sips.append(sip)
            if error is not None:
                logging.info(error)
                errors.append(error)

        reviewers = set()
        approvals = self.get_approvals(pr)
        logging.info("Found approvals for %d: %r", prnum, approvals)
        for sip in sips:
            logging.info("SIP %d has authors: %r", sip.number, sip.authors)
            if len(sip.authors) == 0:
                errors.append("SIP %d has no identifiable authors who can approve PRs" % (sip.number,))
            elif sip.authors.isdisjoint(approvals):
                errors.append("SIP %d requires approval from one of (%s)" % (sip.number, ', '.join(sip.authors)))
                for author in sip.authors:
                    if author.startswith('@'):
                        reviewers.add(author[1:])

        if len(errors) == 0:
            logging.info("Merging PR %d!", prnum)
            self.response.write("Merging PR %d!" % (prnum,))
            pr.merge(
                commit_title="Automatically merged updates to draft SIP(s) %s (#%d)" % (', '.join('%s' % sip.number for sip in sips), prnum),
                commit_message=MERGE_MESSAGE,
                merge_method="squash",
                sha=pr.head.sha)
        elif len(errors) > 0 and len(sips) > 0:
            message = "Hi! I'm a bot, and I wanted to automerge your PR, but couldn't because of the following issue(s):\n\n"
            message += "\n".join(" - " + error for error in errors)

            self.post_comment(pr, message)

    def post_comment(self, pr, message):
        me = github.get_user()
        for comment in pr.get_issue_comments():
            if comment.user.login == me.login:
                logging.info("Found comment by myself")
                if comment.body != message:
                    comment.edit(message)
                return
        pr.create_issue_comment(message)


app = webapp2.WSGIApplication([
    ('/merge/', MergeHandler),
], debug=True)
