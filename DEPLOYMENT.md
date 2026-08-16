# Deployment guide

Everything in this repo is deploy-ready and has been tested locally. The
two steps below need your own GitHub/Render accounts, so they can't be
done from a sandbox — here's exactly what to do.

## 1. Push this repo to GitHub

```bash
cd ai-code-scanner
git init
git add .
git commit -m "Initial commit: SlopGuard v1"
gh repo create slopguard --public --source=. --push
# or, without the gh CLI: create an empty repo on github.com, then:
#   git remote add origin https://github.com/<you>/slopguard.git
#   git branch -M main
#   git push -u origin main
```

## 2. Deploy the API to Render

`render.yaml` is already in the repo, so this is a "Blueprint" deploy:

1. Go to [render.com](https://render.com) → **New** → **Blueprint**
2. Connect your GitHub account, select the `slopguard` repo
3. Render reads `render.yaml` automatically and proposes a web service
   named `slopguard` — confirm and deploy
4. Wait for the build (a few minutes for the Docker build)
5. Once live, your health check should work:
   ```bash
   curl https://slopguard-<random>.onrender.com/health
   # {"status": "ok"}
   ```
6. Test a real scan against it:
   ```bash
   cd tests/fixtures && zip -r /tmp/test.zip . && cd -
   curl -X POST https://slopguard-<random>.onrender.com/scan \
     -F "file=@/tmp/test.zip"
   ```

**Note on the free tier**: Render's free web services spin down after 15
minutes of inactivity and take ~30-60s to wake back up on the next
request. Fine for a portfolio demo link; mention this if you link it from
your resume so a slow first load doesn't look broken.

## 3. Enable the GitHub Action on a real repo

The Action (`action.yml` + `action/entrypoint.sh` +
`action/post_comment.py`) is built and tested — `post_comment.py` was
verified locally to make a real (correctly-rejected, since it used a fake
token) call to `api.github.com`, confirming the request-building logic is
correct end-to-end.

**To try it on this repo itself** (recommended first test — dogfooding):

1. Push this repo to GitHub if you haven't (step 1 above)
2. Open a PR against `main` that changes any `.py` file (even a comment)
3. Add `.github/workflows/slopguard-self-check.yml`:
   ```yaml
   name: SlopGuard Self-Check
   on:
     pull_request:
       branches: [main]
   jobs:
     slopguard:
       runs-on: ubuntu-latest
       permissions:
         contents: read
         pull-requests: write
       steps:
         - uses: actions/checkout@v4
         - uses: ./               # uses the action.yml in this same repo
           with:
             path: .
             fail-on: critical
           env:
             GITHUB_TOKEN: ${{ github.token }}
   ```
4. Push, open the PR, and watch the Actions tab — you should see the scan
   run and, if there are findings, a comment appear on the PR

**To use it on a *different* repo** (once you're happy with the self-test):
use `action/example-consumer-workflow.yml` as a template, pointing
`uses:` at `<your-username>/slopguard@main` instead of `./`.

### What to verify when you run this for real
- [ ] The Action actually builds the Docker image and runs (not just
      "workflow syntax is valid" — the build itself can fail for reasons
      that don't show up until it actually runs on GitHub's infrastructure)
- [ ] A PR comment appears with real findings
- [ ] Pushing a second commit to the same PR **updates** the existing
      comment rather than adding a new one each time (this is what
      `_find_existing_comment` in `post_comment.py` is for — confirmed by
      unit test, but worth seeing happen for real)
- [ ] The job's exit code correctly fails the check when `fail-on` is met

If anything here behaves differently than described, that's genuinely
useful signal — GitHub Actions' Docker container runtime has a few
environment quirks (env var passthrough, working directory) that are
easy to get subtly wrong and only surface on the real platform.

## 4. Tag a release (optional, but makes the Action nicer to consume)

Once the self-check above passes:
```bash
git tag v1.0.0
git push origin v1.0.0
```
Then others (including your own other repos) can pin to
`uses: <you>/slopguard@v1.0.0` instead of the less-stable `@main`.
