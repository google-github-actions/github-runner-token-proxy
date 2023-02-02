# GitHub Runner Token Proxy

The GitHub Runner Token Proxy generates registration/removal tokens for GitHub self-hosted runners using a privileged credential, without disclosing the privileged credential to the caller.


## Background

There are two locations in which GitHub Actions self-hosted runners can be installed:

1.  **Repository-level** - in this mode, the self-hosted runner is installed at
    the [repo level][repo-runner]. This option works for both personal
    repositories and repositories in an organization.

    To register a GitHub Actions self-hosted runner at the repository level, you must have one of the following:

    -   A Personal Access Token (PAT) with `repo` scope.
    -   A GitHub App with "Administration" permissions.

    Both the PAT and the GitHub App have permissions to create, delete, modify
    settings, and update collaborators on the selected repos. This is likely an
    overly-broad permission if you just want to create a self-hosted runner
    token.

1.  **Organization-level** - in this mode, the self-hosted runner is installed
    at the [organization level][org-runner]. This option is not available for
    personal accounts and requires a GitHub organization.

    To register a GitHub Actions self-hosted runner at the organization level, you must have one of the following:

    -   A Personal Access Token (PAT) with `admin:org` scope.
    -   A GitHub App with "Self-hosted runners" permissions.

    The PAT has full control of orgs, teams, projects, and memberships in _all_
    your organizations. The GitHub App is actually appropriately scoped and has
    only permissions to register self-hosted runners. However, the GitHub App
    can _only_ register self-hosted runners at the organization level; it does
    not have permission to register runners on an individual repo (that would
    require "Administration" permissions as noted above).

    Note: You can also install GitHub Actions self-hosted runners at the
    Enterprise level, but it's identical to the Organization level in terms of
    the API.

Given the generally overly broad permissions, it would be unwise to distribute
PAT or GitHub App credentials directly to a GitHub Actions self-hosted runner
for self-registration. This proxy provides endpoints that, which invoked with
authorization, generate and distribute registration or removal tokens to the
caller. It never discloses the highly-privileged token to the caller, and it
supports both GitHub Apps and Personal Access Tokens (PAT).

![GitHub Runner Token Proxy flow](assets/pat-proxy-flow.svg)


## Usage

The service is invoked via HTTP. Authorization should be provided by the
platform (e.g. Google Cloud IAM); there is no built-in authorization.

### API

Once deployed the service exposes the following endpoints:

-   `POST /register` - generate a GitHub Actions self-hosted runner registration
    token for the provided scope.

    ```sh
    curl ${URL}/register --data '{"scope":"my-org/my-repo"}'
    ```

-   `POST /remove` - generate a GitHub Actions self-hosted runner removal token
    for the provided scope.

    ```sh
    curl ${URL}/remove --data '{"scope":"my-org/my-repo"}'
    ```

In both instances, the request body is the same:

```json
{"scope": "<scope>"}
```

-   `scope` - this refers to the location in which the GitHub Actions
    self-hosted runner registration token should be created. For organizations
    or enterprises, this is the name of the organization (e.g. "my-org"). For
    individual repositories, this is the full repo identifier (e.g.
    "my-org/my-repo"). See [Background](#background) for more information on the
    required permissions depending on scope.


## Deployment

This deployment example uses Google Cloud and [Cloud Run][cloud-run] to deploy
and manage the proxy. There is no requirement to use Google Cloud - the proxy
should run anywhere.

1.  Create or use an existing Google Cloud project:

    ```sh
    export PROJECT_ID="..."
    ```

1.  Enable required APIs:

    ```sh
    gcloud services enable --project="${PROJECT_ID}" \
      artifactregistry.googleapis.com \
      cloudbuild.googleapis.com \
      run.googleapis.com \
      secretmanager.googleapis.com
    ```

1.  Create a GitHub Personal Access token with `repo` scopes. Save the token in
    Google Secret Manager:

    ```sh
    echo -n "<VALUE FROM GITHUB>" | gcloud secrets create "ght-proxy-token" \
      --project="${PROJECT_ID}" \
      --data-file=-
    ```

    Alternatively, for GitHub Apps, save the GitHub App private key in Google
    Secret Manager:

    ```sh
    echo -n "<VALUE FROM GITHUB>" | gcloud secrets create "ght-proxy-app-private-key" \
      --project="${PROJECT_ID}" \
      --data-file=-
    ```

1.  Create a service account to run the proxy:

    ```sh
    gcloud iam service-accounts create "ght-proxy" \
      --description="GitHub Token proxy" \
      --project="${PROJECT_ID}"
    ```

1.  Grant the service account permissions to access the secret:

    ```sh
    gcloud secrets add-iam-policy-binding "github-token" \
      --project="${PROJECT_ID}" \
      --role="roles/secretmanager.secretAccessor" \
      --member="serviceAccount:ght-proxy@${PROJECT_ID}.iam.gserviceaccount.com"
    ```

1.  Create a repository in Artifact Registry to store the container:

    ```sh
    gcloud artifacts repositories create "ght-proxy" \
      --project="${PROJECT_ID}" \
      --repository-format="docker" \
      --location="us" \
      --description="GitHub Runner Token Proxy"
    ```

1.  Build and push the container:

    ```sh
    gcloud builds submit . \
      --project="${PROJECT_ID}" \
      --tag="us-docker.pkg.dev/${PROJECT_ID}/ght-proxy/ght-proxy"
    ```

1.  Deploy the service and attach the secret (see
    [Configuration](#configuration) for more information on available options):

    For a Personal Access Token (PAT):

    ```sh
    gcloud beta run deploy "ght-proxy" \
      --quiet \
      --project="${PROJECT_ID}" \
      --region="us-east1" \
      --set-secrets="GITHUB_TOKEN=ght-proxy-token:1" \
      --set-env-vars="ALLOWED_SCOPES=match:.*" \
      --image="us-docker.pkg.dev/${PROJECT_ID}/ght-proxy/ght-proxy" \
      --service-account="ght-proxy@${PROJECT_ID}.iam.gserviceaccount.com" \
      --ingress=internal
    ```

    For a GitHub App:

    ```sh
    export GITHUB_INSTALLATION_ID=<VALUE_FROM_GITHUB>
    export GITHUB_APP_ID=<VALUE_FROM_GITHUB>
    gcloud beta run deploy "ght-proxy" \
      --quiet \
      --project="${PROJECT_ID}" \
      --region="us-east1" \
      --set-secrets="GITHUB_APP_PRIVATE_KEY=ght-proxy-app-private-key:1" \
      --set-env-vars="ALLOWED_SCOPES=match:.*,GITHUB_INSTALLATION_ID=${GITHUB_INSTALLATION_ID?},GITHUB_APP_ID=${GITHUB_APP_ID?}" \
      --image="gcr.io/${PROJECT_ID}/ght-proxy" \
      --service-account="ght-proxy@${PROJECT_ID}.iam.gserviceaccount.com" \
      --ingress=internal
    ```


## Configuration

### Personal Access Token (PAT)

To use the GitHub Runner Token Proxy with a Personal Access Token (PAT),
[generate a PAT][create-pat] with the proper scopes on GitHub. Depending on your
needs, the PAT should have either `repo` or `admin:org` permissions. See
[Background](#background) for more information on required permissions.

When deploying the service, set the `GITHUB_TOKEN` environment variable to the
value of your PAT. Take care not to expose this PAT to people with access to
your service. For example, on Google Cloud, the PAT can be stored in Secret
Manager and then injected into the workload at runtime.

PATs have a few downsides, most notably their long-lived nature and overly-broad
permissions. You can further restrict the repositories and organizations for
which your PAT can generate GitHub Actions self-hosted runner tokens by setting
[Allowed scopes](#allowed-scopes). PATs also have stricter API quota limits.
Depending on the rate at which you plan to register and remove GitHub Actions
self-hosted runners, you may exhaust the quota limits for a PAT. At this point,
you will need to switch to a GitHub App.

### GitHub App

To use the GitHub Runner Token Proxy with a GitHub App, first [create a GitHub App][github-app-create]. Since this GitHub App will be for your own internal use:

-   You can set the homepage URL to any value.
-   You can ignore the Callback URL for "Identifying and authorizing users".
-   Do not use any of the OAuth functions.
-   Do not fill in a setup URL.
-   Do not fill in a webhook URL or secret.
-   For required permissions, see [Background](#background) and choose the best
    value based on your needs.
-   Choose where the app can be installed. Since this is a private GitHub App,
    you can choose to restrict it to your organization.

1.  Take note of your numeric App ID.

1.  [Generate a private key][app-private-key] for your GitHub App. You will need
    to inject the contents of this private key into the proxy in a future step.

1.  Install the application in your target organization or enterprise. You can
    install the app from the "Install App" sidebar menu.

1.  Capture the numeric installation ID. The easiest way to capture this ID is
    to grab it from the URL bar.

Provide the following environment variables to the service:

-   `GITHUB_APP_ID` - numeric ID for your GitHub App.

-   `GITHUB_APP_PRIVATE_KEY` - string contents of the private key for your
    GitHub App. Note: treat this like a secret. You may want to store the
    contents in a secret manager and inject them at runtime.

-   `GITHUB_APP_INSTALLATION_ID` - the numeric ID for your GitHub App
    installation in your organization.

### Allowed scopes

**By default, no scopes are permitted** to generate registration or removal
tokens. You must explicitly add scopes to the allowlist.

A scope is an enterprise, organization, or repository. Enterprises and
organizations are specified as their name, and repositories are specified as
their parent-slash-name (e.g. "my-org/my-repo").

You can specify the allowlist as a semicolon-separated list of values in the
`ALLOWED_SCOPES` environment variable. Here are some examples:

-   `my-org/my-repo` - allow only the specified repository.
-   `my-org/my-repo1;my-org/my-repo2` - allow only the specified repositories.

You can also use regular expressions by providing the `match:` prefix. Regular expressions are parsed in the [re2 syntax][re2]:

-   `match:my-org/*` - allow all repositories in the specified org.
-   `match:my-*` - allow all repositories in all organizations as long as the
    organization name starts with the provided prefix.
-   `match:*` - allow everything, **NOT recommended**.

In addition to allowed scopes, you can also specifically deny scopes via the
`DENIED_SCOPES` environment variable. The syntax is identical to above, but
denied scopes are processed _first_, meaning they take precedence over allowed
scopes.

### GitHub Enterprise

Warning: I do not have access to a GitHub Enterprise installation, so these
instructions _should_ work, but have not been tested.

To use a GitHub Enterprise installation instead of the public github.com, start the service with the following environment variables:

-   `GITHUB_API_URL` - the GitHub Enterprise API endpoint; this is usually
    `{url}/api/v3`.

### Bind address and port

By default, the service listens on all interfaces on port 8080.

-   Configure the port by specifying the `PORT` environment variable.
-   Configure the bind address by specifying the `BIND` environment variable.

### Stopping

Gracefully stop the server by sending either `SIGINT` or `SIGTERM`.

[cloud-run]: https://cloud.google.com/run
[create-pat]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
[github-app-create]: https://docs.github.com/en/developers/apps/building-github-apps/creating-a-github-app
[app-private-key]: https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#generating-a-private-key
[repo-runner]: https://docs.github.com/en/actions/hosting-your-own-runners/adding-self-hosted-runners#adding-a-self-hosted-runner-to-a-repository
[org-runner]: https://docs.github.com/en/actions/hosting-your-own-runners/adding-self-hosted-runners#adding-a-self-hosted-runner-to-an-organization
[re2]: https://github.com/google/re2/wiki/Syntax
