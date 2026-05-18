# Jira Integration Reference

This reference provides guidance on detecting and fetching Jira issues across ZoomInfo repositories.

## Detecting Jira Issues

Jira issues can be referenced in two formats:

### 1. Full URL Format
```
https://discoverorg.atlassian.net/browse/ISSUE-ID
```

Example: `https://discoverorg.atlassian.net/browse/ZIP-123`

### 2. Issue Key Pattern
```
ABC-123
```

Where:
- `ABC` is the project key (uppercase letters, numbers, or underscores)
- `123` is the issue number

**Important:** Before assuming a pattern like `ABC-123` is a Jira issue, verify against the repository's autolinks:

```bash
gh api repos/:owner/:repo/autolinks --jq '.[] | .key_prefix'
```

This returns the valid Jira project prefixes configured for the repository.

## Fetching Jira Issue Details

To retrieve full issue details including description, acceptance criteria, and status:

```bash
curl --request GET \
  --url 'https://discoverorg.atlassian.net/rest/api/3/issue/<issue-id>' \
  --user "$ATLASSIAN_USERNAME:$ATLASSIAN_API_TOKEN" \
  --header 'Accept: application/json'
```

### Required Environment Variables

The following environment variables are automatically provided via GitHub Actions secrets in the workflow:

- `ATLASSIAN_USERNAME`: Atlassian account email
- `ATLASSIAN_API_TOKEN`: Atlassian API token

These are configured in `.github/workflows/claude.yml` and do not require additional setup.

## Handling API Failures

If the Jira API request fails:

1. **Note the failure clearly** - Don't silently continue
2. **Check for:**
   - Missing environment variables
   - Invalid credentials
   - Network connectivity issues
   - Issue doesn't exist or user lacks permission
3. **Proceed with available information** - Use PR description, issue comments, or ask user for clarification
4. **Ask for clarification** if requirements are unclear without Jira context. NEVER guess requirements.

## When to Fetch Jira Issues

**Always fetch Jira details when a Jira issue is mentioned** in the context (PR description, issue body, comments, etc.).

Once fetched, use Jira data to:
- **Verify alignment**: Check that changes match acceptance criteria
- **Understand context**: Read full description and comments
- **Guide implementation**: Follow requirements exactly as specified
- **Provide informed answers**: Reference actual issue details in responses
