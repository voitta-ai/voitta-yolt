---
name: implement-issue-default
description: This skill must be used when the user mentions "User @username opened issue '#123' and tagged you" or "User @username assigned you to Issue '#123'", or asks to "implement issue" or "fix issue". Retrieves issue details, creates branches, implements changes, and creates pull requests.
---

# Issue Implementation Skill

Use this skill when asked to implement a feature, fix a bug, or make code changes based on a GitHub issue.

## Implementation Workflow

### 1. Analyze the Task
Identify what needs to be implemented:
- Technologies and libraries involved
- Patterns and integrations required
- APIs to consume or expose

### 2. Decide if Search Tools Are Needed
Search tools are REQUIRED when:
- Using technologies/libraries not currently in the codebase
- Integrating with external APIs or services
- Implementing patterns that might exist in golden repos (CLI commands, NestJS endpoints, Angular components, etc.)

**Skip search tools for:**
- Simple/straightforward tasks with clear solutions
- Minor modifications to existing patterns
- Bug fixes with obvious solutions

### 3. Search Documentation (if needed)
Query internal ZoomInfo engineering documentation for relevant standards and patterns.

**See:** [Documentation Search Best Practices](../_shared/references/documentation-search.md) for effective query strategies.

### 4. Search Golden Repos (if needed)
Search for similar implementations in golden repositories to follow established patterns.

**See:** [Sourcegraph Search Guidelines](../_shared/references/sourcegraph-search.md) for code search techniques.

### 5. Implement the Changes
- Follow found standards and patterns from searches
- Follow repository's existing coding conventions
- Include reference links in PR description when searches were used
- Ensure Unix-style LF (`\n`) line endings

### 6. Create Pull Request
- Create a new branch prefixed with `zip/`
- Use [Conventional Commits](https://www.conventionalcommits.org/) format
- Link PR to original issue in the "Development" section
- Add a comment to the relevant issue with your response
