---
name: answer-question-default
description: This skill must be used when the user mentions "User @username commented comment '456' on issue '#123' and tagged you in it" or asks questions like "how does X work" or "explain this code". Uses Sourcegraph code search and internal documentation for comprehensive answers.
---

# Answer Question Skill

Use this skill when asked to answer questions, provide explanations, or give guidance in PR or issue comments.

## Response Workflow

### 1. Analyze the Question
Identify what's being asked:
- Technical explanation or clarification
- "How to" implement something
- Why certain patterns are used
- Debugging assistance
- Architecture or design guidance

### 2. Decide if Search Tools Are Needed
Search tools are helpful when:
- Question involves ZoomInfo-specific standards or patterns
- Answering "how to" questions about implementations
- Uncertain about ZoomInfo best practices for the specific case
- Question references patterns in other repositories

**Skip search tools for:**
- General programming questions
- Questions about code visible in the current context
- Simple clarifications

### 3. Search Documentation (if needed)
Query internal ZoomInfo engineering documentation to provide authoritative answers.

**See:** [Documentation Search Best Practices](../_shared/references/documentation-search.md) for effective search strategies.

### 4. Search Golden Repos (if needed)
When the question is about "how we do X" or references other ZoomInfo repos, search golden repositories for code examples.

**See:** [Sourcegraph Search Guidelines](../_shared/references/sourcegraph-search.md) for code search techniques.

### 5. Provide the Answer
- Be detailed and actionable
- Include relevant code snippets and references
- Link to documentation where appropriate
- Provide links to golden repo examples when searches were used
- If you can't fully answer, explain what's unclear and ask for more context

## Response Format
- Direct and clear answers
- Code examples when helpful
- Links to relevant resources
- Acknowledge limitations or uncertainties honestly
