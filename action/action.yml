name: "SlopGuard"
description: "Security scanner for AI-generated code: catches hallucinated dependencies, unsafe patterns, and intent drift."
author: "Paarth Agl"

inputs:
  path:
    description: "Path to scan (default: repo root)"
    required: false
    default: "."
  fail-on:
    description: "Minimum severity that fails the build: critical | high | medium | low"
    required: false
    default: "high"
  exclude:
    description: "Comma-separated paths to exclude from scan"
    required: false
    default: ""
  github-token:
    description: "GitHub token for API calls — pass secrets.GITHUB_TOKEN from the workflow"
    required: false
    default: ""

runs:
  using: "docker"
  image: "Dockerfile"
  env:
    INPUT_PATH: ${{ inputs.path }}
    INPUT_FAIL_ON: ${{ inputs.fail-on }}
    INPUT_EXCLUDE: ${{ inputs.exclude }}
    GITHUB_TOKEN: ${{ inputs.github-token }}

branding:
  icon: "shield"
  color: "purple"
