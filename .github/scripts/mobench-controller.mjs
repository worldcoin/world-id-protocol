export const COMPILE_GATE_WORKFLOW_FILE = 'compile-gate.yml';
export const COMPILE_GATE_WORKFLOW_NAME = 'Compile Gate';
export const MOBILE_BENCH_WORKFLOW_FILE = 'mobile-bench.yml';
export const COMMENT_MARKER = '<!-- mobench-compile-gate -->';
export const TRUSTED_ASSOCIATIONS = new Set([
  'OWNER',
  'MEMBER',
  'COLLABORATOR',
]);

export const DEFAULT_INPUTS = {
  platform: 'both',
  device_profile: 'low-spec',
  ios_device: '',
  ios_os_version: '',
  android_device: '',
  android_os_version: '',
  iterations: '30',
  warmup: '5',
};

const MOBENCH_COMMAND = '/mobench';
const ALLOWED_KEYS = new Set(Object.keys(DEFAULT_INPUTS));

export function isTrustedAssociation(association) {
  return TRUSTED_ASSOCIATIONS.has(association ?? '');
}

export function isSameRepoPullRequest(pullRequest, repositoryFullName) {
  return pullRequest?.head?.repo?.full_name === repositoryFullName;
}

export function hasBenchLabel(pullRequest) {
  return (pullRequest?.labels ?? []).some((label) => label.name === 'bench');
}

export function parseMobenchCommand(body) {
  const commandLine = body
    ?.split(/\r?\n/u)
    .map((line) => line.trim())
    .find((line) => line.length > 0);
  if (!commandLine?.startsWith(MOBENCH_COMMAND)) {
    return null;
  }

  const command = commandLine.slice(MOBENCH_COMMAND.length);
  if (command.length > 0 && !/^\s/u.test(command)) {
    return null;
  }

  const args = { ...DEFAULT_INPUTS };
  const remainder = command.trim();
  if (remainder.length === 0) {
    return args;
  }

  let currentKey = null;
  let currentValue = '';

  for (const token of remainder.split(/\s+/u)) {
    const separatorIndex = token.indexOf('=');
    if (separatorIndex !== -1) {
      if (!applyToken(args, currentKey, currentValue)) {
        return null;
      }
      currentValue = '';

      const key = token.slice(0, separatorIndex);
      const value = token.slice(separatorIndex + 1);
      if (!ALLOWED_KEYS.has(key)) {
        return null;
      }

      currentKey = key;
      currentValue = value;
      continue;
    }

    if (!currentKey) {
      return null;
    }

    currentValue = currentValue ? `${currentValue} ${token}` : token;
  }

  if (!applyToken(args, currentKey, currentValue)) {
    return null;
  }

  return validateArgs(args) ? args : null;
}

export function buildDispatchInputs({
  prNumber,
  baseRef,
  headSha,
  requestedBy,
  triggerSource,
  requestCommand,
  overrides,
}) {
  return {
    ...DEFAULT_INPUTS,
    ...overrides,
    pr_number: String(prNumber),
    base_ref: baseRef,
    head_sha: headSha ?? '',
    requested_by: requestedBy,
    trigger_source: triggerSource,
    request_command: requestCommand ?? '',
    dispatch_id: '',
  };
}

export function decideWorkflowRunDispatch({
  workflowRun,
  pullRequest,
  repositoryFullName,
}) {
  if (workflowRun?.conclusion !== 'success') {
    return { dispatch: false, reason: 'compile-gate-failed' };
  }
  if (!pullRequest || pullRequest.state !== 'open') {
    return { dispatch: false, reason: 'no-open-pr' };
  }
  if (!isSameRepoPullRequest(pullRequest, repositoryFullName)) {
    return { dispatch: false, reason: 'fork-pr' };
  }
  if (!hasBenchLabel(pullRequest)) {
    return { dispatch: false, reason: 'bench-label-missing' };
  }

  return {
    dispatch: true,
    ref: workflowRun.head_branch,
    inputs: buildDispatchInputs({
      prNumber: pullRequest.number,
      baseRef: pullRequest.base.ref,
      headSha: workflowRun.head_sha,
      requestedBy: 'github-actions',
      triggerSource: 'label',
      requestCommand: '',
      overrides: DEFAULT_INPUTS,
    }),
  };
}

export function decideBenchLabelDispatch({
  labelName,
  compileGatePassed,
  pullRequest,
  repositoryFullName,
}) {
  if (labelName !== 'bench') {
    return { dispatch: false, reason: 'not-bench-label' };
  }
  if (!pullRequest || pullRequest.state !== 'open') {
    return { dispatch: false, reason: 'pr-closed' };
  }
  if (!isSameRepoPullRequest(pullRequest, repositoryFullName)) {
    return { dispatch: false, reason: 'fork-pr' };
  }
  if (!compileGatePassed) {
    return { dispatch: false, reason: 'compile-gate-pending' };
  }

  return {
    dispatch: true,
    ref: pullRequest.head.ref,
    inputs: buildDispatchInputs({
      prNumber: pullRequest.number,
      baseRef: pullRequest.base.ref,
      headSha: pullRequest.head.sha,
      requestedBy: 'github-actions',
      triggerSource: 'label',
      requestCommand: '',
      overrides: DEFAULT_INPUTS,
    }),
  };
}

export function buildCompileGatePendingComment({ sha, workflowName }) {
  return `${COMMENT_MARKER}
Required CI for the current head SHA \`${sha}\` has not passed yet.

Benchmarks were not started. Wait for **${workflowName}** to succeed for this exact commit, then retry \`/mobench\`.`;
}

export function decideCommentDispatch({
  issueComment,
  pullRequest,
  compileGatePassed,
  repositoryFullName,
}) {
  if (!pullRequest) {
    return { dispatch: false, reason: 'not-a-pr-comment' };
  }
  if (!isTrustedAssociation(issueComment?.author_association)) {
    return { dispatch: false, reason: 'untrusted-actor' };
  }
  if (pullRequest.state !== 'open') {
    return { dispatch: false, reason: 'pr-closed' };
  }
  if (!isSameRepoPullRequest(pullRequest, repositoryFullName)) {
    return { dispatch: false, reason: 'fork-pr' };
  }

  const overrides = parseMobenchCommand(issueComment?.body ?? '');
  if (!overrides) {
    return { dispatch: false, reason: 'not-a-valid-command' };
  }
  if (!compileGatePassed) {
    return {
      dispatch: false,
      reason: 'compile-gate-pending',
      commentBody: buildCompileGatePendingComment({
        sha: pullRequest.head.sha,
        workflowName: COMPILE_GATE_WORKFLOW_NAME,
      }),
    };
  }

  return {
    dispatch: true,
    ref: pullRequest.head.ref,
    inputs: buildDispatchInputs({
      prNumber: pullRequest.number,
      baseRef: pullRequest.base.ref,
      headSha: pullRequest.head.sha,
      requestedBy: issueComment.user.login,
      triggerSource: 'pr_comment',
      requestCommand: issueComment.body.trim(),
      overrides,
    }),
  };
}

export async function handleWorkflowRun({ github, context, core }) {
  const workflowRun = context.payload.workflow_run;
  if (!workflowRun) {
    core.setFailed('Missing workflow_run payload.');
    return;
  }

  const repositoryFullName = `${context.repo.owner}/${context.repo.repo}`;
  const pullNumber = await findAssociatedPullRequestNumber({
    github,
    owner: context.repo.owner,
    repo: context.repo.repo,
    repositoryFullName,
    workflowRun,
  });

  if (!pullNumber) {
    core.info(
      `No associated pull request found for workflow run ${workflowRun.id ?? 'unknown'}.`,
    );
    return;
  }

  const pullRequest = (
    await github.rest.pulls.get({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: pullNumber,
    })
  ).data;

  const decision = decideWorkflowRunDispatch({
    workflowRun,
    pullRequest,
    repositoryFullName,
  });
  if (!decision.dispatch) {
    core.info(`Skipping mobench dispatch: ${decision.reason}.`);
    return;
  }

  await github.rest.actions.createWorkflowDispatch({
    owner: context.repo.owner,
    repo: context.repo.repo,
    workflow_id: MOBILE_BENCH_WORKFLOW_FILE,
    ref: decision.ref,
    inputs: decision.inputs,
  });

  core.notice(
    `Dispatched ${MOBILE_BENCH_WORKFLOW_FILE} for PR #${pullRequest.number} at ${workflowRun.head_sha}.`,
  );
}

export async function handleBenchLabelEvent({ github, context, core }) {
  const repositoryFullName = `${context.repo.owner}/${context.repo.repo}`;
  const labelName = context.payload.label?.name ?? '';
  const pullRequest = withBenchLabel(
    context.payload.pull_request,
    context.payload.label,
  );
  const compileGatePassed = pullRequest
    ? await hasSuccessfulCompileGateForSha({
        github,
        owner: context.repo.owner,
        repo: context.repo.repo,
        headSha: pullRequest.head?.sha,
      })
    : false;

  const decision = decideBenchLabelDispatch({
    labelName,
    compileGatePassed,
    pullRequest,
    repositoryFullName,
  });
  if (!decision.dispatch) {
    core.info(`Skipping mobench dispatch: ${decision.reason}.`);
    return;
  }

  await github.rest.actions.createWorkflowDispatch({
    owner: context.repo.owner,
    repo: context.repo.repo,
    workflow_id: MOBILE_BENCH_WORKFLOW_FILE,
    ref: decision.ref,
    inputs: decision.inputs,
  });

  core.notice(
    `Dispatched ${MOBILE_BENCH_WORKFLOW_FILE} for PR #${pullRequest.number} from bench label event.`,
  );
}

export async function handleIssueCommentEvent({ github, context, core }) {
  const issue = context.payload.issue;
  const issueComment = context.payload.comment;
  const repositoryFullName = `${context.repo.owner}/${context.repo.repo}`;

  if (!issue?.pull_request) {
    core.info('Skipping mobench dispatch: not-a-pr-comment.');
    return;
  }
  if (!isTrustedAssociation(issueComment?.author_association)) {
    core.info('Skipping mobench dispatch: untrusted-actor.');
    return;
  }
  if (!parseMobenchCommand(issueComment?.body ?? '')) {
    core.info('Skipping mobench dispatch: not-a-valid-command.');
    return;
  }

  const pullRequest = (
    await github.rest.pulls.get({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: issue.number,
    })
  ).data;
  const compileGatePassed = await hasSuccessfulCompileGateForSha({
    github,
    owner: context.repo.owner,
    repo: context.repo.repo,
    headSha: pullRequest.head?.sha,
  });

  const decision = decideCommentDispatch({
    issueComment,
    pullRequest,
    compileGatePassed,
    repositoryFullName,
  });
  if (!decision.dispatch) {
    if (decision.reason === 'compile-gate-pending' && decision.commentBody) {
      await upsertIssueComment({
        github,
        owner: context.repo.owner,
        repo: context.repo.repo,
        issueNumber: issue.number,
        body: decision.commentBody,
      });
    }
    core.info(`Skipping mobench dispatch: ${decision.reason}.`);
    return;
  }

  await github.rest.actions.createWorkflowDispatch({
    owner: context.repo.owner,
    repo: context.repo.repo,
    workflow_id: MOBILE_BENCH_WORKFLOW_FILE,
    ref: decision.ref,
    inputs: decision.inputs,
  });

  core.notice(
    `Dispatched ${MOBILE_BENCH_WORKFLOW_FILE} for PR #${pullRequest.number} from /mobench comment.`,
  );
}

function applyToken(args, key, value) {
  if (!key) {
    return true;
  }
  if (!ALLOWED_KEYS.has(key)) {
    return false;
  }

  args[key] = value;
  return true;
}

function validateArgs(args) {
  if (!['ios', 'android', 'both'].includes(args.platform)) {
    return false;
  }

  return [args.iterations, args.warmup].every(isPositiveInteger);
}

function isPositiveInteger(value) {
  if (!/^\d+$/u.test(value)) {
    return false;
  }

  return Number.parseInt(value, 10) > 0;
}

async function findAssociatedPullRequestNumber({
  github,
  owner,
  repo,
  repositoryFullName,
  workflowRun,
}) {
  const directPullNumber = workflowRun.pull_requests
    ?.find((pullRequest) => Number.isInteger(pullRequest.number))
    ?.number;
  if (directPullNumber) {
    return directPullNumber;
  }

  const response =
    await github.rest.repos.listPullRequestsAssociatedWithCommit({
      owner,
      repo,
      commit_sha: workflowRun.head_sha,
    });
  const pullRequests = response.data ?? [];

  return (
    pullRequests.find((pullRequest) =>
      pullRequest.state === 'open' &&
      isSameRepoPullRequest(pullRequest, repositoryFullName) &&
      pullRequest.head?.sha === workflowRun.head_sha,
    )?.number ??
    pullRequests.find((pullRequest) =>
      pullRequest.state === 'open' &&
      isSameRepoPullRequest(pullRequest, repositoryFullName) &&
      pullRequest.head?.ref === workflowRun.head_branch,
    )?.number ??
    null
  );
}

async function hasSuccessfulCompileGateForSha({ github, owner, repo, headSha }) {
  if (!headSha) {
    return false;
  }

  const response = await github.rest.actions.listWorkflowRuns({
    owner,
    repo,
    workflow_id: COMPILE_GATE_WORKFLOW_FILE,
    event: 'pull_request',
    head_sha: headSha,
    per_page: 20,
  });

  return (response.data.workflow_runs ?? []).some(
    (workflowRun) =>
      workflowRun.head_sha === headSha &&
      workflowRun.conclusion === 'success',
  );
}

function withBenchLabel(pullRequest, label) {
  if (!pullRequest) {
    return null;
  }
  if (pullRequest.labels) {
    return pullRequest;
  }
  if (!label?.name) {
    return pullRequest;
  }

  return {
    ...pullRequest,
    labels: [label],
  };
}

async function upsertIssueComment({ github, owner, repo, issueNumber, body }) {
  const response = await github.rest.issues.listComments({
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  const existingComment = (response.data ?? []).find((comment) =>
    comment.body?.includes(COMMENT_MARKER),
  );

  if (existingComment) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existingComment.id,
      body,
    });
    return;
  }

  await github.rest.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body,
  });
}
