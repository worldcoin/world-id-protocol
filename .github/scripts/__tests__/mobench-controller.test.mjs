import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const fixturesDir = path.join(
  process.cwd(),
  '.github',
  'scripts',
  '__tests__',
  'fixtures',
);

const fixture = (name) =>
  JSON.parse(fs.readFileSync(path.join(fixturesDir, name), 'utf8'));

const controller = await import('../mobench-controller.mjs');

test('parseMobenchCommand keeps existing webhook defaults', () => {
  assert.deepEqual(controller.parseMobenchCommand('/mobench'), {
    platform: 'both',
    device_profile: 'low-spec',
    ios_device: '',
    ios_os_version: '',
    android_device: '',
    android_os_version: '',
    iterations: '30',
    warmup: '5',
  });
});

test('parseMobenchCommand preserves values with spaces', () => {
  assert.equal(
    controller.parseMobenchCommand(
      '/mobench platform=ios iterations=50 ios_device=iPhone 15 ios_os_version=17',
    ).ios_device,
    'iPhone 15',
  );
});

test('parseMobenchCommand rejects invalid keys and values', () => {
  assert.equal(controller.parseMobenchCommand('/mobench foo=bar'), null);
  assert.equal(controller.parseMobenchCommand('/mobench iterations=0'), null);
});

test('trusted associations are OWNER MEMBER and COLLABORATOR only', () => {
  assert.equal(controller.isTrustedAssociation('MEMBER'), true);
  assert.equal(controller.isTrustedAssociation('COLLABORATOR'), true);
  assert.equal(controller.isTrustedAssociation('FIRST_TIME_CONTRIBUTOR'), false);
});

test('buildDispatchInputs matches the existing webhook normalization contract', () => {
  const inputs = controller.buildDispatchInputs({
    prNumber: 123,
    baseRef: 'release/1.2',
    headSha: 'abc123def456',
    requestedBy: 'octocat',
    triggerSource: 'pr_comment',
    requestCommand:
      '/mobench platform=ios iterations=50 ios_device=iPhone 15 ios_os_version=17',
    overrides: controller.parseMobenchCommand(
      '/mobench platform=ios iterations=50 ios_device=iPhone 15 ios_os_version=17',
    ),
  });

  assert.equal(inputs.pr_number, '123');
  assert.equal(inputs.base_ref, 'release/1.2');
  assert.equal(inputs.head_sha, 'abc123def456');
  assert.equal(inputs.requested_by, 'octocat');
  assert.equal(inputs.trigger_source, 'pr_comment');
  assert.equal(
    inputs.request_command,
    '/mobench platform=ios iterations=50 ios_device=iPhone 15 ios_os_version=17',
  );
});

test('same-repo bench label is required for auto dispatch', () => {
  const payload = fixture('pull_request_labeled_bench.json');
  const pullRequest = {
    ...payload.pull_request,
    labels: [payload.label],
  };
  assert.equal(
    controller.isSameRepoPullRequest(pullRequest, 'worldcoin/world-id-protocol'),
    true,
  );
  assert.equal(controller.hasBenchLabel(pullRequest), true);
});

test('compile gate workflow file exists with stable name', () => {
  const yaml = fs.readFileSync('.github/workflows/compile-gate.yml', 'utf8');
  assert.match(yaml, /^name: Compile Gate$/m);
  assert.match(yaml, /cargo test --all --locked --no-run/);
});

test('workflow_run auto path dispatches only same-repo open PRs with bench label', () => {
  const decision = controller.decideWorkflowRunDispatch({
    workflowRun: {
      conclusion: 'success',
      head_sha: 'abc123',
      head_branch: 'feature/bench-pr',
      pull_requests: [{ number: 123 }],
    },
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'main' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'abc123def456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
      labels: [{ name: 'bench' }],
    },
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, true);
  assert.equal(decision.ref, 'feature/bench-pr');
  assert.equal(decision.inputs.head_sha, 'abc123');
  assert.equal(decision.inputs.trigger_source, 'label');
  assert.equal(decision.inputs.requested_by, 'github-actions');
});

test('workflow_run auto path preserves the compile-gated sha when the PR head has moved', () => {
  const decision = controller.decideWorkflowRunDispatch({
    workflowRun: {
      conclusion: 'success',
      head_sha: 'gated123',
      head_branch: 'feature/bench-pr',
      pull_requests: [{ number: 123 }],
    },
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'main' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'newer456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
      labels: [{ name: 'bench' }],
    },
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, true);
  assert.equal(decision.inputs.head_sha, 'gated123');
});

test('workflow_run auto path rejects closed PRs unlabeled PRs and forks', () => {
  const baseArgs = {
    workflowRun: {
      conclusion: 'success',
      head_sha: 'abc123',
      head_branch: 'feature/bench-pr',
      pull_requests: [{ number: 123 }],
    },
    repositoryFullName: 'worldcoin/world-id-protocol',
  };

  assert.equal(
    controller.decideWorkflowRunDispatch({
      ...baseArgs,
      pullRequest: {
        number: 123,
        state: 'closed',
        base: { ref: 'main' },
        head: {
          ref: 'feature/bench-pr',
          repo: { full_name: 'worldcoin/world-id-protocol' },
        },
        labels: [{ name: 'bench' }],
      },
    }).reason,
    'no-open-pr',
  );

  assert.equal(
    controller.decideWorkflowRunDispatch({
      ...baseArgs,
      pullRequest: {
        number: 123,
        state: 'open',
        base: { ref: 'main' },
        head: {
          ref: 'feature/bench-pr',
          repo: { full_name: 'worldcoin/world-id-protocol' },
        },
        labels: [],
      },
    }).reason,
    'bench-label-missing',
  );

  assert.equal(
    controller.decideWorkflowRunDispatch({
      ...baseArgs,
      pullRequest: {
        number: 123,
        state: 'open',
        base: { ref: 'main' },
        head: {
          ref: 'feature/bench-pr',
          repo: { full_name: 'someone-else/world-id-protocol' },
        },
        labels: [{ name: 'bench' }],
      },
    }).reason,
    'fork-pr',
  );
});

test('bench label dispatches immediately when compile gate already passed for current SHA', () => {
  const decision = controller.decideBenchLabelDispatch({
    labelName: 'bench',
    compileGatePassed: true,
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'main' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'abc123def456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
      labels: [{ name: 'bench' }],
    },
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, true);
  assert.equal(decision.inputs.head_sha, 'abc123def456');
  assert.equal(decision.inputs.trigger_source, 'label');
});

test('bench label exits cleanly when compile gate has not passed yet', () => {
  const decision = controller.decideBenchLabelDispatch({
    labelName: 'bench',
    compileGatePassed: false,
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'main' },
      head: {
        ref: 'feature/bench-pr',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
      labels: [{ name: 'bench' }],
    },
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, false);
  assert.equal(decision.reason, 'compile-gate-pending');
});

test('trusted /mobench comment dispatches only when compile gate already passed', () => {
  const payload = fixture('issue_comment_mobench_custom.json');
  const decision = controller.decideCommentDispatch({
    issueComment: payload.comment,
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'release/1.2' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'abc123def456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
    },
    compileGatePassed: true,
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, true);
  assert.equal(decision.inputs.head_sha, 'abc123def456');
  assert.equal(decision.inputs.trigger_source, 'pr_comment');
  assert.equal(decision.inputs.requested_by, 'octocat');
  assert.equal(
    decision.inputs.request_command,
    '/mobench platform=ios iterations=50 ios_device=iPhone 15 ios_os_version=17',
  );
});

test('untrusted /mobench comment is ignored', () => {
  const decision = controller.decideCommentDispatch({
    issueComment: {
      body: '/mobench',
      author_association: 'NONE',
      user: { login: 'rando' },
    },
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'main' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'abc123def456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
    },
    compileGatePassed: false,
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, false);
  assert.equal(decision.reason, 'untrusted-actor');
});

test('trusted /mobench comment before compile gate green returns a sticky explanation', () => {
  const payload = fixture('issue_comment_mobench_custom.json');
  const decision = controller.decideCommentDispatch({
    issueComment: payload.comment,
    pullRequest: {
      number: 123,
      state: 'open',
      base: { ref: 'release/1.2' },
      head: {
        ref: 'feature/bench-pr',
        sha: 'abc123def456',
        repo: { full_name: 'worldcoin/world-id-protocol' },
      },
    },
    compileGatePassed: false,
    repositoryFullName: 'worldcoin/world-id-protocol',
  });

  assert.equal(decision.dispatch, false);
  assert.equal(decision.reason, 'compile-gate-pending');
  assert.match(
    decision.commentBody,
    /required CI for the current head SHA .* has not passed/i,
  );
});

test('mobile-bench runner has stateless concurrency and exact sha plumbing', () => {
  const runnerYaml = fs.readFileSync('.github/workflows/mobile-bench.yml', 'utf8');
  const reusableYaml = fs.readFileSync('.github/workflows/reusable-bench.yml', 'utf8');
  const labelYaml = fs.readFileSync('.github/workflows/mobile-bench-pr-auto.yml', 'utf8');
  const commandYaml = fs.readFileSync('.github/workflows/mobile-bench-pr-command.yml', 'utf8');

  assert.match(runnerYaml, /^\s*base_ref:\s*$/m);
  assert.match(runnerYaml, /^\s*head_sha:\s*$/m);
  assert.match(runnerYaml, /^concurrency:/m);
  assert.match(runnerYaml, /trigger_source == 'pr_comment' && 'comment'/);
  assert.match(
    runnerYaml,
    /cancel-in-progress:\s+\${{\s*inputs\.trigger_source == 'label'\s*}}/,
  );
  assert.match(reusableYaml, /ref:\s+\${{\s*inputs\.head_sha \|\| github\.sha\s*}}/);
  assert.match(reusableYaml, /cargo-mobench build --target ios .*--crate-path "\${{ inputs\.crate_path }}"/);
  assert.match(reusableYaml, /cargo-mobench run \\\s*\n\s+--target ios[\s\S]*?--crate-path "\${{ inputs\.crate_path }}"/);
  assert.match(reusableYaml, /cargo-mobench build --target android .*--crate-path "\${{ inputs\.crate_path }}"/);
  assert.match(reusableYaml, /cargo-mobench run \\\s*\n\s+--target android[\s\S]*?--crate-path "\${{ inputs\.crate_path }}"/);
  assert.match(labelYaml, /^name: Mobile Bench PR Auto$/m);
  assert.match(commandYaml, /^name: Mobile Bench PR Command$/m);
});
