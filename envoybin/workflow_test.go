package envoybin_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// The tests of the envoy workflow are in this package for two reasons. The
// workflow guards the pin of this package, and this package is in the
// module at the root of the repository. The go command caches the result
// of a test. It drops the result only when a file that the test read
// inside its own module changes. A test in a module below the root
// therefore keeps its cached result after a change to the workflow.

// Path of the envoy workflow, and the names of its jobs and steps that the
// tests read. The path is relative to the directory of this package.
const (
	workflowPath = "../.github/workflows/envoy.yaml"

	jobChanges = "changes"
	jobVerify  = "verify"
	jobResult  = "result"

	stepDiff   = "Find changes that the verify jobs check"
	stepVerify = "Verify the pinned Envoy build"
	stepLoad   = "Load the proxy bootstraps with the pinned Envoy build"
	stepResult = "Check the results of the other jobs"
)

// The test that the load step of the envoy workflow runs, and the
// variable that turns the test on. The test is in the terrarium command,
// and loadTestPath is the path of its file. The path is relative to the
// directory of this package.
const (
	loadTestPath = "../cmd/terrarium/proxy_bootstrap_test.go"
	loadTestName = "TestPinnedEnvoyLoadsProxyBootstraps"
	loadTestEnv  = "TERRARIUM_TEST_ENVOY_DIR"
)

// workflow holds the fields of a GitHub Actions workflow that the tests
// read.
type workflow struct {
	On   map[string]map[string]any `yaml:"on"`
	Jobs map[string]workflowJob    `yaml:"jobs"`
}

// workflowJob is one job of a [workflow].
type workflowJob struct {
	Outputs  map[string]string `yaml:"outputs"`
	Name     string            `yaml:"name"`
	If       string            `yaml:"if"`
	Needs    []string          `yaml:"needs"`
	Steps    []workflowStep    `yaml:"steps"`
	Strategy workflowStrategy  `yaml:"strategy"`
}

// workflowStrategy is the strategy of a [workflowJob].
type workflowStrategy struct {
	Matrix workflowMatrix `yaml:"matrix"`
}

// workflowMatrix is the matrix of a [workflowStrategy]. GitHub runs the
// job one time for each entry of Include, with the values of that entry.
type workflowMatrix struct {
	Include []map[string]string `yaml:"include"`
}

// workflowStep is one step of a [workflowJob].
type workflowStep struct {
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
}

// readEnvoyWorkflow parses the envoy workflow of the repository.
func readEnvoyWorkflow(t *testing.T) workflow {
	t.Helper()

	data, err := os.ReadFile(filepath.FromSlash(workflowPath))
	require.NoError(t, err)

	var wf workflow

	require.NoError(t, yaml.Unmarshal(data, &wf))

	return wf
}

// step returns the step of the job that has the given name.
func (j workflowJob) step(t *testing.T, name string) workflowStep {
	t.Helper()

	for _, s := range j.Steps {
		if s.Name == name {
			return s
		}
	}

	require.FailNow(t, "the job has no step with the name "+name)

	return workflowStep{}
}

// scriptEnv returns a process environment that holds PATH, a home
// directory under dir, and the given variables. It keeps the settings of
// the user and of the host away from git.
func scriptEnv(dir string, vars map[string]string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}

	for k, v := range vars {
		env = append(env, k+"="+v)
	}

	return env
}

// runStep runs the script of a workflow step in dir with the given
// variables, the way that GitHub runs a step on a Linux runner. It returns
// the output of the script and the error of the shell.
func runStep(t *testing.T, step workflowStep, dir string, vars map[string]string) (string, error) {
	t.Helper()

	require.NotEmpty(t, step.Run, "the step %q runs no script", step.Name)

	cmd := exec.CommandContext(t.Context(), "bash", "-e", "-c", step.Run)
	cmd.Dir = dir
	cmd.Env = scriptEnv(dir, vars)

	out, err := cmd.CombinedOutput()

	return string(out), err
}

// git runs a git command in the repository at dir and returns its output
// without the final newline.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	cmd.Env = scriptEnv(dir, nil)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)

	return strings.TrimSpace(string(out))
}

// gitCommit changes each of the paths in the repository at dir and records
// the changes in one commit. The paths are relative to dir.
func gitCommit(t *testing.T, dir string, paths ...string) {
	t.Helper()

	for _, p := range paths {
		file := filepath.Join(dir, filepath.FromSlash(p))

		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))

		f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		require.NoError(t, err)

		_, err = f.WriteString("change\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	git(t, dir, "add", "--all")
	git(t, dir, "commit", "--quiet", "--message", "change "+strings.Join(paths, " "))
}

// TestWorkflowReportsOneResult checks the parts of the envoy workflow that
// make its result job fit for a required status check. The workflow must
// start for every pull request, and the result job must run whatever the
// other jobs did.
func TestWorkflowReportsOneResult(t *testing.T) {
	t.Parallel()

	wf := readEnvoyWorkflow(t)

	// GitHub skips a workflow whose trigger has a filter that does not
	// match. A required check of that workflow then never reports, and
	// the pull request stays blocked.
	require.Contains(t, wf.On, "pull_request")
	assert.Empty(t, wf.On["pull_request"])
	require.Contains(t, wf.On, "push")
	assert.Equal(t, map[string]any{"branches": []any{"main"}}, wf.On["push"])

	changes := wf.Jobs[jobChanges]

	assert.Empty(t, changes.If)
	assert.Empty(t, changes.Needs)
	assert.Equal(t, map[string]string{"verify": "${{ steps.diff.outputs.verify }}"}, changes.Outputs)

	// The diff step reads the commit before a push, so the checkout must
	// fetch the history.
	require.NotEmpty(t, changes.Steps)
	assert.EqualValues(t, 0, changes.Steps[0].With["fetch-depth"])

	diff := changes.step(t, stepDiff)

	assert.Equal(t, "diff", diff.ID)
	assert.Equal(t, map[string]string{
		"EVENT_NAME": "${{ github.event_name }}",
		"BEFORE":     "${{ github.event.before }}",
	}, diff.Env)

	verify := wf.Jobs[jobVerify]

	assert.Equal(t, []string{jobChanges}, verify.Needs)
	assert.Equal(t, "${{ needs.changes.outputs.verify == 'true' }}", verify.If)

	result := wf.Jobs[jobResult]

	// A branch rule names a required check by the name of its job, so the
	// name must not depend on the run. Without the always() condition,
	// GitHub skips the job after a verify job fails, and a skipped job
	// satisfies a required check.
	assert.Equal(t, "envoy-pin", result.Name)
	assert.Equal(t, "${{ always() }}", result.If)
	assert.ElementsMatch(t, []string{jobChanges, jobVerify}, result.Needs)
	assert.Equal(t, map[string]string{
		"CHANGES_RESULT": "${{ needs.changes.result }}",
		"VERIFY_NEEDED":  "${{ needs.changes.outputs.verify }}",
		"VERIFY_RESULT":  "${{ needs.verify.result }}",
	}, result.step(t, stepResult).Env)
}

// TestWorkflowCoversManifestPlatforms checks that the envoy workflow has
// one verify job for each platform of [envoybin.DefaultManifest]. A
// platform without a job gets no provenance check.
func TestWorkflowCoversManifestPlatforms(t *testing.T) {
	t.Parallel()

	verify := readEnvoyWorkflow(t).Jobs[jobVerify]

	// The verify command fails when the runner is not the platform of
	// its matrix entry.
	step := verify.step(t, stepVerify)

	assert.Equal(t, `go run ./cmd/envoymanifest verify "$PLATFORM"`, step.Run)
	assert.Equal(t, "${{ matrix.platform }}", step.Env["PLATFORM"])

	var jobs []string

	for _, entry := range verify.Strategy.Matrix.Include {
		jobs = append(jobs, entry["platform"])
	}

	var want []string

	for p := range envoybin.DefaultManifest().Builds {
		want = append(want, p.String())
	}

	assert.ElementsMatch(t, want, jobs)
}

// TestWorkflowLoadsProxyBootstraps checks that each verify job of the
// envoy workflow runs the test that loads the proxy bootstraps with the
// pinned Envoy build. That test skips without its variable, and the go
// command passes when a pattern matches no test. A step with a stale name
// therefore passes and checks nothing. This test compares the names of
// the step with the names in the file of the test.
func TestWorkflowLoadsProxyBootstraps(t *testing.T) {
	t.Parallel()

	verify := readEnvoyWorkflow(t).Jobs[jobVerify]

	step := verify.step(t, stepLoad)

	// The -count flag turns off the test cache, and the pattern matches
	// exactly one test.
	assert.Equal(t, "go test -count=1 -run '^"+loadTestName+"$' ./cmd/terrarium", step.Run)

	// The test installs the build into the directory of the variable. A
	// directory of the runner keeps the build out of the checkout.
	assert.Equal(t, map[string]string{loadTestEnv: "${{ runner.temp }}/envoy"}, step.Env)

	// The step must run a build only after the provenance checks of that
	// build passed.
	names := make([]string, 0, len(verify.Steps))

	for _, s := range verify.Steps {
		names = append(names, s.Name)
	}

	assert.Less(t, slices.Index(names, stepVerify), slices.Index(names, stepLoad))

	src, err := os.ReadFile(filepath.FromSlash(loadTestPath))
	require.NoError(t, err)

	assert.Contains(t, string(src), "\nfunc "+loadTestName+"(t *testing.T) {\n")
	assert.Contains(t, string(src), "\nconst pinnedEnvoyDirEnv = \""+loadTestEnv+"\"\n")
}

// TestWorkflowFindsChanges runs the diff step of the envoy workflow in a
// repository that holds one change. The verify output of the step decides
// whether the verify jobs run. The verify jobs check the pin, and they
// load the proxy bootstraps with the pinned builds. A change to the pin
// or to the code that generates the bootstraps must therefore start them.
func TestWorkflowFindsChanges(t *testing.T) {
	t.Parallel()

	const (
		eventPullRequest = "pull_request"
		eventPush        = "push"
		eventManual      = "workflow_dispatch"

		readme   = "README.md"
		manifest = "envoybin/manifest.go"
	)

	type changeTest struct {
		// event is the name of the event that starts the workflow.
		event string
		// before replaces the commit before a push when it is not empty.
		before string
		// want is the value of the verify output.
		want string
		// commits holds the paths that each commit of the change touches.
		commits [][]string
		// base holds the paths that the base branch of a pull request
		// touches after the change forks from it.
		base []string
	}

	tests := map[string]changeTest{
		"pull request changes the manifest": {
			event:   eventPullRequest,
			commits: [][]string{{manifest}},
			want:    "true",
		},
		"pull request changes the manifest in an earlier commit": {
			event:   eventPullRequest,
			commits: [][]string{{manifest}, {readme}},
			want:    "true",
		},
		"pull request changes the manifest tool": {
			event:   eventPullRequest,
			commits: [][]string{{"cmd/envoymanifest/verify.go"}},
			want:    "true",
		},
		"pull request changes the Go version": {
			event:   eventPullRequest,
			commits: [][]string{{"go.work"}},
			want:    "true",
		},
		"pull request changes the workspace sums": {
			event:   eventPullRequest,
			commits: [][]string{{"go.work.sum"}},
			want:    "true",
		},
		"pull request changes the workflow": {
			event:   eventPullRequest,
			commits: [][]string{{".github/workflows/envoy.yaml"}},
			want:    "true",
		},
		"pull request changes the bootstrap generator": {
			event:   eventPullRequest,
			commits: [][]string{{"envoy/route.go"}},
			want:    "true",
		},
		"pull request changes the proxy command": {
			event:   eventPullRequest,
			commits: [][]string{{"cmd/terrarium/proxy.go"}},
			want:    "true",
		},
		"pull request changes the tests of the proxy bootstraps": {
			event:   eventPullRequest,
			commits: [][]string{{"cmd/terrarium/proxy_bootstrap_test.go"}},
			want:    "true",
		},
		"pull request changes the module requirements": {
			event:   eventPullRequest,
			commits: [][]string{{"go.mod"}},
			want:    "true",
		},
		"pull request changes the module sums": {
			event:   eventPullRequest,
			commits: [][]string{{"go.sum"}},
			want:    "true",
		},
		"pull request changes other files": {
			event:   eventPullRequest,
			commits: [][]string{{readme}, {"firewall/rules.go", ".github/workflows/validate.yaml"}},
			want:    "false",
		},
		"base branch changes the manifest after the fork": {
			event:   eventPullRequest,
			commits: [][]string{{readme}},
			base:    []string{manifest},
			want:    "false",
		},
		"push changes the manifest": {
			event:   eventPush,
			commits: [][]string{{manifest}},
			want:    "true",
		},
		"push changes the manifest in an earlier commit": {
			event:   eventPush,
			commits: [][]string{{manifest}, {readme}},
			want:    "true",
		},
		"push changes the bootstrap generator": {
			event:   eventPush,
			commits: [][]string{{"envoy/route.go"}, {readme}},
			want:    "true",
		},
		"push changes other files": {
			event:   eventPush,
			commits: [][]string{{readme}, {"dnsproxy/proxy.go"}},
			want:    "false",
		},
		"push creates the branch": {
			event:   eventPush,
			before:  strings.Repeat("0", 40),
			commits: [][]string{{readme}},
			want:    "true",
		},
		"push replaces a commit that the history does not hold": {
			event:   eventPush,
			before:  strings.Repeat("1", 40),
			commits: [][]string{{readme}},
			want:    "true",
		},
		"manual run": {
			event:   eventManual,
			commits: [][]string{{readme}},
			want:    "true",
		},
	}

	// A package that the generator of the proxy bootstraps imports can
	// change the bootstraps, so a change to it must start the verify jobs.
	for _, dir := range bootstrapPackageDirs(t) {
		tests["pull request changes the package in "+dir] = changeTest{
			event:   eventPullRequest,
			commits: [][]string{{dir + "/change.go"}},
			want:    "true",
		}
	}

	step := readEnvoyWorkflow(t).Jobs[jobChanges].step(t, stepDiff)

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			git(t, dir, "init", "--quiet", "--initial-branch", "main")
			gitCommit(t, dir, "LICENSE")

			vars := map[string]string{
				"EVENT_NAME":    tt.event,
				"GITHUB_OUTPUT": filepath.Join(t.TempDir(), "output"),
			}

			if tt.event == eventPush {
				vars["BEFORE"] = git(t, dir, "rev-parse", "HEAD")
			}

			if tt.before != "" {
				vars["BEFORE"] = tt.before
			}

			if tt.event == eventPullRequest {
				git(t, dir, "switch", "--quiet", "--create", "change")
			}

			for _, paths := range tt.commits {
				gitCommit(t, dir, paths...)
			}

			// GitHub checks out the merge of the pull request into its
			// base branch. The base branch is the first parent.
			if tt.event == eventPullRequest {
				git(t, dir, "switch", "--quiet", "main")

				if len(tt.base) > 0 {
					gitCommit(t, dir, tt.base...)
				}

				git(t, dir, "merge", "--quiet", "--no-ff", "--message", "merge", "change")
			}

			out, err := runStep(t, step, dir, vars)
			require.NoError(t, err, out)

			got, err := os.ReadFile(vars["GITHUB_OUTPUT"])
			require.NoError(t, err)

			assert.Equal(t, "verify="+tt.want+"\n", string(got))
		})
	}
}

// bootstrapPackageDirs returns the directory of each package of the
// repository that the envoy and certs packages import, with those two
// packages. The directories are relative to the root of the repository,
// with forward slashes. The proxy command generates its bootstraps with
// the envoy package and creates their certificates with the certs
// package.
func bootstrapPackageDirs(t *testing.T) []string {
	t.Helper()

	root, err := filepath.Abs("..")
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps",
		"-f", "{{if .Module}}{{if .Module.Main}}{{.Dir}}{{end}}{{end}}",
		"./envoy", "./certs")
	cmd.Dir = root

	out, err := cmd.Output()
	require.NoError(t, err)

	var dirs []string

	for line := range strings.Lines(string(out)) {
		dir := strings.TrimSpace(line)
		if dir == "" {
			continue
		}

		rel, err := filepath.Rel(root, dir)
		require.NoError(t, err)

		dirs = append(dirs, filepath.ToSlash(rel))
	}

	require.Contains(t, dirs, "envoy")
	require.Contains(t, dirs, "certs")

	return dirs
}

// TestWorkflowResult runs the step of the result job of the envoy workflow
// with the results that GitHub can report for the other jobs. The step
// must fail for every combination in which a verify job did not pass for
// a change to a file that the verify jobs check.
func TestWorkflowResult(t *testing.T) {
	t.Parallel()

	// The results that GitHub reports for a job.
	const (
		success  = "success"
		failure  = "failure"
		canceled = "cancelled" //nolint:misspell // GitHub spells the result with two l's.
		skipped  = "skipped"
	)

	tests := map[string]struct {
		// changes is the result of the changes job.
		changes string
		// needed is the verify output of the changes job.
		needed string
		// verify is the result of the verify jobs.
		verify string
		// pass says whether the step succeeds.
		pass bool
	}{
		"verify needed and every verify job passed": {
			changes: success, needed: "true", verify: success, pass: true,
		},
		"verify not needed and no verify job ran": {
			changes: success, needed: "false", verify: skipped, pass: true,
		},
		"verify needed and a verify job failed": {
			changes: success, needed: "true", verify: failure,
		},
		"verify needed and a verify job was canceled": {
			changes: success, needed: "true", verify: canceled,
		},
		"verify needed and no verify job ran": {
			changes: success, needed: "true", verify: skipped,
		},
		"changes job set no output": {
			changes: success, needed: "", verify: skipped,
		},
		"changes job failed": {
			changes: failure, needed: "", verify: skipped,
		},
		"changes job was canceled": {
			changes: canceled, needed: "", verify: skipped,
		},
		"changes job was skipped": {
			changes: skipped, needed: "", verify: skipped,
		},
		"changes job was canceled after it set the output": {
			changes: canceled, needed: "false", verify: skipped,
		},
		"no result": {
			changes: "", needed: "", verify: "",
		},
	}

	step := readEnvoyWorkflow(t).Jobs[jobResult].step(t, stepResult)

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			out, err := runStep(t, step, t.TempDir(), map[string]string{
				"CHANGES_RESULT": tt.changes,
				"VERIFY_NEEDED":  tt.needed,
				"VERIFY_RESULT":  tt.verify,
			})

			if tt.pass {
				require.NoError(t, err, out)
				assert.NotContains(t, out, "::error::")

				return
			}

			var exitErr *exec.ExitError

			require.ErrorAs(t, err, &exitErr, out)
			assert.Equal(t, 1, exitErr.ExitCode(), out)
			assert.Contains(t, out, "::error::")
		})
	}
}
