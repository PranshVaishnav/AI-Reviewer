# 🔄 How to Rerun C++ Code Analysis

There are several ways to rerun the C++ code analysis workflow:

## 1. 🎯 Manual Workflow Dispatch (Recommended)

### From GitHub UI:
1. Go to your repository
2. Click **Actions** tab
3. Select **"C++ Code Guidelines Check"** workflow
4. Click **"Run workflow"** button
5. Choose your options:
   - **Branch**: Select which branch to run on
   - **Files**: Specify files to analyze (leave empty for all changed files)
   - **Branch Compare**: Which branch to compare against (default: main)
   - **Analysis Level**: Choose what to analyze
     - `all`: All violations (errors, warnings, info)
     - `errors-only`: Only error-level violations
     - `warnings-and-errors`: Errors and warnings only
6. Click **"Run workflow"**

### Example Scenarios:
```
✅ Analyze all changed files: Leave "Files" empty
✅ Analyze specific files: "src/main.cpp src/utils.h"
✅ Compare against develop: Set "Branch Compare" to "develop"
✅ Only show errors: Set "Analysis Level" to "errors-only"
```

## 2. 💬 Comment Commands (If comment-rerun.yml is enabled)

In any PR, comment with:
```
/analyze-cpp
```

The bot will:
- 🚀 React with a rocket emoji
- 🔄 Trigger a new analysis run
- 💬 Post updated results

## 3. 🔁 Re-run Failed Workflows

If a workflow fails or you want to re-run it:

### Option A: Re-run from Actions tab
1. Go to **Actions** tab
2. Find the failed workflow run
3. Click **"Re-run jobs"** or **"Re-run failed jobs"**

### Option B: Re-run from PR
1. Go to your PR
2. Scroll down to status checks
3. Click **"Details"** next to failed check
4. Click **"Re-run jobs"**

## 4. ⚡ Quick Commands Reference

| Action | Method | Where |
|--------|--------|-------|
| **Manual run** | Actions → Run workflow | Repository Actions tab |
| **Comment trigger** | `/analyze-cpp` | PR comments |
| **Re-run failed** | Re-run jobs | Actions tab or PR checks |
| **Analyze specific files** | Manual run with file input | Actions tab |
| **Different branch** | Manual run with branch input | Actions tab |

## 5. 🛠️ Advanced Options

### Analyze Specific Files Only:
```
Files input: "src/main.cpp include/header.h"
```

### Compare Against Different Branch:
```
Branch Compare: "develop"  (instead of main)
```

### Focus on Errors Only:
```
Analysis Level: "errors-only"
```

## 6. 🔐 Permissions Required

### For Manual Runs:
- Repository **write** access
- Actions **read** permission

### For Comment Triggers:
- PR **comment** permission (usually automatic for collaborators)

## 7. 📊 Understanding Results

After rerunning, you'll get:
- ✅ **Updated PR comment** with latest analysis
- 📁 **New artifacts** with JSON/text reports  
- 🔍 **Status check** (pass/fail)
- 📝 **Workflow logs** for debugging

## 8. 🚫 Troubleshooting

### "Workflow not found" error:
- Make sure workflow files are in `.github/workflows/`
- Check file syntax is valid YAML

### "Permission denied" error:
- Check repository Actions permissions
- Ensure you have write access

### "No files to analyze" message:
- Verify your file paths are correct
- Check that files actually exist in the branch

### Comment commands not working:
- Ensure `comment-rerun.yml` workflow is present
- Check that you're commenting on a PR (not issue)

## 9. 🎯 Best Practices

1. **Use manual runs** for testing specific files
2. **Use comment triggers** for quick PR re-analysis
3. **Set analysis level** to focus on what matters most
4. **Compare against feature branches** when working on long-lived branches
5. **Check artifacts** for detailed reports when debugging

## 10. 🔔 Pro Tips

- 💡 **Bookmark** the Actions tab for quick access
- 🏷️ **Tag teammates** when using comment triggers
- 📈 **Use analysis levels** to gradually fix issues (errors first, then warnings)
- 🔄 **Re-run periodically** on long-lived PRs to catch new issues
- 📊 **Download artifacts** for offline analysis or sharing

---

**Quick Access Links:**
- 🔄 [Manual Run](../../actions/workflows/cpp-guidelines-check.yml)
- 📊 [All Workflow Runs](../../actions)
- ⚙️ [Repository Settings](../../settings/actions) 