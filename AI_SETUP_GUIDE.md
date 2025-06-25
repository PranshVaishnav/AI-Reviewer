# AI-Powered Code Analysis Setup Guide

This guide will help you set up AI-powered code analysis in your GitHub repository using the integrated analysis system.

## 🚀 Quick Setup

### Step 1: Add API Keys to Repository Secrets

The AI analysis requires an API key from either OpenAI or Anthropic. Follow these steps to add your API key securely:

#### Option A: OpenAI (Recommended)
1. Get an API key from [OpenAI](https://platform.openai.com/api-keys)
2. Go to your GitHub repository
3. Navigate to **Settings** → **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Add:
   - **Name**: `OPENAI_API_KEY`
   - **Secret**: Your OpenAI API key

#### Option B: Anthropic Claude
1. Get an API key from [Anthropic](https://console.anthropic.com/)
2. Go to your GitHub repository
3. Navigate to **Settings** → **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Add:
   - **Name**: `ANTHROPIC_API_KEY`
   - **Secret**: Your Anthropic API key

### Step 2: Verify Workflow Configuration

The GitHub Actions workflow (`cpp-guidelines-check.yml`) is already configured to use the AI analysis. It will:

- ✅ Automatically detect API keys from repository secrets
- ✅ Run AI analysis if keys are available
- ✅ Fall back to C++ guidelines only if no keys are found
- ✅ Support multiple programming languages
- ✅ Generate comprehensive PR comments

## 🔧 Analysis Coverage

### With AI Analysis Enabled:
- **🐛 Bug Detection**: Runtime errors, logic issues, null pointer dereferences
- **🔒 Security Audit**: Vulnerabilities, injection attacks, authentication issues  
- **⚡ Performance Optimization**: Algorithmic improvements, memory optimization
- **🏗️ C++ Guidelines**: Naming conventions, formatting, best practices
- **📊 Multi-language Support**: C++, Python, JavaScript, TypeScript, Java, Go, Rust, etc.

### Without AI Analysis (C++ Guidelines Only):
- **🏗️ C++ Guidelines**: Naming conventions, formatting, best practices
- **📝 Style Checking**: Include guards, namespace usage, smart pointers

## 📋 Workflow Features

### Automatic Analysis
- Triggers on pull requests affecting supported file types
- Analyzes only changed files for efficiency
- Provides different severity levels (Critical, High, Medium, Low, Info)

### Smart PR Comments
- Updates existing comments instead of creating new ones
- Shows analysis coverage (AI + C++ Guidelines vs C++ Guidelines only)
- Provides actionable recommendations
- Includes expandable detailed reports

### Flexible Severity Handling
- **Critical Issues**: Block PR merge (exit 1)
- **High Priority**: Flag for review but allow merge
- **Medium/Low**: Informational, no blocking
- **Info**: Suggestions for improvement

## 🎯 Testing the Setup

### Step 1: Create a Test PR
Create a simple PR with some code changes to trigger the analysis.

### Step 2: Check Workflow Logs
1. Go to **Actions** tab in your repository
2. Find the "Comprehensive Code Analysis" workflow
3. Check the logs to verify:
   - ✅ Dependencies installed correctly
   - ✅ API key detected (if configured)
   - ✅ Analysis completed successfully

### Step 3: Verify PR Comment
The workflow should automatically post a comment on your PR showing:
- Analysis coverage (AI enabled/disabled)
- Issue summary by severity
- Detailed findings
- Helpful recommendations

## 🔧 Customization Options

### Analysis Types
You can customize which AI analysis types to run by modifying the workflow file:

```yaml
# In .github/workflows/cpp-guidelines-check.yml
--ai-analysis-types bug_detection security_audit performance_optimization
```

Available analysis types:
- `bug_detection`
- `security_audit` 
- `performance_optimization`
- `code_complexity`
- `architecture_review`
- `refactoring_suggestions`
- `maintainability`
- `testing_recommendations`
- `dependency_analysis`
- `documentation_generation`

### File Type Support
The workflow currently supports:
- **C/C++**: .cpp, .cc, .cxx, .c++, .c, .h, .hpp, .hxx
- **Python**: .py
- **JavaScript**: .js, .jsx
- **TypeScript**: .ts, .tsx  
- **Java**: .java
- **Go**: .go
- **Rust**: .rs
- **PHP**: .php
- **Ruby**: .rb
- **Swift**: .swift
- **Kotlin**: .kt

### Excluding Files
Add file patterns to exclude from analysis:

```yaml
# Example: Skip test files
if [[ "$file" =~ \.(test|spec)\. ]]; then
  continue
fi
```

## 📊 Cost Considerations

### OpenAI Pricing (approximate)
- **GPT-4**: ~$0.03 per 1K tokens input, ~$0.06 per 1K tokens output
- **Average cost per file**: $0.01 - $0.05 depending on file size
- **Monthly cost for active repository**: $5 - $50 depending on PR frequency

### Anthropic Pricing (approximate)  
- **Claude**: ~$0.015 per 1K tokens input, ~$0.075 per 1K tokens output
- Similar cost profile to OpenAI

### Cost Optimization Tips
1. **Analyze only changed files** (already implemented)
2. **Limit analysis types** to most important ones
3. **Set file size limits** to skip very large files
4. **Use AI analysis selectively** for critical repositories

## 🛠️ Troubleshooting

### Common Issues

#### "No API key found" 
- Verify API key is added to repository secrets
- Check secret name matches exactly: `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`
- Ensure you have proper repository permissions

#### "Analysis failed"
- Check workflow logs for specific error messages
- Verify API key is valid and has sufficient credits
- Check if file size exceeds limits

#### "No issues found but expected some"
- AI analysis focuses on logic/bugs, not style (C++ guidelines handle style)
- Some files may not have detectable issues
- Analysis is conservative to avoid false positives

#### "Too many API calls"
- Implement rate limiting if analyzing many files
- Consider reducing analysis types for large PRs
- Monitor API usage in provider dashboard

### Getting Help

1. **Check workflow logs** in GitHub Actions tab
2. **Review PR comments** for specific error messages  
3. **Verify configuration** using the demo script: `python3 demo_ai_analysis.py`
4. **Test locally** before committing:
   ```bash
   export OPENAI_API_KEY="your-key"
   python3 integrated_code_analyzer.py your_file.cpp
   ```

## 🎉 Success Indicators

You'll know the setup is working when:

- ✅ PR comments show "AI Analysis: ✅ Enabled"
- ✅ Analysis finds bugs/security issues beyond style
- ✅ Multiple file types are analyzed (not just C++)
- ✅ Comments include confidence scores and detailed recommendations
- ✅ Critical issues block PR merges appropriately

## 📚 Next Steps

1. **Start with a test repository** to validate setup
2. **Gradually enable on production repositories**
3. **Monitor costs and adjust analysis types as needed**
4. **Train team on interpreting AI analysis results**
5. **Consider integrating with other code quality tools**

---

**Need help?** Check the demo script (`python3 demo_ai_analysis.py`) or review the integrated analyzer documentation. 