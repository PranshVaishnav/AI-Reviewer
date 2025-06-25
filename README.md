# AI-Powered Code Analysis Suite

A comprehensive code analysis suite that combines traditional rule-based analysis with cutting-edge AI capabilities. Features C++ coding guidelines analysis alongside AI-powered bug detection, security auditing, performance optimization, and more. Perfect for PR reviews, CI/CD pipelines, and maintaining code quality standards.

## 🚀 Features

### Traditional Rule-Based Analysis
- **C++ Guidelines**: Comprehensive C++ coding standards enforcement
- **English Text Rules**: Define coding rules in plain English, similar to Cursor rules
- **Multiple Analysis Modes**: Analyze individual files, GitHub PRs, git diffs, or staged files
- **Comprehensive Coverage**: Naming conventions, best practices, formatting, and code structure

### AI-Powered Analysis
- **🤖 AI Code Review**: Leverage GPT-4 or Claude for intelligent code analysis
- **🐛 Bug Detection**: Find potential bugs, logic errors, and runtime issues
- **🔒 Security Audit**: Identify security vulnerabilities and risks
- **⚡ Performance Optimization**: Suggest algorithmic and performance improvements
- **🏗️ Architecture Review**: Analyze design patterns and SOLID principles
- **📚 Documentation Generation**: Auto-generate comprehensive code documentation
- **🔄 Refactoring Suggestions**: Recommend code improvements and patterns
- **🧪 Testing Recommendations**: Suggest test cases and coverage improvements

### Integration & Output
- **Multiple Output Formats**: Text reports, JSON, Markdown, or GitHub PR comments
- **Multi-Language Support**: C++, Python, JavaScript, TypeScript, Java, Go, Rust, and more
- **Flexible Integration**: Combine rule-based and AI analysis or use independently
- **CI/CD Ready**: Perfect for automated code quality checks
- **Configurable**: Customize analysis types, severity levels, and reporting

## 📦 Installation

### Prerequisites

- Python 3.7+
- Git (for analyzing git diffs and staged files)
- API key for AI analysis (OpenAI or Anthropic)

### Setup

1. Clone the repository:
```bash
git clone [repository-url]
cd ai-code-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up API keys for AI analysis:
```bash
# For OpenAI (recommended)
export OPENAI_API_KEY="your-openai-api-key"

# Or for Anthropic Claude
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

4. Make the scripts executable:
```bash
chmod +x *.py
```

## 🎯 Quick Start

### AI-Powered Analysis

```bash
# Run comprehensive AI analysis
python ai_code_analyzer.py my_file.cpp

# Run specific analysis types
python ai_code_analyzer.py --analysis-types bug_detection security_audit *.cpp

# Use different AI provider
python ai_code_analyzer.py --provider anthropic --api-key YOUR_KEY file.cpp

# Generate markdown report
python ai_code_analyzer.py --format markdown --output report.md src/
```

### Integrated Analysis (C++ Guidelines + AI)

```bash
# Combine traditional and AI analysis
python integrated_code_analyzer.py *.cpp

# Disable C++ guidelines, use only AI
python integrated_code_analyzer.py --disable-cpp *.py

# Generate PR comment format
python integrated_code_analyzer.py --format pr-comment src/
```

### Traditional C++ Guidelines Analysis

### Analyze Individual Files

```bash
# Analyze a single C++ file
python3 cpp_code_analyzer.py my_file.cpp

# Analyze multiple files
python3 cpp_code_analyzer.py src/*.cpp include/*.h

# Use custom guidelines
python3 cpp_code_analyzer.py --guidelines custom_rules.json src/main.cpp
```

### Analyze PR Changes

```bash
# Analyze files changed in current branch vs main
python3 pr_analyzer.py --git-diff main

# Analyze staged files before commit
python3 pr_analyzer.py --staged

# Analyze specific GitHub PR
python3 pr_analyzer.py --pr owner/repo/123 --github-token YOUR_TOKEN

# Generate PR comment format
python3 pr_analyzer.py --files *.cpp --format pr-comment
```

## 📋 Usage Examples

### 1. Basic File Analysis

```bash
$ python3 cpp_code_analyzer.py sample_code.cpp

📋 C++ Code Analysis Report
==================================================

Summary:
  🔴 Errors: 0
  🟡 Warnings: 2
  🔵 Info: 5

📁 sample_code.cpp
-----------------
🟡 Line 4: Class names should use PascalCase (e.g., MyClass, HttpRequest)
   Code: class myClass {
   💡 Class name 'myClass' should use PascalCase

🟡 Line 9: Function names should use camelCase or snake_case consistently
   Code: void SomeFunction() {
   💡 Function name 'SomeFunction' should use camelCase or snake_case
```

### 2. PR Analysis with GitHub API

```bash
# Set your GitHub token
export GITHUB_TOKEN="your_github_token_here"

# Analyze a specific PR
python3 pr_analyzer.py --pr microsoft/vscode/12345 --github-token $GITHUB_TOKEN --format pr-comment

## 📋 Code Analysis Report

**Language:** CPP
**Files Analyzed:** 3

### Summary
- 🔴 **Errors:** 1
- 🟡 **Warnings:** 3
- 🔵 **Info:** 8

❗ **Please fix the errors before merging.**

### Issues Found

#### 📁 `src/parser.h`
🔴 **Line 1:** Header files should use include guards or #pragma once
💡 *Add #pragma once at the top of the header file*
```

### 3. Git Integration

```bash
# Check what you're about to commit
git add .
python3 pr_analyzer.py --staged

# Compare against different branch
python3 pr_analyzer.py --git-diff develop

# JSON output for CI/CD
python3 pr_analyzer.py --git-diff main --format json --output violations.json
```

## 🤖 AI Analysis Types

The AI analyzer supports multiple analysis types that can be run individually or in combination:

### Available Analysis Types

| Analysis Type | Description | Severity Levels |
|---------------|-------------|-----------------|
| **Bug Detection** | Find potential bugs, logic errors, runtime issues | Critical, High, Medium |
| **Security Audit** | Identify security vulnerabilities and risks | Critical, High, Medium |
| **Performance Optimization** | Suggest algorithmic and performance improvements | High, Medium, Low |
| **Code Complexity** | Analyze complexity and maintainability issues | Medium, Low, Info |
| **Architecture Review** | Review design patterns and SOLID principles | Medium, Low, Info |
| **Refactoring Suggestions** | Recommend code improvements and patterns | Medium, Low, Info |
| **Maintainability** | Assess code readability and maintenance | Medium, Low, Info |
| **Testing Recommendations** | Suggest test cases and coverage | Medium, Low, Info |
| **Documentation Generation** | Auto-generate code documentation | Info |
| **Dependency Analysis** | Analyze dependencies and coupling | Medium, Low, Info |

### Running Specific Analysis Types

```bash
# Run only bug detection and security audit
python ai_code_analyzer.py --analysis-types bug_detection security_audit *.cpp

# Run performance and architecture analysis
python ai_code_analyzer.py --analysis-types performance_optimization architecture_review src/

# Run all analysis types (default)
python ai_code_analyzer.py my_file.cpp
```

### Supported Languages

The AI analyzer supports multiple programming languages:

- **C/C++** (.cpp, .cc, .cxx, .c++, .c, .h, .hpp)
- **Python** (.py, .pyx)
- **JavaScript** (.js, .jsx)
- **TypeScript** (.ts, .tsx)
- **Java** (.java)
- **C#** (.cs)
- **Go** (.go)
- **Rust** (.rs)
- **PHP** (.php)
- **Ruby** (.rb)
- **Swift** (.swift)
- **Kotlin** (.kt)

## ⚙️ Configuration

### Custom Guidelines

Create a custom guidelines file (`custom_cpp_rules.json`):

```json
{
  "naming_conventions": {
    "class_names": {
      "rule": "Class names must use PascalCase starting with a capital letter",
      "pattern": "^[A-Z][a-zA-Z0-9]*$",
      "severity": "warning",
      "examples": {
        "good": ["MyClass", "HttpRequest", "FileReader"],
        "bad": ["myClass", "http_request", "file_reader"]
      }
    },
    "function_names": {
      "rule": "Function names should use camelCase consistently",
      "pattern": "^[a-z][a-zA-Z0-9]*$",
      "severity": "warning",
      "examples": {
        "good": ["calculateSum", "processData", "getValue"],
        "bad": ["CalculateSum", "process_data", "get_Value"]
      }
    }
  },
  "best_practices": {
    "memory_management": {
      "rule": "Prefer smart pointers over raw pointers",
      "keywords": ["new", "delete", "malloc", "free"],
      "severity": "info",
      "suggestion": "Use std::unique_ptr, std::shared_ptr, or RAII patterns"
    }
  }
}
```

Use your custom rules:
```bash
python3 cpp_code_analyzer.py --guidelines custom_cpp_rules.json src/
```

### Default Guidelines

The analyzer includes comprehensive default guidelines covering:

#### Naming Conventions
- **Class Names**: PascalCase (e.g., `MyClass`, `HttpRequest`)
- **Function Names**: camelCase or snake_case consistently
- **Variables**: snake_case for locals, camelCase or m_ prefix for members
- **Constants**: UPPER_SNAKE_CASE

#### Code Structure
- **Line Length**: Maximum 120 characters
- **Include Guards**: Required for header files
- **Function Length**: Maximum 50 lines

#### Best Practices
- **Memory Management**: Prefer smart pointers over raw pointers
- **Null Checks**: Validate pointers before dereferencing
- **Namespace Usage**: Avoid `using namespace std` in headers
- **Const Correctness**: Use const where appropriate

#### Formatting
- **Trailing Whitespace**: Remove trailing spaces
- **Consistent Indentation**: 2 or 4 spaces (no tabs)
- **Brace Style**: Consistent placement

## 🔧 Command Line Options

### cpp_code_analyzer.py

```bash
usage: cpp_code_analyzer.py [-h] [--guidelines GUIDELINES] [--format {text,json}] [--output OUTPUT] files [files ...]

Arguments:
  files                 C++ files to analyze

Options:
  --guidelines         Custom guidelines JSON file
  --format {text,json} Output format (default: text)
  --output OUTPUT      Output file (default: stdout)
```

### pr_analyzer.py

```bash
usage: pr_analyzer.py [-h] [--pr PR] [--files FILES [FILES ...]] [--git-diff [GIT_DIFF]] [--staged] 
                     [--language LANGUAGE] [--format {text,json,pr-comment}] [--output OUTPUT] 
                     [--github-token GITHUB_TOKEN]

Options:
  --pr PR                    GitHub PR in format 'owner/repo/pr_number'
  --files FILES [FILES ...]  Specific files to analyze
  --git-diff [GIT_DIFF]     Compare against branch (default: main)
  --staged                   Analyze staged files
  --language LANGUAGE        Programming language (default: cpp)
  --format {text,json,pr-comment}  Output format (default: text)
  --output OUTPUT           Output file (default: stdout)
  --github-token GITHUB_TOKEN  GitHub token for API access
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Code Quality Check

on:
  pull_request:
    branches: [ main ]

jobs:
  code-analysis:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: pip install requests
    
    - name: Run C++ Code Analysis
      run: |
        python3 pr_analyzer.py --git-diff origin/main --format json --output analysis.json
        
    - name: Comment PR
      if: github.event_name == 'pull_request'
      run: |
        python3 pr_analyzer.py --git-diff origin/main --format pr-comment --output comment.md
        # Use GitHub CLI or API to post comment.md to the PR
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Run code analysis on staged files
python3 pr_analyzer.py --staged --format text

# Exit with error code if there are critical violations
python3 pr_analyzer.py --staged --format json | jq -e '.summary.errors == 0' > /dev/null
if [ $? -ne 0 ]; then
    echo "❌ Critical errors found. Please fix before committing."
    exit 1
fi
```

## 🎨 Output Formats

### Text Format (Default)
Human-readable report with emojis and color coding.

### JSON Format
Structured data perfect for CI/CD integration:

```json
{
  "summary": {
    "total_violations": 5,
    "errors": 1,
    "warnings": 2,
    "info": 2
  },
  "violations": [
    {
      "rule_name": "include_guards",
      "description": "Header files should use include guards or #pragma once",
      "file_path": "src/parser.h",
      "line_number": 1,
      "severity": "error",
      "suggestion": "Add #pragma once at the top of the header file"
    }
  ]
}
```

### PR Comment Format
GitHub-flavored markdown perfect for automated PR comments.

## 🛠️ Extending the Analyzer

### Adding New Languages

1. Create a new analyzer class (e.g., `PythonGuidelinesAnalyzer`)
2. Implement the same interface as `CppGuidelinesAnalyzer`
3. Add language detection in `pr_analyzer.py`

### Adding New Rules

Add rules to your custom guidelines JSON:

```json
{
  "custom_category": {
    "rule_name": {
      "rule": "English description of the rule",
      "pattern": "regex_pattern",
      "severity": "error|warning|info",
      "suggestion": "How to fix this issue"
    }
  }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

MIT License - feel free to use in your projects!

## 🔗 Related Tools

This analyzer was inspired by tools like:
- [Qodo AI](https://qodo.ai) - AI-powered code integrity platform
- Cursor IDE rules
- Traditional linters like cpplint, clang-tidy

## 📞 Support

- 🐛 **Issues**: Report bugs or request features
- 📖 **Documentation**: Check this README for comprehensive usage
- 💬 **Discussions**: Ask questions or share improvements

---

**Happy coding! 🚀** 