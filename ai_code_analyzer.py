#!/usr/bin/env python3
"""
AI-Powered Code Analyzer
Uses LLM capabilities to analyze code for quality, bugs, security, performance, and more.
Excludes C++ coding guidelines (handled by cpp_code_analyzer.py).
"""

import os
import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import argparse
from enum import Enum

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


class AnalysisType(Enum):
    """Types of AI-powered code analysis."""
    BUG_DETECTION = "bug_detection"
    SECURITY_AUDIT = "security_audit"
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    CODE_COMPLEXITY = "code_complexity"
    DOCUMENTATION_GENERATION = "documentation_generation"
    REFACTORING_SUGGESTIONS = "refactoring_suggestions"
    ARCHITECTURE_REVIEW = "architecture_review"
    MAINTAINABILITY = "maintainability"
    TESTING_RECOMMENDATIONS = "testing_recommendations"
    DEPENDENCY_ANALYSIS = "dependency_analysis"


@dataclass
class AIAnalysisResult:
    """Result from AI-powered code analysis."""
    analysis_type: str
    file_path: str
    language: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str
    title: str
    description: str
    recommendation: str
    code_snippet: Optional[str] = None
    line_number: Optional[int] = None
    confidence: float = 0.0  # 0.0 to 1.0
    impact: str = ""  # Impact on the codebase
    effort: str = ""  # Estimated effort to fix


class AICodeAnalyzer:
    """AI-powered code analyzer using multiple LLM providers."""
    
    def __init__(self, provider: str = "openai", api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.client = None
        self.supported_languages = {
            'cpp', 'c', 'python', 'javascript', 'typescript', 'java', 
            'csharp', 'go', 'rust', 'php', 'ruby', 'swift', 'kotlin'
        }
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the LLM client based on provider."""
        if self.provider == "openai" and HAS_OPENAI:
            openai.api_key = self.api_key
            self.client = openai
        elif self.provider == "anthropic" and HAS_ANTHROPIC:
            self.client = anthropic.Anthropic(api_key=self.api_key)
        else:
            print(f"Warning: {self.provider} client not available or API key not set")
    
    def detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.c++': 'cpp',
            '.c': 'c', '.h': 'c', '.hpp': 'cpp',
            '.py': 'python', '.pyx': 'python',
            '.js': 'javascript', '.jsx': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.java': 'java',
            '.cs': 'csharp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
            '.swift': 'swift',
            '.kt': 'kotlin'
        }
        
        return language_map.get(ext, 'unknown')
    
    async def analyze_code(self, file_path: str, 
                          analysis_types: Optional[List[AnalysisType]] = None) -> List[AIAnalysisResult]:
        """Analyze code file using AI for multiple analysis types."""
        if not os.path.exists(file_path):
            return []
        
        if analysis_types is None:
            analysis_types = list(AnalysisType)
        
        language = self.detect_language(file_path)
        if language == 'unknown':
            print(f"Unsupported file type: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except UnicodeDecodeError:
            print(f"Cannot read file (encoding issue): {file_path}")
            return []
        
        # Run all analysis types concurrently
        tasks = []
        for analysis_type in analysis_types:
            task = self._analyze_single_type(file_path, code_content, language, analysis_type)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and flatten results
        all_results = []
        for result in results:
            if isinstance(result, Exception):
                print(f"Analysis error: {result}")
            elif isinstance(result, list):
                all_results.extend(result)
        
        return all_results
    
    async def _analyze_single_type(self, file_path: str, code_content: str, 
                                  language: str, analysis_type: AnalysisType) -> List[AIAnalysisResult]:
        """Perform a single type of AI analysis."""
        prompt = self._build_analysis_prompt(code_content, language, analysis_type)
        
        try:
            if self.provider == "openai" and self.client:
                response = await self._query_openai(prompt)
            elif self.provider == "anthropic" and self.client:
                response = await self._query_anthropic(prompt)
            else:
                return []
            
            return self._parse_ai_response(file_path, language, analysis_type, response)
            
        except Exception as e:
            print(f"Error in {analysis_type.value} analysis: {e}")
            return []
    
    def _build_analysis_prompt(self, code: str, language: str, analysis_type: AnalysisType) -> str:
        """Build analysis prompt for specific analysis type."""
        base_context = f"""
Analyze the following {language.upper()} code for {analysis_type.value.replace('_', ' ')}.

IMPORTANT: Do NOT analyze or comment on coding style, formatting, or naming conventions. 
Focus ONLY on {analysis_type.value.replace('_', ' ')}.

Code to analyze:
```{language}
{code}
```

"""
        
        type_specific_prompts = {
            AnalysisType.BUG_DETECTION: """
Find potential bugs, logic errors, and runtime issues:
- Null pointer dereferences
- Array bounds violations
- Memory leaks
- Logic errors
- Race conditions
- Unhandled exceptions
- Infinite loops
            """,
            
            AnalysisType.SECURITY_AUDIT: """
Identify security vulnerabilities and risks:
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Buffer overflows
- Insecure data handling
- Authentication bypasses
- Authorization issues
- Cryptographic weaknesses
            """,
            
            AnalysisType.PERFORMANCE_OPTIMIZATION: """
Suggest performance improvements:
- Algorithmic complexity issues
- Memory usage optimization
- CPU-intensive operations
- I/O bottlenecks
- Caching opportunities
- Database query optimization
- Concurrent processing opportunities
            """,
            
            AnalysisType.CODE_COMPLEXITY: """
Analyze code complexity and maintainability:
- Cyclomatic complexity
- Function/method length
- Nesting depth
- Code duplication
- Tight coupling
- Low cohesion
- Complex conditional logic
            """,
            
            AnalysisType.DOCUMENTATION_GENERATION: """
Generate comprehensive documentation:
- Function/method descriptions
- Parameter explanations
- Return value descriptions
- Usage examples
- Edge cases
- Dependencies
- Integration points
            """,
            
            AnalysisType.REFACTORING_SUGGESTIONS: """
Suggest code refactoring improvements:
- Extract methods/functions
- Remove code duplication
- Simplify complex expressions
- Improve variable naming
- Reduce parameter lists
- Apply design patterns
- Modularization opportunities
            """,
            
            AnalysisType.ARCHITECTURE_REVIEW: """
Review architectural aspects:
- Design pattern usage
- SOLID principles adherence
- Separation of concerns
- Dependency management
- Module boundaries
- Interface design
- Scalability considerations
            """,
            
            AnalysisType.MAINTAINABILITY: """
Assess code maintainability:
- Code readability
- Documentation completeness
- Test coverage implications
- Error handling robustness
- Configuration management
- Logging and monitoring
- Debugging support
            """,
            
            AnalysisType.TESTING_RECOMMENDATIONS: """
Suggest testing improvements:
- Test case recommendations
- Edge cases to test
- Mock/stub opportunities
- Integration test points
- Performance test scenarios
- Security test cases
- Regression test risks
            """,
            
            AnalysisType.DEPENDENCY_ANALYSIS: """
Analyze dependencies and coupling:
- External library usage
- Circular dependencies
- Unused imports/includes
- Version compatibility
- Security vulnerabilities in dependencies
- License compliance
- Update recommendations
            """
        }
        
        specific_prompt = type_specific_prompts.get(analysis_type, "Perform general code analysis.")
        
        return base_context + specific_prompt + """

Return your analysis in JSON format with this structure:
{
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "specific category",
      "title": "Brief title",
      "description": "Detailed description",
      "recommendation": "Specific recommendation",
      "line_number": null or number,
      "code_snippet": "relevant code if applicable",
      "confidence": 0.0-1.0,
      "impact": "impact description",
      "effort": "low|medium|high"
    }
  ]
}
"""
    
    async def _query_openai(self, prompt: str) -> str:
        """Query OpenAI API."""
        try:
            response = await self.client.ChatCompletion.acreate(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert code analyst. Provide detailed, actionable insights."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI API error: {e}")
            return ""
    
    async def _query_anthropic(self, prompt: str) -> str:
        """Query Anthropic Claude API."""
        try:
            response = await self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=2000,
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        except Exception as e:
            print(f"Anthropic API error: {e}")
            return ""
    
    def _parse_ai_response(self, file_path: str, language: str, 
                          analysis_type: AnalysisType, response: str) -> List[AIAnalysisResult]:
        """Parse AI response into structured results."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return []
            
            data = json.loads(json_match.group())
            findings = data.get('findings', [])
            
            results = []
            for finding in findings:
                result = AIAnalysisResult(
                    analysis_type=analysis_type.value,
                    file_path=file_path,
                    language=language,
                    severity=finding.get('severity', 'info'),
                    category=finding.get('category', 'general'),
                    title=finding.get('title', 'AI Analysis Finding'),
                    description=finding.get('description', ''),
                    recommendation=finding.get('recommendation', ''),
                    code_snippet=finding.get('code_snippet'),
                    line_number=finding.get('line_number'),
                    confidence=float(finding.get('confidence', 0.5)),
                    impact=finding.get('impact', ''),
                    effort=finding.get('effort', 'unknown')
                )
                results.append(result)
            
            return results
            
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            return []
        except Exception as e:
            print(f"Response parsing error: {e}")
            return []
    
    def analyze_files(self, file_paths: List[str], 
                     analysis_types: Optional[List[AnalysisType]] = None) -> List[AIAnalysisResult]:
        """Analyze multiple files synchronously."""
        return asyncio.run(self._analyze_files_async(file_paths, analysis_types))
    
    async def _analyze_files_async(self, file_paths: List[str], 
                                  analysis_types: Optional[List[AnalysisType]] = None) -> List[AIAnalysisResult]:
        """Analyze multiple files asynchronously."""
        tasks = []
        for file_path in file_paths:
            task = self.analyze_code(file_path, analysis_types)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_results = []
        for result in results:
            if isinstance(result, Exception):
                print(f"File analysis error: {result}")
            elif isinstance(result, list):
                all_results.extend(result)
        
        return all_results
    
    def generate_report(self, results: List[AIAnalysisResult], format_type: str = "text") -> str:
        """Generate analysis report in specified format."""
        if format_type == "json":
            return self._generate_json_report(results)
        elif format_type == "markdown":
            return self._generate_markdown_report(results)
        else:
            return self._generate_text_report(results)
    
    def _generate_text_report(self, results: List[AIAnalysisResult]) -> str:
        """Generate text report."""
        if not results:
            return "✅ No issues found in AI analysis!"
        
        report = "🤖 AI-Powered Code Analysis Report\n"
        report += "=" * 50 + "\n\n"
        
        # Summary
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        analysis_types = {}
        
        for result in results:
            severities[result.severity] = severities.get(result.severity, 0) + 1
            analysis_types[result.analysis_type] = analysis_types.get(result.analysis_type, 0) + 1
        
        report += "Summary:\n"
        report += f"  🔴 Critical: {severities['critical']}\n"
        report += f"  🟠 High: {severities['high']}\n"
        report += f"  🟡 Medium: {severities['medium']}\n"
        report += f"  🟢 Low: {severities['low']}\n"
        report += f"  🔵 Info: {severities['info']}\n\n"
        
        report += "Analysis Types:\n"
        for analysis_type, count in analysis_types.items():
            report += f"  • {analysis_type.replace('_', ' ').title()}: {count}\n"
        report += "\n"
        
        # Group by file
        files_results = {}
        for result in results:
            if result.file_path not in files_results:
                files_results[result.file_path] = []
            files_results[result.file_path].append(result)
        
        # Generate file reports
        for file_path, file_results in files_results.items():
            report += f"📁 {file_path}\n"
            report += "-" * (len(file_path) + 2) + "\n"
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_results = sorted(file_results, key=lambda x: severity_order.get(x.severity, 5))
            
            for result in sorted_results:
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}
                report += f"{icon.get(result.severity, '⚪')} {result.title}\n"
                report += f"   Category: {result.category}\n"
                report += f"   Analysis: {result.analysis_type.replace('_', ' ').title()}\n"
                
                if result.line_number:
                    report += f"   Line: {result.line_number}\n"
                
                report += f"   Description: {result.description}\n"
                report += f"   Recommendation: {result.recommendation}\n"
                
                if result.confidence > 0:
                    report += f"   Confidence: {result.confidence:.1%}\n"
                
                if result.impact:
                    report += f"   Impact: {result.impact}\n"
                
                if result.effort:
                    report += f"   Effort: {result.effort}\n"
                
                if result.code_snippet:
                    report += f"   Code: {result.code_snippet[:100]}...\n"
                
                report += "\n"
        
        return report
    
    def _generate_json_report(self, results: List[AIAnalysisResult]) -> str:
        """Generate JSON report."""
        report_data = {
            "analysis_timestamp": "",
            "total_findings": len(results),
            "summary": {
                "critical": len([r for r in results if r.severity == 'critical']),
                "high": len([r for r in results if r.severity == 'high']),
                "medium": len([r for r in results if r.severity == 'medium']),
                "low": len([r for r in results if r.severity == 'low']),
                "info": len([r for r in results if r.severity == 'info'])
            },
            "findings": [asdict(result) for result in results]
        }
        
        return json.dumps(report_data, indent=2)
    
    def _generate_markdown_report(self, results: List[AIAnalysisResult]) -> str:
        """Generate Markdown report."""
        if not results:
            return "# 🤖 AI Code Analysis\n\n✅ No issues found!"
        
        report = "# 🤖 AI-Powered Code Analysis Report\n\n"
        
        # Summary table
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results:
            severities[result.severity] = severities.get(result.severity, 0) + 1
        
        report += "## Summary\n\n"
        report += "| Severity | Count |\n"
        report += "|----------|-------|\n"
        report += f"| 🔴 Critical | {severities['critical']} |\n"
        report += f"| 🟠 High | {severities['high']} |\n"
        report += f"| 🟡 Medium | {severities['medium']} |\n"
        report += f"| 🟢 Low | {severities['low']} |\n"
        report += f"| 🔵 Info | {severities['info']} |\n\n"
        
        # Group by file
        files_results = {}
        for result in results:
            if result.file_path not in files_results:
                files_results[result.file_path] = []
            files_results[result.file_path].append(result)
        
        report += "## Detailed Findings\n\n"
        
        for file_path, file_results in files_results.items():
            report += f"### 📁 `{file_path}`\n\n"
            
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_results = sorted(file_results, key=lambda x: severity_order.get(x.severity, 5))
            
            for result in sorted_results:
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}
                report += f"#### {icon.get(result.severity, '⚪')} {result.title}\n\n"
                
                report += f"**Analysis Type:** {result.analysis_type.replace('_', ' ').title()}  \n"
                report += f"**Category:** {result.category}  \n"
                
                if result.line_number:
                    report += f"**Line:** {result.line_number}  \n"
                
                if result.confidence > 0:
                    report += f"**Confidence:** {result.confidence:.1%}  \n"
                
                report += f"**Description:** {result.description}\n\n"
                report += f"**Recommendation:** {result.recommendation}\n\n"
                
                if result.code_snippet:
                    report += f"**Code Snippet:**\n```{result.language}\n{result.code_snippet}\n```\n\n"
                
                if result.impact:
                    report += f"**Impact:** {result.impact}\n\n"
                
                if result.effort:
                    report += f"**Effort:** {result.effort}\n\n"
                
                report += "---\n\n"
        
        return report


def main():
    """Main function for CLI usage."""
    parser = argparse.ArgumentParser(description="AI-powered code analysis")
    parser.add_argument("files", nargs="+", help="Files to analyze")
    parser.add_argument("--provider", choices=["openai", "anthropic"], 
                       default="openai", help="LLM provider")
    parser.add_argument("--api-key", help="API key for LLM provider")
    parser.add_argument("--analysis-types", nargs="+", 
                       choices=[t.value for t in AnalysisType],
                       help="Specific analysis types to run")
    parser.add_argument("--format", choices=["text", "json", "markdown"], 
                       default="text", help="Output format")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    # Convert analysis types
    analysis_types = None
    if args.analysis_types:
        analysis_types = [AnalysisType(t) for t in args.analysis_types]
    
    # Initialize analyzer
    analyzer = AICodeAnalyzer(provider=args.provider, api_key=args.api_key)
    
    # Analyze files
    print("🤖 Starting AI code analysis...")
    results = analyzer.analyze_files(args.files, analysis_types)
    
    # Generate report
    report = analyzer.generate_report(results, args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main() 