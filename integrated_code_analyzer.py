#!/usr/bin/env python3
"""
Integrated Code Analyzer
Combines traditional rule-based analysis (C++ guidelines) with AI-powered analysis
for comprehensive code review and quality assurance.
"""

import os
import json
import asyncio
import argparse
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    from cpp_code_analyzer import CppGuidelinesAnalyzer, Violation
    HAS_CPP_ANALYZER = True
except ImportError:
    HAS_CPP_ANALYZER = False
    print("Warning: C++ analyzer not available")

try:
    from ai_code_analyzer import AICodeAnalyzer, AIAnalysisResult, AnalysisType
    HAS_AI_ANALYZER = True
except ImportError:
    HAS_AI_ANALYZER = False
    print("Warning: AI analyzer not available")


@dataclass
class IntegratedAnalysisResult:
    """Combined result from both rule-based and AI analysis."""
    file_path: str
    language: str
    
    # Rule-based analysis results
    cpp_violations: List[Dict[str, Any]] = None
    
    # AI analysis results
    ai_findings: List[Dict[str, Any]] = None
    
    # Summary statistics
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    info_issues: int = 0


class IntegratedCodeAnalyzer:
    """Integrated analyzer combining rule-based and AI-powered analysis."""
    
    def __init__(self, ai_provider: str = "openai", ai_api_key: Optional[str] = None,
                 cpp_guidelines_file: Optional[str] = None):
        self.ai_provider = ai_provider
        self.ai_api_key = ai_api_key
        self.cpp_guidelines_file = cpp_guidelines_file
        
        # Initialize analyzers
        self.cpp_analyzer = None
        self.ai_analyzer = None
        
        if HAS_CPP_ANALYZER:
            self.cpp_analyzer = CppGuidelinesAnalyzer(cpp_guidelines_file)
        
        if HAS_AI_ANALYZER:
            self.ai_analyzer = AICodeAnalyzer(ai_provider, ai_api_key)
    
    def analyze_file(self, file_path: str, 
                    enable_cpp_analysis: bool = True,
                    enable_ai_analysis: bool = True,
                    ai_analysis_types: Optional[List[AnalysisType]] = None) -> IntegratedAnalysisResult:
        """Analyze a single file with both rule-based and AI analysis."""
        language = self._detect_language(file_path)
        result = IntegratedAnalysisResult(file_path=file_path, language=language)
        
        # Rule-based analysis (C++ guidelines)
        if enable_cpp_analysis and self.cpp_analyzer and language in ['cpp', 'c']:
            try:
                violations = self.cpp_analyzer.analyze_file(file_path)
                result.cpp_violations = [asdict(v) for v in violations]
            except Exception as e:
                print(f"C++ analysis error for {file_path}: {e}")
        
        # AI-powered analysis
        if enable_ai_analysis and self.ai_analyzer:
            try:
                ai_results = asyncio.run(
                    self.ai_analyzer.analyze_code(file_path, ai_analysis_types)
                )
                result.ai_findings = [asdict(r) for r in ai_results]
            except Exception as e:
                print(f"AI analysis error for {file_path}: {e}")
        
        # Calculate summary statistics
        result.total_issues = self._calculate_total_issues(result)
        result.critical_issues = self._count_issues_by_severity(result, 'critical', 'error')
        result.high_issues = self._count_issues_by_severity(result, 'high')
        result.medium_issues = self._count_issues_by_severity(result, 'medium', 'warning')
        result.low_issues = self._count_issues_by_severity(result, 'low')
        result.info_issues = self._count_issues_by_severity(result, 'info')
        
        return result
    
    def analyze_files(self, file_paths: List[str],
                     enable_cpp_analysis: bool = True,
                     enable_ai_analysis: bool = True,
                     ai_analysis_types: Optional[List[AnalysisType]] = None) -> List[IntegratedAnalysisResult]:
        """Analyze multiple files."""
        results = []
        
        for file_path in file_paths:
            print(f"Analyzing {file_path}...")
            result = self.analyze_file(
                file_path, enable_cpp_analysis, enable_ai_analysis, ai_analysis_types
            )
            results.append(result)
        
        return results
    
    def analyze_pr_files(self, changed_files: List[str],
                        enable_cpp_analysis: bool = True,
                        enable_ai_analysis: bool = True,
                        ai_analysis_types: Optional[List[AnalysisType]] = None) -> List[IntegratedAnalysisResult]:
        """Analyze files changed in a PR."""
        # Filter to supported file types
        supported_files = []
        for file_path in changed_files:
            if os.path.exists(file_path):
                language = self._detect_language(file_path)
                if language != 'unknown':
                    supported_files.append(file_path)
        
        return self.analyze_files(supported_files, enable_cpp_analysis, enable_ai_analysis, ai_analysis_types)
    
    def _detect_language(self, file_path: str) -> str:
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
    
    def _calculate_total_issues(self, result: IntegratedAnalysisResult) -> int:
        """Calculate total number of issues."""
        count = 0
        
        if result.cpp_violations:
            count += len(result.cpp_violations)
        
        if result.ai_findings:
            count += len(result.ai_findings)
        
        return count
    
    def _count_issues_by_severity(self, result: IntegratedAnalysisResult, 
                                 *severities: str) -> int:
        """Count issues by severity level."""
        count = 0
        
        # Count C++ violations
        if result.cpp_violations:
            for violation in result.cpp_violations:
                if violation.get('severity') in severities:
                    count += 1
        
        # Count AI findings
        if result.ai_findings:
            for finding in result.ai_findings:
                if finding.get('severity') in severities:
                    count += 1
        
        return count
    
    def generate_report(self, results: List[IntegratedAnalysisResult], 
                       format_type: str = "text") -> str:
        """Generate comprehensive analysis report."""
        if format_type == "json":
            return self._generate_json_report(results)
        elif format_type == "markdown":
            return self._generate_markdown_report(results)
        elif format_type == "pr-comment":
            return self._generate_pr_comment(results)
        else:
            return self._generate_text_report(results)
    
    def _generate_text_report(self, results: List[IntegratedAnalysisResult]) -> str:
        """Generate comprehensive text report."""
        if not results:
            return "✅ No files analyzed."
        
        report = "🔍 Comprehensive Code Analysis Report\n"
        report += "=" * 60 + "\n\n"
        
        # Overall summary
        total_files = len(results)
        total_issues = sum(r.total_issues for r in results)
        critical_issues = sum(r.critical_issues for r in results)
        high_issues = sum(r.high_issues for r in results)
        medium_issues = sum(r.medium_issues for r in results)
        low_issues = sum(r.low_issues for r in results)
        info_issues = sum(r.info_issues for r in results)
        
        report += "📊 Overall Summary:\n"
        report += f"  Files Analyzed: {total_files}\n"
        report += f"  Total Issues: {total_issues}\n"
        report += f"  🔴 Critical: {critical_issues}\n"
        report += f"  🟠 High: {high_issues}\n"
        report += f"  🟡 Medium: {medium_issues}\n"
        report += f"  🟢 Low: {low_issues}\n"
        report += f"  🔵 Info: {info_issues}\n\n"
        
        # Analysis type breakdown
        cpp_files = len([r for r in results if r.cpp_violations])
        ai_files = len([r for r in results if r.ai_findings])
        
        report += "🔧 Analysis Coverage:\n"
        report += f"  C++ Guidelines Analysis: {cpp_files} files\n"
        report += f"  AI-Powered Analysis: {ai_files} files\n\n"
        
        # File-by-file results
        for result in results:
            if result.total_issues == 0:
                continue
            
            report += f"📁 {result.file_path} ({result.language.upper()})\n"
            report += "-" * (len(result.file_path) + 20) + "\n"
            
            if result.cpp_violations:
                report += "  🏗️  C++ Guidelines Issues:\n"
                for violation in result.cpp_violations:
                    severity_icon = {'error': '🔴', 'warning': '🟡', 'info': '🔵'}.get(
                        violation.get('severity', 'info'), '⚪'
                    )
                    report += f"    {severity_icon} Line {violation.get('line_number', 'N/A')}: "
                    report += f"{violation.get('description', 'No description')}\n"
                    if violation.get('suggestion'):
                        report += f"       💡 {violation.get('suggestion')}\n"
                report += "\n"
            
            if result.ai_findings:
                report += "  🤖 AI Analysis Findings:\n"
                for finding in result.ai_findings:
                    severity_icon = {
                        'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                        'low': '🟢', 'info': '🔵'
                    }.get(finding.get('severity', 'info'), '⚪')
                    
                    report += f"    {severity_icon} {finding.get('title', 'AI Finding')}\n"
                    report += f"       Analysis: {finding.get('analysis_type', 'general').replace('_', ' ').title()}\n"
                    report += f"       Category: {finding.get('category', 'general')}\n"
                    
                    if finding.get('line_number'):
                        report += f"       Line: {finding.get('line_number')}\n"
                    
                    report += f"       Description: {finding.get('description', 'No description')}\n"
                    report += f"       Recommendation: {finding.get('recommendation', 'No recommendation')}\n"
                    
                    if finding.get('confidence', 0) > 0:
                        report += f"       Confidence: {finding.get('confidence') * 100:.0f}%\n"
                    
                    report += "\n"
            
            report += "\n"
        
        return report
    
    def _generate_json_report(self, results: List[IntegratedAnalysisResult]) -> str:
        """Generate JSON report."""
        report_data = {
            "analysis_type": "integrated",
            "total_files": len(results),
            "total_issues": sum(r.total_issues for r in results),
            "summary": {
                "critical": sum(r.critical_issues for r in results),
                "high": sum(r.high_issues for r in results),
                "medium": sum(r.medium_issues for r in results),
                "low": sum(r.low_issues for r in results),
                "info": sum(r.info_issues for r in results)
            },
            "coverage": {
                "cpp_analysis": len([r for r in results if r.cpp_violations]),
                "ai_analysis": len([r for r in results if r.ai_findings])
            },
            "results": [asdict(result) for result in results]
        }
        
        return json.dumps(report_data, indent=2)
    
    def _generate_markdown_report(self, results: List[IntegratedAnalysisResult]) -> str:
        """Generate Markdown report."""
        if not results:
            return "# 🔍 Code Analysis\n\n✅ No files analyzed."
        
        report = "# 🔍 Comprehensive Code Analysis Report\n\n"
        
        # Summary table
        total_files = len(results)
        total_issues = sum(r.total_issues for r in results)
        critical_issues = sum(r.critical_issues for r in results)
        high_issues = sum(r.high_issues for r in results)
        medium_issues = sum(r.medium_issues for r in results)
        low_issues = sum(r.low_issues for r in results)
        info_issues = sum(r.info_issues for r in results)
        
        report += "## 📊 Summary\n\n"
        report += f"**Files Analyzed:** {total_files}  \n"
        report += f"**Total Issues:** {total_issues}  \n\n"
        
        report += "| Severity | Count |\n"
        report += "|----------|-------|\n"
        report += f"| 🔴 Critical | {critical_issues} |\n"
        report += f"| 🟠 High | {high_issues} |\n"
        report += f"| 🟡 Medium | {medium_issues} |\n"
        report += f"| 🟢 Low | {low_issues} |\n"
        report += f"| 🔵 Info | {info_issues} |\n\n"
        
        # Analysis coverage
        cpp_files = len([r for r in results if r.cpp_violations])
        ai_files = len([r for r in results if r.ai_findings])
        
        report += "## 🔧 Analysis Coverage\n\n"
        report += f"- **C++ Guidelines Analysis:** {cpp_files} files\n"
        report += f"- **AI-Powered Analysis:** {ai_files} files\n\n"
        
        # Detailed findings
        report += "## 📋 Detailed Findings\n\n"
        
        for result in results:
            if result.total_issues == 0:
                continue
            
            report += f"### 📁 `{result.file_path}` ({result.language.upper()})\n\n"
            
            if result.cpp_violations:
                report += "#### 🏗️ C++ Guidelines Issues\n\n"
                for violation in result.cpp_violations:
                    severity_icon = {'error': '🔴', 'warning': '🟡', 'info': '🔵'}.get(
                        violation.get('severity', 'info'), '⚪'
                    )
                    report += f"- {severity_icon} **Line {violation.get('line_number', 'N/A')}:** "
                    report += f"{violation.get('description', 'No description')}\n"
                    if violation.get('suggestion'):
                        report += f"  - 💡 *{violation.get('suggestion')}*\n"
                report += "\n"
            
            if result.ai_findings:
                report += "#### 🤖 AI Analysis Findings\n\n"
                for finding in result.ai_findings:
                    severity_icon = {
                        'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                        'low': '🟢', 'info': '🔵'
                    }.get(finding.get('severity', 'info'), '⚪')
                    
                    report += f"- {severity_icon} **{finding.get('title', 'AI Finding')}**\n"
                    report += f"  - **Analysis:** {finding.get('analysis_type', 'general').replace('_', ' ').title()}\n"
                    report += f"  - **Category:** {finding.get('category', 'general')}\n"
                    
                    if finding.get('line_number'):
                        report += f"  - **Line:** {finding.get('line_number')}\n"
                    
                    report += f"  - **Description:** {finding.get('description', 'No description')}\n"
                    report += f"  - **Recommendation:** {finding.get('recommendation', 'No recommendation')}\n"
                    
                    if finding.get('confidence', 0) > 0:
                        report += f"  - **Confidence:** {finding.get('confidence') * 100:.0f}%\n"
                    
                    report += "\n"
        
        return report
    
    def _generate_pr_comment(self, results: List[IntegratedAnalysisResult]) -> str:
        """Generate GitHub PR comment."""
        if not results:
            return "✅ **Code Analysis Complete**\n\nNo files to analyze."
        
        total_issues = sum(r.total_issues for r in results)
        
        if total_issues == 0:
            return "✅ **Code Analysis Complete**\n\nNo issues found in the analyzed files!"
        
        critical_issues = sum(r.critical_issues for r in results)
        high_issues = sum(r.high_issues for r in results)
        medium_issues = sum(r.medium_issues for r in results)
        low_issues = sum(r.low_issues for r in results)
        info_issues = sum(r.info_issues for r in results)
        
        comment = "## 🔍 Comprehensive Code Analysis Report\n\n"
        comment += f"**Files Analyzed:** {len(results)}\n\n"
        
        comment += "### Summary\n"
        comment += f"- 🔴 **Critical:** {critical_issues}\n"
        comment += f"- 🟠 **High:** {high_issues}\n"
        comment += f"- 🟡 **Medium:** {medium_issues}\n"
        comment += f"- 🟢 **Low:** {low_issues}\n"
        comment += f"- 🔵 **Info:** {info_issues}\n\n"
        
        if critical_issues > 0 or high_issues > 0:
            comment += "❗ **Please address critical and high priority issues before merging.**\n\n"
        
        # Analysis coverage
        cpp_files = len([r for r in results if r.cpp_violations])
        ai_files = len([r for r in results if r.ai_findings])
        
        comment += "### Analysis Coverage\n"
        comment += f"- 🏗️ **C++ Guidelines:** {cpp_files} files\n"
        comment += f"- 🤖 **AI Analysis:** {ai_files} files\n\n"
        
        # Show top issues (limit for readability)
        comment += "### Key Issues Found\n\n"
        
        issue_count = 0
        max_issues = 15
        
        for result in results:
            if issue_count >= max_issues:
                break
            
            if result.total_issues == 0:
                continue
            
            comment += f"#### 📁 `{result.file_path}`\n\n"
            
            # Show critical/high issues first
            all_issues = []
            
            # Add C++ violations
            if result.cpp_violations:
                for violation in result.cpp_violations:
                    all_issues.append({
                        'type': 'cpp',
                        'severity': violation.get('severity', 'info'),
                        'data': violation
                    })
            
            # Add AI findings
            if result.ai_findings:
                for finding in result.ai_findings:
                    all_issues.append({
                        'type': 'ai',
                        'severity': finding.get('severity', 'info'),
                        'data': finding
                    })
            
            # Sort by severity
            severity_order = {
                'critical': 0, 'error': 0, 'high': 1, 'medium': 2, 
                'warning': 2, 'low': 3, 'info': 4
            }
            all_issues.sort(key=lambda x: severity_order.get(x['severity'], 5))
            
            for issue in all_issues[:5]:  # Show top 5 per file
                if issue_count >= max_issues:
                    break
                
                data = issue['data']
                severity_icon = {
                    'critical': '🔴', 'error': '🔴', 'high': '🟠', 
                    'medium': '🟡', 'warning': '🟡', 'low': '🟢', 'info': '🔵'
                }.get(data.get('severity', 'info'), '⚪')
                
                if issue['type'] == 'cpp':
                    comment += f"{severity_icon} **Line {data.get('line_number', 'N/A')}:** "
                    comment += f"{data.get('description', 'C++ guideline violation')}\n"
                    if data.get('suggestion'):
                        comment += f"💡 *{data.get('suggestion')}*\n"
                else:  # AI finding
                    comment += f"{severity_icon} **{data.get('title', 'AI Finding')}**\n"
                    comment += f"*{data.get('analysis_type', 'general').replace('_', ' ').title()}*: "
                    comment += f"{data.get('description', 'No description')}\n"
                
                comment += "\n"
                issue_count += 1
        
        if issue_count >= max_issues:
            remaining_issues = total_issues - max_issues
            comment += f"... and {remaining_issues} more issues. See full report for details.\n\n"
        
        comment += "\n---\n"
        comment += "*This analysis combines C++ coding guidelines with AI-powered code review.*"
        
        return comment


def main():
    """Main function for CLI usage."""
    parser = argparse.ArgumentParser(description="Integrated code analysis (C++ guidelines + AI)")
    parser.add_argument("files", nargs="+", help="Files to analyze")
    parser.add_argument("--ai-provider", choices=["openai", "anthropic"], 
                       default="openai", help="AI provider")
    parser.add_argument("--ai-api-key", help="API key for AI provider")
    parser.add_argument("--cpp-guidelines", help="Custom C++ guidelines file")
    parser.add_argument("--disable-cpp", action="store_true", 
                       help="Disable C++ guidelines analysis")
    parser.add_argument("--disable-ai", action="store_true", 
                       help="Disable AI analysis")
    parser.add_argument("--ai-analysis-types", nargs="+",
                       help="Specific AI analysis types")
    parser.add_argument("--format", choices=["text", "json", "markdown", "pr-comment"], 
                       default="text", help="Output format")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    # Convert AI analysis types
    ai_analysis_types = None
    if args.ai_analysis_types and HAS_AI_ANALYZER:
        try:
            ai_analysis_types = [AnalysisType(t) for t in args.ai_analysis_types]
        except ValueError as e:
            print(f"Invalid analysis type: {e}")
            return
    
    # Initialize integrated analyzer
    analyzer = IntegratedCodeAnalyzer(
        ai_provider=args.ai_provider,
        ai_api_key=args.ai_api_key,
        cpp_guidelines_file=args.cpp_guidelines
    )
    
    # Analyze files
    print("🔍 Starting comprehensive code analysis...")
    results = analyzer.analyze_files(
        args.files,
        enable_cpp_analysis=not args.disable_cpp,
        enable_ai_analysis=not args.disable_ai,
        ai_analysis_types=ai_analysis_types
    )
    
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