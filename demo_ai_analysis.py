#!/usr/bin/env python3
"""
Demo script showing how to use the AI-powered code analysis system
integrated with the existing C++ guidelines analyzer.
"""

import os
import asyncio
from typing import List
from pathlib import Path

# Import the analyzers
try:
    from ai_code_analyzer import AICodeAnalyzer, AnalysisType
    from integrated_code_analyzer import IntegratedCodeAnalyzer
    from cpp_code_analyzer import CppGuidelinesAnalyzer
    HAS_ANALYZERS = True
except ImportError as e:
    print(f"Import error: {e}")
    HAS_ANALYZERS = False


def demo_basic_ai_analysis():
    """Demo basic AI analysis capabilities."""
    print("🤖 AI Code Analysis Demo")
    print("=" * 50)
    
    if not HAS_ANALYZERS:
        print("❌ Analyzers not available. Please install dependencies.")
        return
    
    # Check if API key is set
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("⚠️  Warning: OPENAI_API_KEY not set. Using mock analysis.")
        print("To use real AI analysis, set your API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        print()
    
    # Initialize AI analyzer
    print("Initializing AI analyzer...")
    ai_analyzer = AICodeAnalyzer(provider="openai", api_key=api_key)
    
    # Find sample files
    sample_files = []
    for file_path in Path(".").glob("*.cpp"):
        sample_files.append(str(file_path))
    for file_path in Path(".").glob("*.h"):
        sample_files.append(str(file_path))
    
    if not sample_files:
        print("❌ No C++ files found for analysis.")
        return
    
    print(f"Found {len(sample_files)} sample files: {sample_files}")
    
    # Demo different analysis types
    analysis_types = [
        AnalysisType.BUG_DETECTION,
        AnalysisType.SECURITY_AUDIT,
        AnalysisType.PERFORMANCE_OPTIMIZATION
    ]
    
    print(f"\nRunning AI analysis for: {[t.value for t in analysis_types]}")
    
    # Run analysis (this would normally be async, but we'll simulate)
    if api_key:
        try:
            results = ai_analyzer.analyze_files(sample_files[:1], analysis_types)  # Just first file
            
            print(f"\n📊 Analysis Results:")
            print(f"Found {len(results)} findings")
            
            for result in results[:3]:  # Show first 3 results
                print(f"\n🔍 {result.title}")
                print(f"   Type: {result.analysis_type}")
                print(f"   Severity: {result.severity}")
                print(f"   Description: {result.description[:100]}...")
                
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
    else:
        print("✅ AI analyzer initialized successfully (mock mode)")


def demo_integrated_analysis():
    """Demo integrated analysis combining C++ guidelines with AI."""
    print("\n🔍 Integrated Analysis Demo")
    print("=" * 50)
    
    if not HAS_ANALYZERS:
        print("❌ Analyzers not available.")
        return
    
    # Initialize integrated analyzer
    print("Initializing integrated analyzer...")
    analyzer = IntegratedCodeAnalyzer(
        ai_provider="openai",
        ai_api_key=os.getenv("OPENAI_API_KEY")
    )
    
    # Find sample files
    sample_files = ["sample_code.cpp", "sample_header.h"]
    existing_files = [f for f in sample_files if os.path.exists(f)]
    
    if not existing_files:
        print("❌ No sample files found.")
        return
    
    print(f"Analyzing files: {existing_files}")
    
    # Run integrated analysis
    print("\nRunning integrated analysis...")
    
    # Enable only C++ analysis for demo (since AI requires API key)
    results = analyzer.analyze_files(
        existing_files,
        enable_cpp_analysis=True,
        enable_ai_analysis=bool(os.getenv("OPENAI_API_KEY")),
        ai_analysis_types=[AnalysisType.BUG_DETECTION, AnalysisType.SECURITY_AUDIT]
    )
    
    print(f"\n📊 Analysis Complete!")
    print(f"Analyzed {len(results)} files")
    
    for result in results:
        print(f"\n📁 {result.file_path} ({result.language})")
        print(f"   Total issues: {result.total_issues}")
        print(f"   Critical: {result.critical_issues}")
        print(f"   High: {result.high_issues}")
        print(f"   Medium: {result.medium_issues}")
        print(f"   Low: {result.low_issues}")
        print(f"   Info: {result.info_issues}")
        
        if result.cpp_violations:
            print(f"   C++ guideline violations: {len(result.cpp_violations)}")
        
        if result.ai_findings:
            print(f"   AI findings: {len(result.ai_findings)}")
    
    # Generate report
    print("\n📋 Generating report...")
    report = analyzer.generate_report(results, "text")
    
    # Show first part of report
    report_lines = report.split('\n')
    print('\n'.join(report_lines[:30]))  # Show first 30 lines
    
    if len(report_lines) > 30:
        print("\n... (truncated for demo)")


def demo_configuration():
    """Demo configuration and customization options."""
    print("\n⚙️  Configuration Demo")
    print("=" * 50)
    
    print("Available Analysis Types:")
    for analysis_type in AnalysisType:
        print(f"  • {analysis_type.value}: {analysis_type.value.replace('_', ' ').title()}")
    
    print("\nSupported File Types:")
    file_types = [
        "C++ (.cpp, .cc, .cxx, .c++, .hpp, .h)",
        "Python (.py)",
        "JavaScript (.js, .jsx)",
        "TypeScript (.ts, .tsx)",
        "Java (.java)",
        "C# (.cs)",
        "Go (.go)",
        "Rust (.rs)",
        "PHP (.php)",
        "Ruby (.rb)",
        "Swift (.swift)",
        "Kotlin (.kt)"
    ]
    
    for file_type in file_types:
        print(f"  • {file_type}")
    
    print("\nConfiguration Options:")
    print("  • AI Provider: OpenAI, Anthropic")
    print("  • Output Formats: text, json, markdown, pr-comment")
    print("  • Analysis Types: Can be selected individually")
    print("  • Integration: Can combine with C++ guidelines")
    print("  • Filtering: Can exclude test files, specific directories")


def demo_pr_analysis():
    """Demo PR analysis workflow."""
    print("\n📝 PR Analysis Demo")
    print("=" * 50)
    
    print("For PR analysis, you can:")
    print("1. Analyze specific files:")
    print("   python integrated_code_analyzer.py file1.cpp file2.cpp")
    
    print("\n2. Use with git diff:")
    print("   python integrated_code_analyzer.py --git-diff main")
    
    print("\n3. Generate PR comment:")
    print("   python integrated_code_analyzer.py --format pr-comment *.cpp")
    
    print("\n4. Use with GitHub Actions:")
    print("   - Set up API keys as secrets")
    print("   - Configure workflow to run on PR events")
    print("   - Post results as PR comments")


def demo_usage_examples():
    """Show usage examples."""
    print("\n📚 Usage Examples")
    print("=" * 50)
    
    examples = [
        {
            "title": "Basic AI Analysis",
            "command": "python ai_code_analyzer.py my_file.cpp",
            "description": "Run AI analysis on a single file"
        },
        {
            "title": "Specific Analysis Types",
            "command": "python ai_code_analyzer.py --analysis-types bug_detection security_audit *.cpp",
            "description": "Run specific types of analysis"
        },
        {
            "title": "Integrated Analysis",
            "command": "python integrated_code_analyzer.py --format markdown *.cpp",
            "description": "Combine C++ guidelines with AI analysis"
        },
        {
            "title": "PR Comment Format",
            "command": "python integrated_code_analyzer.py --format pr-comment src/*.cpp",
            "description": "Generate GitHub PR comment format"
        },
        {
            "title": "AI Only (No C++ Guidelines)",
            "command": "python integrated_code_analyzer.py --disable-cpp *.py",
            "description": "Run only AI analysis for Python files"
        },
        {
            "title": "Custom AI Provider",
            "command": "python ai_code_analyzer.py --provider anthropic --api-key YOUR_KEY file.cpp",
            "description": "Use Anthropic Claude instead of OpenAI"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"{i}. {example['title']}")
        print(f"   Command: {example['command']}")
        print(f"   Description: {example['description']}")
        print()


def main():
    """Run all demos."""
    print("🚀 AI-Powered Code Analysis Demo")
    print("=" * 60)
    print()
    
    # Basic setup check
    print("Checking setup...")
    
    # Check dependencies
    missing_deps = []
    try:
        import openai
    except ImportError:
        missing_deps.append("openai")
    
    try:
        import anthropic
    except ImportError:
        missing_deps.append("anthropic")
    
    if missing_deps:
        print(f"⚠️  Missing dependencies: {', '.join(missing_deps)}")
        print("Install with: pip install -r requirements.txt")
        print()
    
    # Check API keys
    api_keys = {
        "OpenAI": os.getenv("OPENAI_API_KEY"),
        "Anthropic": os.getenv("ANTHROPIC_API_KEY")
    }
    
    print("API Key Status:")
    for provider, key in api_keys.items():
        status = "✅ Set" if key else "❌ Not set"
        print(f"  {provider}: {status}")
    
    print()
    
    # Run demos
    demo_basic_ai_analysis()
    demo_integrated_analysis()
    demo_configuration()
    demo_pr_analysis()
    demo_usage_examples()
    
    print("\n🎉 Demo Complete!")
    print("\nNext steps:")
    print("1. Set up your API keys (OPENAI_API_KEY or ANTHROPIC_API_KEY)")
    print("2. Install dependencies: pip install -r requirements.txt")
    print("3. Try the analyzers on your own code")
    print("4. Integrate with your CI/CD pipeline")


if __name__ == "__main__":
    main() 