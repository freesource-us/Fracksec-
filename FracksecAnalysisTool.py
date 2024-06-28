import requests
import json
import ast
import os
import subprocess
import numpy as np
import pandas as pd
import git
import networkx as nx
import matplotlib.pyplot as plt
from pylint.lint import Run
from pylint.reporters.text import TextReporter
from io import StringIO
import re

# Constants
NVD_API_KEY = 'REPLACE_WITH_NVD_API'
REPO_URL = "REPLACE_WITH_GITHUB_URL"
CLONE_DIR = "cloned_repo"

# Weights for vulnerability calculation
zeta = 0.5
psi = 0.2
omega = 0.2
chi = 0.1

def calculate_cyclomatic_complexity(code):
    class ComplexityVisitor(ast.NodeVisitor):
        def __init__(self):
            self.complexity = 1

        def visit_If(self, node):
            self.complexity += 1
            self.generic_visit(node)

        def visit_For(self, node):
            self.complexity += 1
            self.generic_visit(node)

        def visit_While(self, node):
            self.complexity += 1
            self.generic_visit(node)

    try:
        tree = ast.parse(code)
        visitor = ComplexityVisitor()
        visitor.visit(tree)
        return visitor.complexity
    except SyntaxError:
        print(f"SyntaxError in file. Returning default complexity.")
        return 1

def calculate_code_evolution(repo, file_path):
    try:
        commits = list(repo.iter_commits(paths=file_path))
        return len(commits)
    except Exception as e:
        print(f"Error calculating code evolution: {e}")
        return 0

def analyze_commit_messages(repo, file_path):
    try:
        commits = list(repo.iter_commits(paths=file_path))
        security_keywords = ['security', 'vulnerability', 'patch', 'fix', 'CVE']
        score = sum(1 for commit in commits if any(keyword in commit.message.lower() for keyword in security_keywords))
        return score
    except Exception as e:
        print(f"Error analyzing commit messages: {e}")
        return 0

def calculate_code_interactions(code):
    try:
        tree = ast.parse(code)
        G = nx.DiGraph()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                G.add_node(node.name)
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        G.add_edge(node.name, child.func.id)
        return len(G.edges)
    except SyntaxError:
        print(f"SyntaxError in file. Returning default interactions.")
        return 0

def data_flow_analysis(code):
    try:
        tree = ast.parse(code)
        flows = [target.id for node in ast.walk(tree) if isinstance(node, ast.Assign) 
                 for target in node.targets if isinstance(target, ast.Name)]
        return len(flows)
    except SyntaxError:
        print(f"SyntaxError in file. Returning default data flows.")
        return 0

def calculate_pylint_score(file_path):
    try:
        pylint_output = StringIO()
        reporter = TextReporter(pylint_output)
        Run([file_path], reporter=reporter, exit=False)
        pylint_output_str = pylint_output.getvalue()
        for line in pylint_output_str.split('\n'):
            if "Your code has been rated at" in line:
                return float(line.split()[6].split('/')[0])
        return 0.0
    except Exception as e:
        print(f"Error calculating pylint score: {e}")
        return 0.0

def clone_repository(repo_url, clone_dir):
    try:
        if os.path.exists(clone_dir):
            subprocess.call(['rm', '-rf', clone_dir])
        repo = git.Repo.clone_from(repo_url, clone_dir)
        return repo
    except git.exc.GitCommandError as e:
        print(f"Failed to clone repository: {e}")
        return None

def calculate_vulnerability_probability(complexity, evolution, interactions):
    return zeta * (psi * complexity + omega * evolution)**-chi * np.log2(interactions + 1)

def identify_vulnerabilities(code):
    vulnerabilities = []
    patterns = [
        (r"os\.system\(", "Command Injection", "High"),
        (r"subprocess\.call\(", "Command Injection", "High"),
        (r"eval\(", "Code Injection", "High"),
        (r"exec\(", "Code Injection", "High"),
        (r"\.execute\(['\"]", "SQL Injection", "High"),
        (r"\.decode\('utf-8'\)", "Encoding Vulnerability", "Medium"),
        (r"pickle\.loads\(", "Deserialization Vulnerability", "High"),
        (r"yaml\.load\(", "YAML Deserialization Vulnerability", "High"),
        (r"@app\.route\(.*methods=\['GET', 'POST'\]\)", "Potential CSRF Vulnerability", "Medium"),
        (r"request\.form\.get\(", "Potential XSS Vulnerability", "Medium")
    ]

    for i, line in enumerate(code.split('\n'), 1):
        for pattern, vuln_type, severity in patterns:
            if re.search(pattern, line):
                vulnerabilities.append((i, line.strip(), vuln_type, severity))
    return vulnerabilities

def identify_coding_errors(code):
    errors = []

    # Syntax errors
    try:
        ast.parse(code)
    except SyntaxError as e:
        errors.append((e.lineno, "SyntaxError", str(e)))

    # Logical errors and potential runtime exceptions
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
                    errors.append((node.lineno, "LogicalError", "Constant condition in if statement"))
            elif isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type is None or (isinstance(handler.type, ast.Name) and handler.type.id == 'Exception'):
                        errors.append((handler.lineno, "PotentialRuntimeException", "Overly broad exception handling"))
    except SyntaxError:
        pass  # Syntax errors are already caught above

    return errors

def analyze_file(repo, file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()

        complexity = calculate_cyclomatic_complexity(code)
        evolution = calculate_code_evolution(repo, file_path)
        commit_message_score = analyze_commit_messages(repo, file_path)
        interactions = calculate_code_interactions(code)
        P_vuln = calculate_vulnerability_probability(complexity, evolution, interactions)
        vulnerabilities = identify_vulnerabilities(code)
        coding_errors = identify_coding_errors(code)

        metrics = {
            'file': file_path,
            'complexity': complexity,
            'evolution': evolution,
            'commit_message_score': commit_message_score,
            'interactions': interactions,
            'data_flows': data_flow_analysis(code),
            'pylint_score': calculate_pylint_score(file_path),
            'P_vuln': P_vuln,
            'vulnerabilities': vulnerabilities,
            'coding_errors': coding_errors
        }
        return metrics
    except Exception as e:
        print(f"Error analyzing file {file_path}: {e}")
        return None

def analyze_codebase(repo_url):
    repo = clone_repository(repo_url, CLONE_DIR)
    if repo is None:
        return pd.DataFrame()

    results = []
    for root, _, files in os.walk(CLONE_DIR):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                result = analyze_file(repo, file_path)
                if result:
                    results.append(result)

    return pd.DataFrame(results)

def save_results_to_csv(df, filename="analysis_results.csv"):
    try:
        df['vulnerabilities'] = df['vulnerabilities'].apply(lambda x: '; '.join([f"Line {line}: {code} ({vuln_type}, {severity})" for line, code, vuln_type, severity in x]))
        df['coding_errors'] = df['coding_errors'].apply(lambda x: '; '.join([f"Line {line}: {error_type} - {message}" for line, error_type, message in x]))
        df.to_csv(filename, index=False)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results to CSV: {e}")

def plot_results(df):
    try:
        plt.figure(figsize=(10, 6))
        plt.hist(df['P_vuln'], bins=20)
        plt.xlabel('Vulnerability Probability')
        plt.ylabel('Frequency')
        plt.title('Distribution of Vulnerability Probabilities')
        plt.savefig('vulnerability_distribution.png')
        plt.close()
        print("Vulnerability distribution plot saved as 'vulnerability_distribution.png'")
    except Exception as e:
        print(f"Error plotting results: {e}")

def generate_vulnerability_report(df):
    try:
        with open('vulnerability_report.txt', 'w') as f:
            f.write("Vulnerability and Code Quality Analysis Report\n")
            f.write("============================================\n\n")

            f.write(f"Total files analyzed: {len(df)}\n")
            f.write(f"Average vulnerability probability: {df['P_vuln'].mean():.2f}\n\n")

            f.write("Top 10 Most Vulnerable Files:\n")
            for _, row in df.nlargest(10, 'P_vuln').iterrows():
                f.write(f"  {row['file']} - Probability: {row['P_vuln']:.2f}\n")
            f.write("\n")

            f.write("Detailed Analysis:\n")
            for _, row in df.iterrows():
                f.write(f"\nFile: {row['file']}\n")
                f.write(f"Vulnerability Probability: {row['P_vuln']:.2f}\n")
                f.write(f"Complexity: {row['complexity']}\n")
                f.write(f"Evolution: {row['evolution']}\n")
                f.write(f"Interactions: {row['interactions']}\n")
                f.write(f"Data Flows: {row['data_flows']}\n")
                f.write(f"Pylint Score: {row['pylint_score']}\n")

                if isinstance(row['vulnerabilities'], list) and row['vulnerabilities']:
                    f.write("Potential Vulnerabilities:\n")
                    for line, code, vuln_type, severity in row['vulnerabilities']:
                        f.write(f"  Line {line}: {vuln_type} ({severity}) - {code}\n")

                if isinstance(row['coding_errors'], list) and row['coding_errors']:
                    f.write("Coding Errors:\n")
                    for line, error_type, message in row['coding_errors']:
                        f.write(f"  Line {line}: {error_type} - {message}\n")

                f.write("-" * 50 + "\n")

        print("Detailed vulnerability and code quality report generated: vulnerability_report.txt")
    except Exception as e:
        print(f"Error generating vulnerability report: {e}")

def main():
    print("Starting codebase analysis...")
    results = analyze_codebase(REPO_URL)

    if results.empty:
        print("No results were generated. Check if the repository was cloned successfully.")
        return

    print("\nAnalysis complete. Summary of results:")
    print(results.describe())

    save_results_to_csv(results)
    plot_results(results)
    generate_vulnerability_report(results)

    print("\nTop 5 most vulnerable files:")
    top_vulnerable = results.nlargest(5, 'P_vuln')
    for _, row in top_vulnerable.iterrows():
        print(f"\nFile: {row['file']}")
        print(f"Vulnerability Probability: {row['P_vuln']:.2f}")
        if isinstance(row['vulnerabilities'], list):
            print("Potential Vulnerabilities:")
            for line, code, vuln_type, severity in row['vulnerabilities']:
                print(f"  Line {line}: {vuln_type} ({severity}) - {code}")
        if isinstance(row['coding_errors'], list):
            print("Coding Errors:")
            for line, error_type, message in row['coding_errors']:
                print(f"  Line {line}: {error_type} - {message}")

if __name__ == "__main__":
    main()
