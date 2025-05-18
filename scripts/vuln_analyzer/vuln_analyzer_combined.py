import json
import argparse
import time
from openai import OpenAI
import os


api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def load_govulncheck_json(json_file):
    entries = []
    with open(json_file, 'r') as f:
        content = f.read()
        json_objects = content.split('}\n{')
        
        for i, obj in enumerate(json_objects):
            if i == 0:
                if not obj.endswith('}'): obj = obj + '}'
            elif i == len(json_objects) - 1:
                if not obj.startswith('{'): obj = '{' + obj
            else:
                if not obj.startswith('{'): obj = '{' + obj
                if not obj.endswith('}'): obj = obj + '}'
            
            try:
                entry = json.loads(obj)
                entries.append(entry)
            except json.JSONDecodeError as e:
                print(f"[!] Error processing JSON object #{i + 1}: {str(e)}")
                continue
    
    return entries

def analyze_vulnerabilities(entries):
    config = None
    sbom = None
    vulnerabilities = []
    findings_dict = {}
    
    for entry in entries:
        if "config" in entry:
            config = entry["config"]
        elif "SBOM" in entry:
            sbom = entry["SBOM"]
        elif "osv" in entry:
            # Only include essential information to minimize tokens
            vuln = {
                "ID": entry["osv"].get("id"),
                "Summary": entry["osv"].get("summary", "Not available"),
                "Details": entry["osv"].get("details", "Not available"),
                "Package": entry["osv"]["affected"][0]["package"]["name"] if entry["osv"].get("affected") else "N/A",
                "Introduced": entry["osv"]["affected"][0]["ranges"][0]["events"][0].get("introduced", "Not available"),
                "Fixed": entry["osv"]["affected"][0]["ranges"][0]["events"][0].get("fixed", "Not available")
            }
            vulnerabilities.append(vuln)
        elif "finding" in entry:
            finding = entry["finding"]
            osv_id = finding["osv"]
            
            # Use dictionary to avoid duplicates
            if osv_id not in findings_dict:
                findings_dict[osv_id] = {
                    "osv": osv_id,
                    "fixed_version": finding.get("fixed_version", "Not specified"),
                    "traces": []
                }
            
            # Add all traces for this finding
            for trace in finding.get("trace", []):
                if trace.get("module") != "stdlib":
                    trace_info = {
                        "module": trace.get("module", "Unknown"),
                        "version": trace.get("version", "Unknown"),
                        "package": trace.get("package", "Unknown"),
                        "function": trace.get("function", "Unknown"),
                        "receiver": trace.get("receiver", ""),
                        "position": trace.get("position", {})
                    }
                    findings_dict[osv_id]["traces"].append(trace_info)
    
    return config, sbom, vulnerabilities, list(findings_dict.values())

def chunk_vulnerabilities(vulns, chunk_size=10):
    """Split vulnerabilities into smaller groups"""
    return [vulns[i:i + chunk_size] for i in range(0, len(vulns), chunk_size)]

def build_prompt(vulns):
    return f"""
Analyze these Go vulnerabilities and classify them. Return the result in JSON format with this structure:
{{
    "stdlib": [{{"id": "ID", "summary": "brief description", "severity": "high/medium/low", "details": "detailed description", "introduced": "version", "fixed": "version"}}],
    "third_party": [{{"id": "ID", "summary": "brief description", "severity": "high/medium/low", "details": "detailed description", "introduced": "version", "fixed": "version"}}]
}}

Vulnerabilities to analyze:
{json.dumps(vulns, indent=2)}
"""

def summarize_with_llm(prompt):
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a Go application security expert. Be concise."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Error calling OpenAI: {str(e)}")
        return None

def print_findings_details(findings):
    if not findings:
        print("🔍 No specific findings in your code.\n")
        return

    print("🔍 Findings Analysis (Vulnerabilities in Your Code):")
    print("   These vulnerabilities have direct traces to your codebase:\n")

    for finding in findings:
        print(f"   🔴 {finding['osv']}:")
        print(f"      Fixed in version: {finding['fixed_version']}")
        if finding['traces']:
            print("      Traces in your code:")
            for trace in finding['traces']:
                filename = trace['position'].get('filename', 'Unknown file')
                line = trace['position'].get('line', 'Unknown line')
                module_info = f"{trace['module']}@{trace['version']}" if trace['version'] != "Unknown" else trace['module']
                func_info = f"{trace['function']}"
                if trace['receiver']:
                    func_info = f"({trace['receiver']}).{func_info}"
                print(f"      → {module_info}/{trace['package']}.{func_info}")
                print(f"        at {filename}:{line}")
        print()

def print_basic_info(config, sbom, vulns, findings):
    if config:
        print("📋 Scan Configuration:")
        print(f"   Scanner: {config['scanner_name']} v{config['scanner_version']}")
        print(f"   Database: {config['db']}")
        print(f"   Last update: {config['db_last_modified']}")
        print(f"   Go version: {config['go_version']}\n")
    
    if sbom:
        print("📦 SBOM Information:")
        print(f"   Modules found: {len(sbom['modules'])}")
        for module in sbom['modules']:
            print(f"   - {module.get('path', 'Path not available')}")
        print()

    print(f"🔨 Total vulnerabilities found: {len(vulns)}")
    print(f"🔍 Vulnerabilities affecting your code: {len(findings)}\n")


def format_final_output(all_results, errors):
    # Combine all results
    combined = {"stdlib": [], "third_party": []}
    for result in all_results:
        try:
            data = json.loads(result)
            combined["stdlib"].extend(data.get("stdlib", []))
            combined["third_party"].extend(data.get("third_party", []))
        except json.JSONDecodeError as e:
            errors.append({"type": "JSONDecodeError", "error": str(e), "response": result})
            continue

    # Severity mapping
    severity_map = {
        "high": "🔴",
        "medium": "🟡",
        "low": "🟢"
    }

    # Format final output
    output = []
    if combined["stdlib"]:
        output.append("\n🔧 Standard Library Vulnerabilities:")
        for vuln in combined["stdlib"]:
            severity = vuln["severity"].lower() if vuln.get("severity") else "unknown"
            severity_emoji = severity_map.get(severity, "⚪")
            output.append(f"  {severity_emoji} {vuln['id']}: {vuln['summary']}")

    if combined["third_party"]:
        output.append("\n📦 Third-party Dependencies Vulnerabilities:")
        for vuln in combined["third_party"]:
            severity = vuln["severity"].lower() if vuln.get("severity") else "unknown"
            severity_emoji = severity_map.get(severity, "⚪")
            output.append(f"  {severity_emoji} {vuln['id']}: {vuln['summary']}")

    return "\n".join(output)

def print_legend():
    print("=== Analysis Legend ===\n")
    print("Severity Levels:")
    print("  🔴 High   - Critical vulnerabilities requiring immediate attention")
    print("  🟡 Medium - Important issues that should be addressed soon")
    print("  🟢 Low    - Minor issues that should be reviewed when possible")
    print("  ⚪ Unknown - Severity level not determined\n")
    
    print("Vulnerability Categories:")
    print("  🔧 Standard Library - Issues in Go's standard library")
    print("  📦 Third-party     - Issues in external dependencies\n")
    print("Additional Indicators:")
    print("  📋 Configuration information")
    print("  🔨 Total vulnerabilities count")
    print("  🔍 Specific findings details")
    print("  📊 Processing statistics")
    print("-" * 50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Analyze govulncheck.json output with OpenAI assistance.")
    parser.add_argument('json_file', help='govulncheck JSON file')
    parser.add_argument('--chunk-size', type=int, default=5, help='Number of vulnerabilities per chunk')
    parser.add_argument('--show-errors', action='store_true', help='Show error details')
    args = parser.parse_args()

    try:
        # Load and analyze JSON
        entries = load_govulncheck_json(args.json_file)
        config, sbom, vulns, findings = analyze_vulnerabilities(entries)

        # Print legend
        print_legend()
        
        # Show basic information
        print_basic_info(config, sbom, vulns, findings)

        # Generate detailed analysis with LLM
        if vulns:
            print("🤖 Generating detailed AI analysis...\n")
            
            # Split vulnerabilities into smaller chunks
            chunks = chunk_vulnerabilities(vulns, args.chunk_size)
            print(f"Analyzing {len(vulns)} vulnerabilities in {len(chunks)} groups...")
            
            # Accumulate results and errors
            all_results = []
            errors = []
            processed_chunks = 0
            error_chunks = 0
            
            for i, chunk in enumerate(chunks, 1):
                print(f"\rProcessing group {i}/{len(chunks)}...", end="")
                try:
                    prompt = build_prompt(chunk)
                    analysis = summarize_with_llm(prompt)
                    if analysis:
                        all_results.append(analysis)
                        processed_chunks += 1
                except Exception as e:
                    error_chunks += 1
                    errors.append({
                        "chunk": i,
                        "type": type(e).__name__,
                        "error": str(e),
                        "vulns": [v["ID"] for v in chunk]
                    })
                # Wait a bit between chunks to avoid rate limits
                if i < len(chunks):
                    time.sleep(2)
            
            print("\n\n=== Vulnerability Summary ===\n")
            print(format_final_output(all_results, errors))
            
            # Show processing statistics
            print(f"\n📊 Processing Statistics:")
            print(f"   - Successfully processed chunks: {processed_chunks}/{len(chunks)}")
            print(f"   - Chunks with errors: {error_chunks}/{len(chunks)}")
            
            # Show detailed findings analysis at the end
            print("\n=== Findings Analysis ===\n")
            print_findings_details(findings)
            
            # Show error details if requested
            if args.show_errors and errors:
                print("\n🔍 Error Details:")
                for err in errors:
                    print(f"\n   Chunk #{err['chunk']}:")
                    print(f"   - Type: {err['type']}")
                    print(f"   - Error: {err['error']}")
                    print(f"   - Affected IDs: {', '.join(err['vulns'])}")
        else:
            print("✅ No vulnerabilities found to analyze.")

    except Exception as e:
        print(f"\n[!] Error: {str(e)}")

if __name__ == "__main__":
    main()
