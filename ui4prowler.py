import json
from jinja2 import Environment, FileSystemLoader
import webbrowser
import sys
import argparse
import os
import subprocess
import re


NO_FILE_CREATED_ERROR = "\nNo new file created with a scan, check your command.\nIf it doesn't work several times, try to set \"-o\" flag in the prowler command."
PATH_ERROR = "\nCouldn't read the path properly."
PARSER_CREATE_SCAN = "Generate prowler scan and visualize it. After this flag use all the syntax as in prowler (e.g 'ui4prowler.py -c=\"<provider> -h\"')."
PARSER_INPUT_PATH = "Visualize prowler scan by providing a path to the prowler-generated JSON file. Chose the file without \".ocsf\" in the name."
PARSER_HELP = "Show this help message and exit."
FILE_WITH_CORRECT_FORMAT = 'Chose the file without ".ocsf" and ".asff" in the name.'

def generate_output_path(input_path):
    input_file_name = os.path.splitext(os.path.basename(input_path))[0]
    output_file_name = f"ui4prowler-{input_file_name}.html"
    path = os.path.join(os.getcwd(), output_file_name)
    return path

def generate_html(provider_info, service_count, services, file):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("index.html")

    rendered_html = template.render(provider=provider_info, 
                                    service_count=service_count,
                                    services = services)
    with open(file, "w") as f:
        f.write(rendered_html)

def generate_checks_dict(data):
    checks = {}
    
    # add to checks array
    for finding in data:
        check_id = finding["CheckID"]

        # creating new finding to be added to the arr Findings inside of inner dict
        new_finding_details = {
            "Status" : finding["Status"],
            "Region" : finding["Region"],
            "ResourceArn" : finding["ResourceArn"],
            "StatusExtended" : finding["StatusExtended"]
        }

        # check if the finding is Info Or Fail so we can count Findings in the Dashboard
        fail_info_amount = 0
        if new_finding_details["Status"] == 'FAIL' or new_finding_details["Status"] == 'INFO':
            fail_info_amount = 1

        # just need to change the existing check
        if check_id in checks.keys(): 
            findings_list = checks[check_id]["Findings"]
            findings_list.append(new_finding_details)
            checks[check_id]['FailInfoAmount'] += fail_info_amount
            continue

        new_finding = {
            "CheckID": check_id,
            "CheckTitle" : finding["CheckTitle"],
            "ServiceName": finding["ServiceName"],
            "Severity" : finding["Severity"],
            "Status": "PASS", # we put then value of max based on the arns checked
            "Risk" : finding["Risk"],
            "Recommendation" : finding["Remediation"]["Recommendation"], # text and url inside
            "Compliance" : finding["Compliance"],
            "FailInfoAmount" : fail_info_amount,
            "Findings" : [ 
                new_finding_details
            ]
        }
        checks[check_id] = new_finding

    set_all_checks_statuses(checks) 

    return checks       

def set_all_checks_statuses(checks):
    # go through each custom object.
    # go through its' findings and mark the highest status value
    # if the it's already max - assign it immidiately and go to the next custom_object
    for check_value in checks.values():
        status = "PASS"

        for finding in check_value.get('Findings'):
            if finding['Status'] == "FAIL":
                status = "FAIL"
                break
            if finding['Status'] == "INFO" and status == "PASS":
                status = "INFO"

        check_value["Status"] = status
    return checks   

def simplify_data_struct(services):
    result = {}
    #value - {'checkid':{custom_object}}
    for key, value in services.items():
        # { 'service_name': [{check1}, {check2}] }
        result[key] = []
        for check in value:
            result.get(key).append(list(check.values())[0])

    return result

def group_checks_by_service(data):
    services = {}

    for key, value in data.items():
        service_name = value["ServiceName"]

        # Add to the array of checks for that service
        if service_name in services.keys():
            check_arr = services[service_name]
            check_arr.append({key:value})
            continue

        # add first check to the service
        services[service_name] = [{key:value}]
    
    return services

def sort_checks_in_service(data):
    for service_checks in data.values():
        service_checks.sort(key=sorting_key)

def sorting_key(obj):
    # sorted obj is [{'CheckId':{Custom_obj}}, {'CheckId':{CUSTOMon}}]
    status_order = {'PASS': 3, 'INFO': 2, 'FAIL': 1,}
    severity_order = {'low': 4, 'medium': 3, 'high': 2, 'critical': 1}
    checks_list = list(obj.values())
    return (status_order[checks_list[0]['Status']], severity_order[checks_list[0]['Severity']])

def generate_service_count(data):
    service_map = {}

    for key, value in data.items():
        checks = 0
        findings = 0
        severity = 'OK'

        for check in value:
            checks += len(check['Findings'])
            findings += check['FailInfoAmount']

            if severity == "ERROR": continue
            
            if check['Status'] == "FAIL":
                if check['Severity'] == "critical" or check['Severity'] == "high":
                    severity = 'ERROR'
                elif check['Severity'] == "medium" or check['Severity'] == "low":
                    severity = 'WARNING'
            elif check['Status'] == "INFO":
                severity = "INFO"

        service_map[key] = {
            'Checks': checks,
            'Findings': findings,
            'Severity': severity
        }    
    return service_map

def get_provider_info(data):
    return {data[0]['Provider']: data[0]['ResourceId']}

def get_all_service_check_data(data):
    checks_dict = generate_checks_dict(data)
    services_data = group_checks_by_service(checks_dict)
    sort_checks_in_service(services_data)
    result = simplify_data_struct(services_data)
    return result

def init_argparser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", "--input-path", type=str, help=PARSER_INPUT_PATH)
    parser.add_argument("-c", "--create-scan", type=str, help=PARSER_CREATE_SCAN)
    parser.add_argument("-h", "--help", action="store_true", help=PARSER_HELP)
    return parser

def get_jsons_in_folder(folder):
    json_files = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if is_json_correct_extension(file): 
                json_files.append(os.path.join(root, file))
    return json_files

def execute_scan(args):
    file_name = ""
    command = args.create_scan

    check_prowler_process = subprocess.run(["pip", "list"], capture_output=True, text=True)
    if "prowler" not in check_prowler_process.stdout:
        subprocess.run(["pip", "install", "prowler"])

    pattern_o = r'-o\s+(\S+)'
    match_o = re.search(pattern_o, command)
    pattern_vh = r'.*-[hv].*'
    match_vh = re.search(pattern_vh, command)

    if match_o:
        folder = match_o.group(1)
    else: 
        folder = os.path.join(os.getcwd(), "output", "")

    files_before_scan = get_jsons_in_folder(folder)
    os.system(f"prowler {command}")

    # no need in returning path as it checks the version of prowler
    if match_vh:
        sys.exit(1)

    files_after_scan = get_jsons_in_folder(folder)
    
    for file in files_after_scan:
        if file not in files_before_scan:
            file_name = file
            break

    if file_name == "":
        sys.exit(NO_FILE_CREATED_ERROR)

    path =  os.path.join(folder, file_name)
    return path

def is_json_correct_extension(file):
    if file.lower().endswith('.json'):
        if (
            file.lower().endswith('.ocsf.json') 
            or file.lower().endswith('.asff.json')
        ): 
            sys.exit(FILE_WITH_CORRECT_FORMAT)
        return True

def get_path_to_input(parser):
    path = ""
    args = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    if args.input_path and is_json_correct_extension(args.input_path):
        path = args.input_path 
    elif args.create_scan:
        path = execute_scan(args)

    if path == "": sys.exit(PATH_ERROR)
    return path
     
def main():
    parser = init_argparser()
    path = get_path_to_input(parser)

    with open(path) as f:
        data = json.load(f)

    provider_info = get_provider_info(data)
    parsed_data = get_all_service_check_data(data)
    service_count = generate_service_count(parsed_data)
  
    output_file = generate_output_path(path)
    generate_html(provider_info, service_count, parsed_data, output_file)
    webbrowser.open(output_file)

if __name__ == "__main__":
    main()