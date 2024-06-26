import os.path
import sys
import openpyxl
import requests
from packaging.version import Version
import argparse


parser = argparse.ArgumentParser(
    prog="CVE Validation Manager",
    description="Check CVE in Resi Product",
    epilog="Developed By Simone Fornasiere",
)
parser.add_argument("--filename", type=str, help="Input file name")
parser.add_argument("--sheet", type=str, help="Sheet name containing vulnerabilities")
args = parser.parse_args()

sheet_vulnerabilities_name = args.sheet
sheet_sw_min_max_name = 'Gemini'
file_path_input = os.path.join(sys.path[0],"input/")
file_path_output = os.path.join(sys.path[0],"output/")
output_filename = 'vulnerabilita_tim_elaborato.xlsm'
input_filename = args.filename
api_url = "https://cve.circl.lu/api/cve/"


# Open Workbook
def open_workbook(file_path):
    workbook = openpyxl.load_workbook(filename=file_path, read_only=False, keep_vba=True)
    return workbook


def read_sw_versions_min_max(sheet, type, sw_type):
    """
    Read minimum and maximum software versions from a spreadsheet.
    
    :param sheet: The worksheet object
    :param type: 'em' or 'probe'
    :param sw_type: The type of software (e.g., 'linux_kernel', 'enterprise_linux')
    :return: A tuple (min_version, max_version)
    """
    sw_types = {
        'linux_kernel': 8,
        'enterprise_linux': 7,
        'apache': 9,
        'oracle_db': 11,
        'nodejs': 10
    }
    
    type_columns = {
        'em': ('B', 'C'),
        'probe': ('D', 'E')
    }
    
    if sw_type not in sw_types:
        raise ValueError(f"Unknown software type: {sw_type}")
    
    if type not in type_columns:
        raise ValueError(f"Invalid type: {type}. Must be 'em' or 'probe'.")
    
    row = sw_types[sw_type]
    min_col, max_col = type_columns[type]
    
    min_version = sheet[f'{min_col}{row}'].value
    max_version = sheet[f'{max_col}{row}'].value
    
    return min_version, max_version


# getting CVE from API
def get_api_cve(val):

    response = requests.get(f"{api_url}{val}")
    response_json = response.json()

    #summary = res_json["summary"]

    if response_json:

        data = response_json["vulnerable_configuration"]

    else:

        data = []

    return data

def read_sheet(workbook, sheet_name):
    sheet = workbook[sheet_name]

    return sheet

def get_sheet_data(sheet_sw, sheet):

    for row in sheet.iter_rows(min_row=2):

        if row[0].value == None:
            continue

        val = row[3].value

        # getting CVE infos for current row
        cve = get_api_cve(val.strip())
        #print(cve)

        vul = check_vulnerabilities(sheet_sw, 'em', cve)
        #print(vul)

        if vul:
            row[20].value = 'SI'

        else:
            row[20].value = 'NO'

        vul = check_vulnerabilities(sheet_sw, 'probe', cve)

        if vul:
              row[21].value = 'SI'

        else:
            row[21].value = 'NO'

    return sheet


def check_vulnerabilities(sheet_sw, type, vulnerable_configuration):
    #print(vulnerable_configuration)
    values_in_range = []
    
    for counter, field in enumerate(vulnerable_configuration, start=1):
        version_parts = []

        # split the field
        parts_field = field['title'].split(':')

        #print (f'valore da analizzare {parts_field[5]}')


        # if is a linux kernel
        if parts_field[3] == 'linux' and parts_field[4] == 'linux_kernel':

            min_version, max_version = read_sw_versions_min_max(sheet_sw, type, 'linux_kernel')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue
        
        elif parts_field[3] == 'redhat' and parts_field[4] == 'enterprise_linux':

            min_version, max_version = read_sw_versions_min_max(sheet_sw, type, 'enterprise_linux')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue


        elif parts_field[3] == 'oracle' and parts_field[4] == 'database_server':

            min_version, max_version = read_sw_versions_min_max(sheet_sw, type, 'oracle_db')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue

        elif parts_field[3] == 'nodejs' and parts_field[4] == 'node.js':
            min_version, max_version = read_sw_versions_min_max(sheet_sw, type, 'nodejs')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue


        elif parts_field[3] == 'apache':

            min_version, max_version = read_sw_versions_min_max(sheet_sw, type, 'apache')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue
         
    return values_in_range

def write_to_excel(workbook, sheet):

    workbook.save(f'{file_path_output}{output_filename}')



if __name__ == "__main__":
    workbook = open_workbook(f'{file_path_input}{input_filename}')

    sheet_vulnerabilities = read_sheet(workbook, sheet_vulnerabilities_name)  

    sheet_sw_min_max_values = read_sheet(workbook, sheet_sw_min_max_name)  

    sheet_vulnerabilities_final = get_sheet_data(sheet_sw_min_max_values, sheet_vulnerabilities)

    write_to_excel(workbook, sheet_vulnerabilities_final)


















