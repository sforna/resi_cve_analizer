import os.path
import sys
import openpyxl
import requests
from packaging.version import Version
import argparse
from enum import Enum
from typing import Tuple, Dict, Any


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
# Old api url, not working at the moment
# api_url = "https://cve.circl.lu/api/cve/"
api_url = "https://cvepremium.circl.lu/api/cve/"

# Open Workbook
def open_workbook(file_path):
    workbook = openpyxl.load_workbook(filename=file_path, read_only=False, keep_vba=True)
    return workbook

# Read Software Versions min and max values
# At first based only to EM Values
def read_sw_versions_min_max(sheet, sw_type):
        # EM Value
        if sw_type == 'linux_kernel':
            min_version = sheet['B8'].value
            max_version = sheet['C8'].value

        # EM Value
        if sw_type == 'enterprise_linux':
            min_version = sheet['B7'].value
            max_version = sheet['C7'].value

        # EM Value
        if sw_type == 'apache':
            min_version = sheet['B15'].value
            max_version = sheet['C15'].value

        # EM Value
        if sw_type == 'oracle_db':
            min_version = sheet['B10'].value
            max_version = sheet['C10'].value

        # EM Value
        if sw_type == 'nodejs':
            min_version = sheet['B9'].value
            max_version = sheet['C9'].value

        return min_version, max_version

# getting CVE from API
def get_api_cve(val):
    print(f'chiamo API per la CVE {val}')

    response = requests.get(f"{api_url}{val}")
    if response.status_code == 404:
        
        print(f'errore 404 per CVE {val}')
        
        data = []
    
    elif response.status_code == 200:

        response_json = response.json()

        #summary = res_json["summary"]

        if response_json:

            data = response_json["vulnerable_configuration"]

        else:

            data = []

    return data




def read_sheet(workbook, sheet_name):
    sheet = workbook[sheet_name]
    #df = pd.DataFrame(sheet.values)
    #print (dt)
    #for index, row in df.iterrows():
    #    print (row[0])

    return sheet


def get_sheet_data(sheet_sw, sheet):


    for row in sheet.iter_rows(min_row=2):

        if row[0].value == None:
            continue

        val = row[3].value

        #print(val)

        # getting CVE infos for current row
        cve = get_api_cve(val.strip())
        #print(cve)

        vul = check_vulnerabilities(sheet_sw, cve)
        #print(vul)

        if vul:

            # aggiunge una colonna
            #row[-1].offset(0, 1).value = "daje"

            row[20].value = 'SI'
            #row[21].value = vul

            #row[20] = '1'
        #new_sheet.append(row)

        else:
            row[20].value = 'NO'

    return sheet





def check_vulnerabilities(sheet_sw, vulnerable_configuration):
    #print(vulnerable_configuration)
    values_in_range = []
    
    for counter, field in enumerate(vulnerable_configuration, start=1):
        version_parts = []

        # split the field
        parts_field = field['title'].split(':')

        #print (f'valore da analizzare {parts_field[5]}')


        # if is a linux kernel
        if parts_field[3] == 'linux' and parts_field[4] == 'linux_kernel':

            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'linux_kernel')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue
        
        elif parts_field[3] == 'redhat' and parts_field[4] == 'enterprise_linux':

            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'enterprise_linux')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue


        elif parts_field[3] == 'oracle' and parts_field[4] == 'database_server':

            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'oracle_db')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue

        elif parts_field[3] == 'nodejs' and parts_field[4] == 'node.js':
            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'nodejs')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue


        elif parts_field[3] == 'apache' and parts_field[3] == 'http_server':
            print('si tratta di apache')

            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'apache')

            affected_version = parts_field[5]

            splitted_affected_version = affected_version.split("-")[0]

            try:          
                if Version(str(min_version)) <= Version(str(splitted_affected_version)) and Version(str(max_version)) >= Version(str(splitted_affected_version)):
                    values_in_range.append(parts_field[5])

            except:
                continue

        
        elif parts_field[3] == 'oracle_db':

            min_version, max_version = read_sw_versions_min_max(sheet_sw ,'oracle_db')

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


















