import os
import datetime
import traceback
import click
import time

from os.path import exists, join, normpath
from CheckmarxPythonSDK.CxODataApiSDK.ProjectsODataAPI import get_all_projects_id_name
from CheckmarxPythonSDK.CxODataApiSDK.ScansODataAPI import get_all_scan_id_of_a_project
from CheckmarxPythonSDK.CxRestAPISDK.ScansAPI import ScansAPI
from CheckmarxPythonSDK.CxPortalSoapApiSDK import create_scan_report


def get_result_state_id_list(result_state_list):
    """

    Args:
        result_state_list (list of str):

    Returns:
        result_state_id_list (list of int)
    """
    all_result_state_list = ["To Verify", "Not Exploitable", "Confirmed", "Urgent", "Proposed Not Exploitable"]
    result_state_id_list = list()
    for result_state in result_state_list:
        try:
            result_state_id = all_result_state_list.index(result_state)
            result_state_id_list.append(result_state_id)
        except ValueError:
            print("result state: {} Not found".format(result_state))
    return result_state_id_list


def generate_report(project_name, scan_id, result_state_list, report_type):
    """

    Args:
        project_name (str):
        scan_id (int):
        result_state_list (list of str):   ["To Verify", "Not Exploitable", "Confirmed", "Urgent",
                                            "Proposed Not Exploitable"]
        report_type (str): ('XML', 'PDF')


    Returns:

    """
    scan_api = ScansAPI()

    current_working_dir = os.getcwd()

    reports_folder = normpath(join(current_working_dir, "cx_sast_reports"))
    if not exists(reports_folder):
        os.mkdir(reports_folder)

    if not scan_id:
        print("No scan found for this project, project name: {}".format(project_name))
        return

    # register scan report
    report = create_scan_report(
        scan_id=scan_id,
        report_type=report_type,
        results_per_vulnerability_maximum=500,
        results_state_all=False,
        results_state_ids=get_result_state_id_list(result_state_list)
    )
    report_id = report["ID"]

    # get report status by id
    while not scan_api.is_report_generation_finished(report_id):
        time.sleep(10)

    # get report by id
    report_content = scan_api.get_report_by_id(report_id)

    # write report content into a file
    name = f"{project_name}_{scan_id}.{report_type}"
    file_name = normpath(join(reports_folder, name))

    with open(str(file_name), "wb") as f_out:
        f_out.write(report_content)


@click.command()
@click.option('--cxsast_base_url', required=True, help="CxSAST base url, for example: https://localhost")
@click.option('--cxsast_username', required=True, help="CxSAST username")
@click.option('--cxsast_password', required=True, help="CxSAST password")
def main(cxsast_base_url, cxsast_username, cxsast_password):
    print("Start process...")
    result_state_list = ["To Verify", "Not Exploitable", "Confirmed", "Urgent", "Proposed Not Exploitable"]
    for project in get_all_projects_id_name():
        project_id = project.get("ProjectId")
        project_name = project.get("ProjectName")
        print(f"ProjectId: {project_id}, ProjectName: {project_name}")
        scan_ids = get_all_scan_id_of_a_project(project_id=project_id)
        for scan_id in scan_ids:
            print(f"scan id: {scan_id}")
            for report_type in ["PDF", "RTF", "CSV", "XML"]:
                print(f"start generating {report_type} report")
                try:
                    generate_report(project_name, scan_id, result_state_list, report_type)
                except Exception as e:
                    print(traceback.format_exc())
                print(f"finish generating {report_type} report")
    print("Finish process...")


if __name__ == '__main__':
    main()
